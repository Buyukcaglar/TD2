"""Audit recovery metadata, original custody, dependencies and public-file scope.

This does not rerun game, decoder, compiler or differential tests. It verifies
the persisted evidence and the expected private/public boundaries.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_reference import verify, DEFAULT_MANIFEST


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_export_names(path: Path) -> set[str]:
    """Read named exports from the pinned native PE DLL without loading it."""
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0':
        raise ValueError('Not a PE library: ' + str(path))
    count, optional_size = struct.unpack_from('<H', data, pe+6)[0], struct.unpack_from('<H', data, pe+20)[0]
    optional = pe+24
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('Expected native x64 PE32+ library: ' + str(path))
    export_rva = struct.unpack_from('<I', data, optional+112)[0]
    sections = []
    for index in range(count):
        at = optional+optional_size+40*index
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from('<4I', data, at+8)
        sections.append((virtual_address, virtual_size, raw_size, raw_offset))

    def raw(rva):
        for address, virtual_size, size, offset in sections:
            if address <= rva < address+max(virtual_size, size) and rva-address < size:
                return offset+rva-address
        raise ValueError('Unmapped native export RVA: ' + str(path))

    if not export_rva:
        return set()
    directory = raw(export_rva)
    names_count = struct.unpack_from('<I', data, directory+24)[0]
    names_table = raw(struct.unpack_from('<I', data, directory+32)[0])
    names = set()
    for index in range(names_count):
        at = raw(struct.unpack_from('<I', data, names_table+4*index)[0])
        end = data.index(b'\0', at, min(len(data), at+512))
        names.add(data[at:end].decode('ascii'))
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT / "docs/recovery/evidence").resolve()):
        raise ValueError("Choose a fresh recovery evidence audit path")
    problems = []
    custody = verify(ROOT, DEFAULT_MANIFEST)
    baseline = json.loads((ROOT / "docs/recovery/evidence/custody-baseline.json").read_text())
    same_metadata = custody["files"] == baseline["files"]
    if custody["result"] != "pass" or not same_metadata:
        problems.append("Original content/metadata custody failure")
    json_files = list((ROOT / "docs").rglob("*.json"))
    for path in json_files:
        json.loads(path.read_text(encoding="utf-8"))
    backlog = json.loads((ROOT / "docs/planning/backlog.json").read_text())
    by = {t["id"]: t for t in backlog["tasks"]}
    if len(by) != backlog["task_count"]:
        problems.append("Task count/identity mismatch")
    visiting, done = set(), set()

    def visit(id):
        if id in visiting:
            raise ValueError("Dependency cycle: " + id)
        if id in done:
            return
        visiting.add(id)
        task = by[id]
        dependencies = task["depends_on"] + [x["id"] for x in task.get("conditional_depends_on", [])]
        for dep in dependencies:
            if dep not in by or by[dep]["phase"] > task["phase"]:
                raise ValueError("Invalid dependency: " + dep)
            visit(dep)
        if task["status"] in ("complete", "in_progress"):
            for dep in task["depends_on"]:
                if by[dep]["status"] != "complete":
                    problems.append(f"Task {id} started before {dep}")
        for path in task.get("evidence", []):
            if not (ROOT / path).exists():
                problems.append("Missing task evidence: " + path)
        visiting.remove(id)
        done.add(id)

    for id in by:
        visit(id)
    requirements = {x for task in by.values() for x in task["requirements"]}
    if requirements != set(backlog["requirements"]):
        problems.append("Requirement coverage mismatch")
    links = 0
    for path in [ROOT / "README.md"] + list((ROOT / "docs").rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for _, url in re.findall(r"\[([^\]]*)\]\(([^)]+)\)", text):
            if re.match(r"^[a-z]+://", url, re.I) or url.startswith("#"):
                continue
            relative = unquote(url.split("#")[0].strip("<>"))
            target = Path(relative) if re.match(r"^[A-Za-z]:[/\\]", relative) else path.parent / relative
            links += 1
            if not target.exists():
                problems.append(f"Broken link in {path.relative_to(ROOT)}: {relative}")
    sys.path.insert(0, str(ROOT / "analysis/tools/validator-python"))
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "docs/recovery/schemas/function-record.schema.json").read_text())
    functions = json.loads((ROOT / "docs/recovery/functions.json").read_text())["records"]
    validator = Draft202012Validator(schema)
    for function in functions:
        validator.validate(function)
        for source in function["portable_source"]:
            if digest(ROOT / source["path"]) != source["sha256"]:
                problems.append("Function source hash mismatch: " + source["path"])
    if len({f['id'] for f in functions}) != len(functions):
        problems.append('Duplicate function IDs')
    function_ids = {f['id'] for f in functions}
    for function in functions:
        if any(id not in function_ids for id in function['callers'] + function['callees']):
            problems.append('Unregistered function relation: ' + function['id'])
        for loc in function['entries'] + function['ranges']:
            if loc['coordinate'] == 'unpacked_module':
                if loc['offset'] != loc['segment'] * 16 + loc['segment_offset']:
                    problems.append('Function coordinate mismatch: ' + function['id'])
                if loc['offset'] + loc['length'] > (ROOT / loc['path']).stat().st_size:
                    problems.append('Function range outside image: ' + function['id'])
    resources = []
    resource_path = ROOT / 'docs/recovery/resources.json'
    if resource_path.exists():
        resources = json.loads(resource_path.read_text())['records']
        resource_validator = Draft202012Validator(json.loads((ROOT / 'docs/recovery/schemas/resource-record.schema.json').read_text()))
        resource_ids = {r['id'] for r in resources}
        if len(resource_ids) != len(resources):
            problems.append('Duplicate resource IDs')
        custody_by_path = {r['path']: r for r in custody['files']}
        for resource in resources:
            resource_validator.validate(resource)
            if any(id not in function_ids for id in resource['consumers'] + resource['writers']):
                problems.append('Unregistered resource consumer/writer: ' + resource['id'])
            for loc in resource['locations']:
                if loc['path'].startswith('reference/'):
                    if loc['sha256'] != custody_by_path[loc['path']]['sha256']:
                        problems.append('Resource/source identity mismatch: ' + resource['id'])
                elif digest(ROOT / loc['path']) != loc['sha256']:
                    problems.append('Derived resource identity mismatch: ' + resource['id'])
                if loc['offset'] + loc['length'] > (ROOT / loc['path']).stat().st_size:
                    problems.append('Resource range outside source: ' + resource['id'])
        for function in functions:
            if any(id.startswith('RS-') and id not in resource_ids for id in function['data_dependencies']):
                problems.append('Unregistered resource dependency: ' + function['id'])
    helper_checks = []
    native_exports, compiled_original_entries = set(), set()
    verified_library_hashes = set()
    helper_specs = [
        ('byte-ring', 'byte_ring', 'build', 'validation'),
        ('filename', 'filename', 'build-v1', 'validation-v2'),
        ('cache-query', 'cache_query', 'build-v1', 'validation-v1'),
        ('cache-allocate', 'cache_allocate', 'build-v1', 'validation-v1'),
        ('cache-discard', 'cache_discard', 'build-v1', 'validation-v1'),
        ('paragraph-copy', 'paragraph_copy', 'build-v2', 'validation-v2'),
        ('cache-compact', 'cache_compact', 'build-v1', 'validation-v1'),
        ('cache-acquire', 'cache_acquire', 'build-v1', 'validation-v2'),
        ('cache-release', 'cache_release', 'build-v1', 'validation-v1'),
        ('prefix-stage', 'prefix_stage', 'build-v1', 'validation-v1'),
        ('run-stage', 'run_stage', 'build-v1', 'validation-v1'),
        ('timer-callbacks', 'timer_callbacks', 'build-v1', 'validation-v1'),
        ('raw-load', 'raw_load', 'build-v1', 'validation-v2'),
        ('file-paragraphs', 'file_paragraphs', 'build-v1', 'validation-v1'),
        ('audio-metadata', 'audio_metadata', 'build-v1', 'validation-v1'),
        ('sim-primitives', 'sim_primitives', 'build-v2', 'validation-v1'),
        ('timer-control', 'timer_control', 'build-v1', 'validation-v1'),
        ('session-init', 'session_init', 'build-v1', 'validation-v1'),
        ('mutable-control', 'mutable_control', 'build-v1', 'validation-v1'),
        ('named-raw', 'named_raw', 'build-v1', 'validation-v1'),
        ('packed-load', 'packed_load', 'build-v1', 'validation-v1'),
        ('directory', 'directory', 'build-v2', 'validation-v2'),
        ('directory-batch', 'directory_batch', 'build-v1', 'validation-v1'),
        ('key-bindings', 'key_bindings', 'build-v1', 'validation-v1'),
        ('gameport', 'gameport', 'build-v1', 'validation-v1'),
        ('sim-targets', 'sim_targets', 'build-v1', 'validation-v1'),
        ('key-dispatch', 'key_dispatch', 'build-v2', 'validation-v1'),
        ('input-poll', 'input_poll', 'build-v2', 'validation-v2'),
        ('control-ops', 'control_ops', 'build-v1', 'validation-v1'),
        ('input-control', 'input_control', 'build-v2', 'validation-v2'),
        ('signed-motion', 'signed_motion', 'build-v1', 'validation-v1'),
        ('input-update', 'input_update', 'build-v3', 'validation-v3'),
        ('pool-setup', 'pool_setup', 'build-v1', 'validation-v1'),
        ('find-files', 'find_files', 'build-v1', 'validation-v1'),
        ('find-nth', 'find_nth', 'build-v1', 'validation-v1'),
        ('music-tick', 'music_tick', 'build-v1', 'validation-v1'),
        ('effect-tick', 'effect_tick', 'build-v1', 'validation-v1'),
        ('timer-handler', 'timer_handler', 'build-v1', 'validation-v1'),
        ('key-actions', 'key_actions', 'build-v1', 'validation-v1'),
        ('keyboard', 'keyboard', 'build-v1', 'validation-v1'),
        ('prepare-records', 'prepare_records', 'build-v1', 'validation-v1'),
        ('state-loop', 'state_loop', 'build-v1', 'validation-v1'),
        ('wait-control', 'wait_control', 'build-v1', 'validation-v1'),
        ('state-messages', 'state_messages', 'build-v1', 'validation-v1'),
        ('input-bridge', 'input_bridge', 'build-v1', 'validation-v1'),
        ('state-sequences', 'state_sequences', 'build-v1', 'validation-v1'),
        ('bios-block', 'bios_block', 'build-v1', 'validation-v1'),
        ('wait-latch', 'wait_latch', 'build-v1', 'validation-v1'),
        ('loop-prepare', 'loop_prepare', 'build-v1', 'validation-v1'),
        ('loop-controls', 'loop_controls', 'build-v1', 'validation-v1'),
        ('near-clamp', 'near_clamp', 'build-v1', 'validation-v1'),
        ('projection', 'projection', 'build-v1', 'validation-v1'),
        ('line-step', 'line_step', 'build-v1', 'validation-v1'),
        ('record-interpolate', 'record_interpolate', 'build-v1', 'validation-v1'),
        ('view-limits', 'view_limits', 'build-v2', 'validation-v1'),
        ('draw-sequence', 'draw_sequence', 'build-v1', 'validation-v1'),
        ('plane-span', 'plane_span', 'build-v2', 'validation-v1'),
        ('plane-rows', 'plane_rows', 'build-v1', 'validation-v1'),
        ('edge-sequence', 'edge_sequence', 'build-v1', 'validation-v1'),
        ('line-draw', 'line_draw', 'build-v2', 'validation-v4'),
        ('rectangle-draw', 'rectangle_draw', 'build-v1', 'validation-v1'),
        ('mask-span', 'mask_span', 'build-v1', 'validation-v1'),
        ('sprite-draw', 'sprite_draw', 'build-v2', 'validation-v3'),
        ('sprite-logic', 'sprite_logic', 'build-v1', 'validation-v4'),
        ('small-state', 'small_state', 'build-v1', 'validation-v3'),
        ('small-platform', 'small_platform', 'build-v1', 'validation-v1'),
        ('copy-config', 'copy_config', 'build-v1', 'validation-v1'),
        ('config-apply', 'config_apply', 'build-v1', 'validation-v1'),
        ('config-fields', 'config_fields', 'build-v1', 'validation-v1'),
        ('raw-write', 'raw_write', 'build-v1', 'validation-v1'),
        ('wait-roots', 'wait_roots', 'build-v1', 'validation-v1'),
        ('shift-assign', 'shift_assign', 'build-v1', 'validation-v1'),
        ('scalar-state', 'scalar_state', 'build-v1', 'validation-v1'),
        ('scan-length', 'scan_length', 'build-v2', 'validation-v1'),
        ('string-memory', 'string_memory', 'build-v2', 'validation-v2'),
        ('table-scalar', 'table_scalar', 'build-v1', 'validation-v1'),
        ('small-arithmetic', 'small_arithmetic', 'build-v2', 'validation-v2'),
        ('delete-file', 'delete_file', 'build-v2', 'validation-v2'),
        ('finalizer-list', 'finalizer_list', 'build-v1', 'validation-v2'),
        ('runtime-message', 'runtime_message', 'build-v1', 'validation-v1'),
        ('runtime-diagnostic', 'runtime_diagnostic', 'build-v1', 'validation-v1'),
        ('runtime-vectors', 'runtime_vectors', 'build-v1', 'validation-v1'),
        ('runtime-exit', 'runtime_exit', 'build-v1', 'validation-v1'),
        ('stream-records', 'stream_records', 'build-v1', 'validation-v3'),
        ('small-algorithms', 'small_algorithms', 'build-v1', 'validation-v1'),
        ('far-member', 'far_member', 'build-v1', 'validation-v1'),
        ('relative-wait', 'relative_wait', 'build-v1', 'validation-v1'),
        ('record-math', 'record_math', 'build-v1', 'validation-v1'),
        ('radix-text', 'radix_text', 'build-v1', 'validation-v1'),
        ('record-sequence', 'record_sequence', 'build-v1', 'validation-v1'),
        ('member-reorder', 'member_reorder', 'build-v1', 'validation-v3'),
        ('ring-selection', 'ring_selection', 'build-v1', 'validation-v1'),
        ('runtime-wrappers', 'runtime_wrappers', 'build-v1', 'validation-v1'),
        ('long-arithmetic', 'long_arithmetic', 'build-v1', 'validation-v1'),
        ('record-flags', 'record_flags', 'build-v1', 'validation-v1'),
        ('record-controller', 'record_controller', 'build-v1', 'validation-v3'),
        ('pair-controller', 'pair_controller', 'build-v1', 'validation-v3'),
        ('field-controller', 'field_controller', 'build-v1', 'validation-v2'),
        ('close-handle', 'close_handle', 'build-v1', 'validation-v2'),
        ('seek-handle', 'seek_handle', 'build-v1', 'validation-v1'),
        ('seek-parent', 'seek_parent', 'build-v1', 'validation-v2'),
        ('control-bus', 'control_bus', 'build-v1', 'validation-v1'),
        ('control-controllers', 'control_controllers', 'build-v1', 'validation-v2'),
        ('secondary-fields', 'secondary_fields', 'build-v1', 'validation-v2'),
        ('record-dispatch', 'record_dispatch', 'build-v1', 'validation-v2'),
        ('number-field', 'number_field', 'build-v1', 'validation-v1'),
        ('mode-controller', 'mode_controller', 'build-v1', 'validation-v3'),
        ('record-projection', 'record_projection', 'build-v1', 'validation-v1'),
        ('field-text', 'field_text', 'build-v1', 'validation-v1'),
        ('block-adjust', 'block_adjust', 'build-v1', 'validation-v1'),
        ('block-request', 'block_request', 'build-v1', 'validation-v3'),
        ('block-wrapper', 'block_wrapper', 'build-v1', 'validation-v2'),
        ('block-tail', 'block_tail', 'build-v1', 'validation-v3'),
        ('block-align', 'block_align', 'build-v1', 'validation-v1'),
        ('heap-walk', 'heap_walk', 'build-v1', 'validation-v3'),
        ('heap-public', 'heap_public', 'build-v1', 'validation-v2'),
        ('stream-buffer', 'stream_buffer', 'build-v1', 'validation-v2'),
        ('stream-push-byte', 'stream_push_byte', 'build-v1', 'validation-v2'),
        ('write-span', 'write_span', 'build-v1', 'validation-v1'),
        ('record-name-select', 'record_name_select', 'build-v1', 'validation-v2'),
        ('dual-name-select', 'dual_name_select', 'build-v1', 'validation-v2'),
        ('plane-fill', 'plane_fill', 'build-v2', 'validation-v2'),
        ('fallback-mode', 'fallback_mode', 'build-v1', 'validation-v1'),
        ('video-init', 'video_init', 'build-v1', 'validation-v2'),
        ('video-reset', 'video_reset', 'build-v1', 'validation-v1'),
        ('discard-object', 'discard_object', 'build-v2', 'validation-v2'),
        ('discard-wrappers', 'discard_wrappers', 'build-v1', 'validation-v1'),
        ('pixel-point', 'pixel_point', 'build-v2', 'validation-v1'),
        ('exit-video', 'exit_video', 'build-v1', 'validation-v2'),
        ('plane-byte-copy', 'plane_byte_copy', 'build-v1', 'validation-v1'),
        ('read-span', 'read_span', 'build-v1', 'validation-v1'),
        ('stream-pull-byte', 'stream_pull_byte', 'build-v1', 'validation-v2'),
        ('stream-next-byte', 'stream_next_byte', 'build-v1', 'validation-v2'),
        ('point-update', 'point_update', 'build-v1', 'validation-v1'),
        ('point-sequence', 'point_sequence', 'build-v1', 'validation-v1'),
        ('plane-gather', 'plane_gather', 'build-v1', 'validation-v1'),
        ('plane-shift-strip', 'plane_shift_strip', 'build-v1', 'validation-v2'),
        ('view-fill', 'view_fill', 'build-v1', 'validation-v1'),
        ('sample-adjust', 'sample_adjust', 'build-v1', 'validation-v2'),
        ('sample-guards', 'sample_guards', 'build-v1', 'validation-v2'),
        ('threshold-transition', 'threshold_transition', 'build-v1', 'validation-v3'),
        ('window-controllers', 'window_controllers', 'build-v1', 'validation-v2'),
        ('indexed-sample', 'indexed_sample', 'build-v1', 'validation-v2'),
        ('sim-dispatch-bus', 'sim_dispatch_bus', 'build-v1', 'validation-v1'),
        ('sample-fields-bus', 'sample_fields_bus', 'build-v1', 'validation-v1'),
        ('sim-controller', 'sim_controller', 'build-v1', 'validation-v3'),
        ('input-fields-bus', 'input_fields_bus', 'build-v1', 'validation-v4'),
        ('motion-scan-bus', 'motion_scan_bus', 'build-v1', 'validation-v1'),
        ('keyboard-bios-bus', 'keyboard_bios_bus', 'build-v1', 'validation-v1'),
        ('gameport-bus', 'gameport_bus', 'build-v1', 'validation-v1'),
        ('key-dispatch-bus', 'key_dispatch_bus', 'build-v1', 'validation-v1'),
        ('input-poll-bus', 'input_poll_bus', 'build-v1', 'validation-v3'),
        ('motion-flags-bus', 'motion_flags_bus', 'build-v1', 'validation-v2'),
        ('input-update-bus', 'input_update_bus', 'build-v2', 'validation-v3'),
        ('state-tick-bus', 'state_tick_bus', 'build-v1', 'validation-v5'),
        ('timer-handler-bus', 'timer_handler_bus', 'build-v3', 'validation-v3'),
        ('effect-tick-bus', 'effect_tick_bus', 'build-v2', 'validation-v2'),
        ('timer-handler-bus-flags', 'timer_handler_bus_flags', 'build-v1', 'validation-v1'),
        ('timer-control-bus', 'timer_control_bus', 'build-v1', 'validation-v1'),
        ('timer-callback-bus', 'timer_callback_bus', 'build-v1', 'validation-v1'),
        ('timer-startup-tail-bus', 'timer_startup_tail_bus', 'build-v1', 'validation-v1'),
        ('session-init-bus', 'session_init_bus', 'build-v1', 'validation-v2'),
        ('runtime-dispatch-bus', 'runtime_dispatch_bus', 'build-v1', 'validation-v2'),
        ('runtime-report-bus', 'runtime_report_bus', 'build-v1', 'validation-v1'),
    ]
    for stem, source, build_version, comparison_version in helper_specs:
        build_path = f'docs/recovery/evidence/td2ega-{stem}-{build_version}.json'
        comparison_path = f'docs/recovery/evidence/td2ega-{stem}-{comparison_version}.json'
        build = json.loads((ROOT / build_path).read_text())
        comparison = json.loads((ROOT / comparison_path).read_text())
        artifacts = build['sources'] + build['outputs'] + [build['executed_recipe'], build['compiler']]
        artifacts += build.get('failed_setup_attempt', []) + build.get('prior_failed_attempt', [])
        if 'architecture_reference' in build:
            artifacts += [build['architecture_reference']]
        if 'static_context' in build:
            artifacts += [build['static_context']]
        if 'log' in build:
            artifacts += [build['log']]
        if 'validator_dependency' in comparison:
            artifacts += [comparison['validator_dependency']]
        artifacts += comparison.get('validator_dependencies', []) + comparison.get('native_libraries', [])
        for item in artifacts:
            if digest(ROOT / item['path']) != item['sha256']:
                problems.append('Build/validation artifact mismatch: ' + item['path'])
        if comparison['source_sha256'] != digest(ROOT / f'src/recovered/td2ega_{source}.c'):
            problems.append('Differential source identity mismatch: ' + stem)
        if comparison['validator_sha256'] != digest(ROOT / f'tools/validate_{source}.py'):
            problems.append('Differential validator identity mismatch: ' + stem)
        libraries = [item for item in build['outputs'] if item['path'].endswith('.dll')]
        verified_library_hashes.update(item['sha256'] for item in libraries)
        if len(libraries) != 1 or comparison['library_sha256'] != libraries[0]['sha256']:
            problems.append('Build/differential DLL identity mismatch: ' + stem)
        if len(libraries) == 1:
            exports = pe_export_names(ROOT / libraries[0]['path'])
            recipe_exports = set(re.findall(r'/EXPORT:([A-Za-z_][A-Za-z_0-9]*)',
                                           (ROOT / build['executed_recipe']['path']).read_text()))
            if exports != recipe_exports:
                problems.append('Native PE/recipe exports mismatch: ' + stem)
            native_exports.update(exports)
        comparison_ids = comparison.get('function_ids', [comparison.get('function_id')])
        build_ids = build.get('function_ids', [build.get('function_id')])
        compiled_original_entries.update(build_ids + build.get('covered_original_local_helpers', []))
        if comparison['result'] != 'pass' or build['result'] != 'pass' or comparison_ids != build_ids or any(id not in function_ids for id in comparison_ids):
            problems.append('Differential/build result/identity mismatch: ' + stem)
        helper_checks.append({'function_ids': comparison_ids, 'vectors': comparison['vectors'],
                              'build': build_path, 'comparison': comparison_path,
                              'scope': comparison.get('limits', build.get('limit'))})
    native_summary = {'exports': len(native_exports), 'original_entries': len(compiled_original_entries),
                      'comparison_suites': len(helper_checks), 'vectors': sum(h['vectors'] for h in helper_checks)}
    progress = json.loads((ROOT / 'docs/recovery/progress.json').read_text())
    if progress.get('native_summary') != native_summary:
        problems.append('Progress native summary differs from PE/build/comparison evidence')
    registered_native = {f['id'] for f in functions if f['portable_source']}
    if compiled_original_entries != registered_native:
        problems.append('Compiled original-entry set differs from portable-source registry')
    for history_path in ['docs/recovery/evidence/td2ega-initial-input-contract-history-v1.json',
                         'docs/recovery/evidence/td2ega-bios-flag-contract-history-v1.json']:
        history = json.loads((ROOT / history_path).read_text())
        for item in history['files']:
            archived = ROOT / item['archived_path']
            if digest(archived) != item['sha256'] or archived.stat().st_size != item['bytes']:
                problems.append('Historical source custody mismatch: ' + item['archived_path'])
        for item in history['evidence_records']:
            if digest(ROOT / item['path']) != item['sha256']:
                problems.append('Frozen historical receipt mismatch: ' + item['path'])
    api_reference = json.loads((ROOT / 'docs/recovery/evidence/msdos-api-reference-v1.json').read_text())
    api_path = ROOT / api_reference['private_path']
    api_reference_ok = digest(api_path) == api_reference['sha256'] and api_path.stat().st_size == api_reference['bytes'] and api_reference['commit'] in api_reference['url']
    if not api_reference_ok:
        problems.append('Historical API reference identity/pinning mismatch')
    if by['P1-11']['status'] == 'complete' and any(f['gates']['code_contract']['status'] not in ('passed', 'not_applicable') for f in functions):
        problems.append('P1-11 declared complete with open function contracts')
    scoped_evidence = []
    for path, script, expected_vectors in [
        ('docs/recovery/evidence/td2ega-packed-loader-composition-v1.json', 'tools/validate_packed_loader_composition.py', 48),
        ('docs/recovery/evidence/td2ega-main-review-v2.json', 'tools/review_ega_main.py', None),
        ('docs/recovery/evidence/td2ega-cache-callers-v1.json', 'tools/map_ega_cache_callers.py', None),
        ('docs/recovery/evidence/td2ega-session-resource-review-v1.json', 'tools/review_ega_session_resources.py', None),
        ('docs/recovery/evidence/td2ega-main-mutator-validation-v2.json', 'tools/validate_main_mutator.py', 1920),
        ('docs/recovery/evidence/td2ega-state-tail-modes-v1.json', 'tools/validate_state_tail_modes.py', 2048),
        ('docs/recovery/evidence/td2ega-retry-mutator-context-v1.json', 'tools/validate_retry_mutator_context.py', 224),
        ('docs/recovery/evidence/td2ega-byte-ring-nested-v1.json', 'tools/validate_byte_ring_nested.py', 45056),
        ('docs/recovery/evidence/td2ega-byte-ring-caller-if-v1.json', 'tools/validate_byte_ring_caller_if.py', 160),
        ('docs/recovery/evidence/td2ega-fatal-default-v1.json', 'tools/validate_fatal_default.py', 64),
        ('docs/recovery/evidence/td2ega-timer-callback-lifetime-v1.json', 'tools/validate_timer_callback_lifetime.py', 16),
        ('docs/recovery/evidence/td2ega-find-nth-native-diagnostics-v1.json', 'tools/validation/validate_find_nth_budget.py', 3),
        ('docs/recovery/evidence/td2ega-music-tick-native-diagnostics-v1.json', 'tools/validation/validate_music_tick_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-effect-tick-native-diagnostics-v1.json', 'tools/validation/validate_effect_tick_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-timer-handler-native-diagnostics-v1.json', 'tools/validation/validate_timer_handler_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-key-actions-native-diagnostics-v1.json', 'tools/validation/validate_key_actions_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-keyboard-native-diagnostics-v1.json', 'tools/validation/validate_keyboard_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-input-bios-flags-native-diagnostics-v1.json', 'tools/validation/validate_input_bios_flags.py', 3),
        ('docs/recovery/evidence/td2ega-installed-keyboard-poll-v1.json', 'tools/validate_installed_keyboard_poll.py', 2876),
        ('docs/recovery/evidence/td2ega-installed-keyboard-update-v1.json', 'tools/validate_installed_keyboard_update.py', 9984),
        ('docs/recovery/evidence/td2ega-prepare-records-native-diagnostics-v1.json', 'tools/validation/validate_prepare_records_diagnostics.py', 3),
        ('docs/recovery/evidence/td2ega-state-loop-native-diagnostics-v1.json', 'tools/validation/validate_state_loop_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-wait-control-native-diagnostics-v1.json', 'tools/validation/validate_wait_control_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-state-messages-native-diagnostics-v1.json', 'tools/validation/validate_state_messages_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-input-bridge-native-diagnostics-v1.json', 'tools/validation/validate_input_bridge_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-state-sequences-native-diagnostics-v1.json', 'tools/validation/validate_state_sequences_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-bios-block-native-diagnostics-v1.json', 'tools/validation/validate_bios_block_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-wait-latch-native-diagnostics-v1.json', 'tools/validation/validate_wait_latch_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-loop-prepare-native-diagnostics-v1.json', 'tools/validation/validate_loop_prepare_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-loop-controls-native-diagnostics-v1.json', 'tools/validation/validate_loop_controls_diagnostics.py', 5),
        ('docs/recovery/evidence/td2ega-near-clamp-native-diagnostics-v2.json', 'tools/validation/validate_near_clamp_diagnostics_v2.py', 2),
        ('docs/recovery/evidence/td2ega-projection-native-diagnostics-v1.json', 'tools/validation/validate_projection_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-line-step-native-diagnostics-v1.json', 'tools/validation/validate_line_step_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-record-interpolate-native-diagnostics-v1.json', 'tools/validation/validate_record_interpolate_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-view-limits-native-diagnostics-v1.json', 'tools/validation/validate_view_limits_diagnostics.py', 4),
        ('docs/recovery/evidence/td2ega-draw-sequence-native-diagnostics-v1.json', 'tools/validation/validate_draw_sequence_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-plane-span-native-diagnostics-v1.json', 'tools/validation/validate_plane_span_diagnostics.py', 3),
        ('docs/recovery/evidence/td2ega-plane-rows-native-diagnostics-v1.json', 'tools/validation/validate_plane_rows_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-edge-sequence-native-diagnostics-v1.json', 'tools/validation/validate_edge_sequence_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-line-draw-native-diagnostics-v1.json', 'tools/validation/validate_line_draw_diagnostics.py', 3),
        ('docs/recovery/evidence/td2ega-rectangle-draw-native-diagnostics-v1.json', 'tools/validation/validate_rectangle_draw_diagnostics.py', 2),
        ('docs/recovery/evidence/td2ega-mask-span-native-diagnostics-v1.json', 'tools/validation/validate_mask_span_diagnostics.py', 3),
        ('docs/recovery/evidence/td2ega-sprite-draw-native-diagnostics-v1.json', 'tools/validation/validate_sprite_draw_diagnostics.py', 6),
        ('docs/recovery/evidence/td2ega-sprite-context-v1.json', 'tools/review_ega_sprite_context.py', None),
        ('docs/recovery/evidence/td2ega-sprite-logic-native-diagnostics-v1.json', 'tools/validation/validate_sprite_logic_diagnostics.py', 6),
        ('docs/recovery/evidence/td2ega-sprite-logic-context-v1.json', 'tools/review_ega_sprite_logic.py', None),
        ('docs/recovery/evidence/td2ega-small-state-native-diagnostics-v2.json', 'tools/validation/validate_small_state_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-small-platform-native-diagnostics-v1.json', 'tools/validation/validate_small_platform_diagnostics.py', 10),
        ('docs/recovery/evidence/td2ega-small-platform-context-v1.json', 'tools/review_ega_small_platform.py', None),
        ('docs/recovery/evidence/td2ega-copy-config-native-diagnostics-v1.json', 'tools/validation/validate_copy_config_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-copy-config-context-v2.json', 'tools/review_ega_copy_config.py', None),
        ('docs/recovery/evidence/td2ega-config-apply-native-diagnostics-v1.json', 'tools/validation/validate_config_apply_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-config-fields-native-diagnostics-v1.json', 'tools/validation/validate_config_fields_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-config-fields-context-v1.json', 'tools/review_ega_config_fields.py', None),
        ('docs/recovery/evidence/td2ega-raw-write-native-diagnostics-v1.json', 'tools/validation/validate_raw_write_diagnostics.py', 10),
        ('docs/recovery/evidence/td2ega-raw-write-context-v1.json', 'tools/review_ega_raw_write.py', None),
        ('docs/recovery/evidence/td2ega-wait-roots-native-diagnostics-v1.json', 'tools/validation/validate_wait_roots_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-wait-roots-context-v1.json', 'tools/review_ega_wait_roots.py', None),
        ('docs/recovery/evidence/td2ega-shift-assign-native-diagnostics-v1.json', 'tools/validation/validate_shift_assign_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-shift-assign-context-v1.json', 'tools/review_ega_shift_assign.py', None),
        ('docs/recovery/evidence/td2ega-scalar-state-native-diagnostics-v1.json', 'tools/validation/validate_scalar_state_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-scalar-state-context-v1.json', 'tools/review_ega_scalar_state.py', None),
        ('docs/recovery/evidence/td2ega-scan-length-native-diagnostics-v1.json', 'tools/validation/validate_scan_length_diagnostics.py', 8),
        ('docs/recovery/evidence/td2ega-scan-length-context-v1.json', 'tools/review_ega_scan_length.py', None),
        ('docs/recovery/evidence/td2ega-string-memory-native-diagnostics-v1.json', 'tools/validation/validate_string_memory_diagnostics.py', 9),
        ('docs/recovery/evidence/td2ega-string-memory-context-v1.json', 'tools/review_ega_string_memory.py', None),
        ('docs/recovery/evidence/td2ega-table-scalar-native-diagnostics-v1.json', 'tools/validation/validate_table_scalar_diagnostics.py', 9),
        ('docs/recovery/evidence/td2ega-table-scalar-context-v1.json', 'tools/review_ega_table_scalar.py', None),
        ('docs/recovery/evidence/td2ega-small-arithmetic-native-diagnostics-v2.json', 'tools/validation/validate_small_arithmetic_diagnostics.py', 9),
        ('docs/recovery/evidence/td2ega-small-arithmetic-context-v1.json', 'tools/review_ega_small_arithmetic.py', None),
        ('docs/recovery/evidence/td2ega-delete-file-native-diagnostics-v1.json', 'tools/validation/validate_delete_file_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-delete-file-context-v1.json', 'tools/review_ega_delete_file.py', None),
        ('docs/recovery/evidence/td2ega-finalizer-list-native-diagnostics-v1.json', 'tools/validation/validate_finalizer_list_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-finalizer-list-context-v1.json', 'tools/review_ega_finalizer_list.py', None),
        ('docs/recovery/evidence/td2ega-runtime-message-native-diagnostics-v1.json', 'tools/validation/validate_runtime_message_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-runtime-message-context-v1.json', 'tools/review_ega_runtime_message.py', None),
        ('docs/recovery/evidence/td2ega-runtime-diagnostic-native-diagnostics-v1.json', 'tools/validation/validate_runtime_diagnostic_diagnostics.py', 18),
        ('docs/recovery/evidence/td2ega-runtime-diagnostic-context-v1.json', 'tools/review_ega_runtime_diagnostic.py', None),
        ('docs/recovery/evidence/td2ega-runtime-vectors-native-diagnostics-v1.json', 'tools/validation/validate_runtime_vectors_diagnostics.py', 17),
        ('docs/recovery/evidence/td2ega-runtime-vectors-context-v1.json', 'tools/review_ega_runtime_vectors.py', None),
        ('docs/recovery/evidence/td2ega-runtime-exit-native-diagnostics-v1.json', 'tools/validation/validate_runtime_exit_diagnostics.py', 20),
        ('docs/recovery/evidence/td2ega-runtime-exit-context-v1.json', 'tools/review_ega_runtime_exit.py', None),
        ('docs/recovery/evidence/td2ega-stream-records-native-diagnostics-v2.json', 'tools/validation/validate_stream_records_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-stream-records-context-v2.json', 'tools/review_ega_stream_records.py', None),
        ('docs/recovery/evidence/td2ega-small-algorithms-native-diagnostics-v1.json', 'tools/validation/validate_small_algorithms_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-small-algorithms-context-v1.json', 'tools/review_ega_small_algorithms.py', None),
        ('docs/recovery/evidence/td2ega-far-member-native-diagnostics-v1.json', 'tools/validation/validate_far_member_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-far-member-context-v1.json', 'tools/review_ega_far_member.py', None),
        ('docs/recovery/evidence/td2ega-relative-wait-native-diagnostics-v1.json', 'tools/validation/validate_relative_wait_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-relative-wait-context-v1.json', 'tools/review_ega_relative_wait.py', None),
        ('docs/recovery/evidence/td2ega-record-math-native-diagnostics-v1.json', 'tools/validation/validate_record_math_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-record-math-context-v1.json', 'tools/review_ega_record_math.py', None),
        ('docs/recovery/evidence/td2ega-radix-text-native-diagnostics-v1.json', 'tools/validation/validate_radix_text_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-radix-text-context-v1.json', 'tools/review_ega_radix_text.py', None),
        ('docs/recovery/evidence/td2ega-record-sequence-native-diagnostics-v1.json', 'tools/validation/validate_record_sequence_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-record-sequence-context-v1.json', 'tools/review_ega_record_sequence.py', None),
        ('docs/recovery/evidence/td2ega-member-reorder-native-diagnostics-v1.json', 'tools/validation/validate_member_reorder_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-member-reorder-context-v1.json', 'tools/review_ega_member_reorder.py', None),
        ('docs/recovery/evidence/td2ega-ring-selection-native-diagnostics-v1.json', 'tools/validation/validate_ring_selection_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-ring-selection-context-v1.json', 'tools/review_ega_ring_selection.py', None),
        ('docs/recovery/evidence/td2ega-runtime-wrappers-native-diagnostics-v1.json', 'tools/validation/validate_runtime_wrappers_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-runtime-wrappers-context-v1.json', 'tools/review_ega_runtime_wrappers.py', None),
        ('docs/recovery/evidence/td2ega-long-arithmetic-native-diagnostics-v1.json', 'tools/validation/validate_long_arithmetic_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-long-arithmetic-context-v1.json', 'tools/review_ega_long_arithmetic.py', None),
        ('docs/recovery/evidence/td2ega-record-flags-native-diagnostics-v1.json', 'tools/validation/validate_record_flags_diagnostics.py', 13),
        ('docs/recovery/evidence/td2ega-record-flags-context-v1.json', 'tools/review_ega_record_flags.py', None),
        ('docs/recovery/evidence/td2ega-record-controller-native-diagnostics-v3.json', 'tools/validation/validate_record_controller_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-record-controller-context-v1.json', 'tools/review_ega_record_controller.py', None),
        ('docs/recovery/evidence/td2ega-pair-controller-native-diagnostics-v2.json', 'tools/validation/validate_pair_controller_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-pair-controller-context-v1.json', 'tools/review_ega_pair_controller.py', None),
        ('docs/recovery/evidence/td2ega-field-controller-native-diagnostics-v1.json', 'tools/validation/validate_field_controller_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-field-controller-context-v1.json', 'tools/review_ega_field_controller.py', None),
        ('docs/recovery/evidence/td2ega-close-handle-native-diagnostics-v2.json', 'tools/validation/validate_close_handle_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-close-handle-context-v1.json', 'tools/review_ega_close_handle.py', None),
        ('docs/recovery/evidence/td2ega-seek-handle-native-diagnostics-v1.json', 'tools/validation/validate_seek_handle_diagnostics.py', 17),
        ('docs/recovery/evidence/td2ega-seek-handle-context-v1.json', 'tools/review_ega_seek_handle.py', None),
        ('docs/recovery/evidence/td2ega-seek-parent-native-diagnostics-v2.json', 'tools/validation/validate_seek_parent_diagnostics.py', 13),
        ('docs/recovery/evidence/td2ega-seek-parent-context-v1.json', 'tools/review_ega_seek_parent.py', None),
        ('docs/recovery/evidence/td2ega-control-bus-native-diagnostics-v1.json', 'tools/validation/validate_control_bus_diagnostics.py', 17),
        ('docs/recovery/evidence/td2ega-control-bus-context-v1.json', 'tools/review_ega_control_bus.py', None),
        ('docs/recovery/evidence/td2ega-control-table-context-v1.json', 'tools/review_ega_control_table.py', None),
        ('docs/recovery/evidence/td2ega-control-controllers-native-diagnostics-v1.json', 'tools/validation/validate_control_controllers_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-control-controllers-context-v1.json', 'tools/review_ega_control_controllers.py', None),
        ('docs/recovery/evidence/td2ega-secondary-fields-native-diagnostics-v1.json', 'tools/validation/validate_secondary_fields_diagnostics.py', 16),
        ('docs/recovery/evidence/td2ega-secondary-fields-context-v1.json', 'tools/review_ega_secondary_fields.py', None),
        ('docs/recovery/evidence/td2ega-record-dispatch-native-diagnostics-v1.json', 'tools/validation/validate_record_dispatch_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-record-dispatch-context-v1.json', 'tools/review_ega_record_dispatch.py', None),
        ('docs/recovery/evidence/td2ega-sample-table-context-v1.json', 'tools/review_ega_sample_table.py', None),
        ('docs/recovery/evidence/td2ega-number-field-context-v1.json', 'tools/review_ega_number_field.py', None),
        ('docs/recovery/evidence/td2ega-mode-controller-context-v1.json', 'tools/review_ega_mode_controller.py', None),
        ('docs/recovery/evidence/td2ega-record-projection-context-v1.json', 'tools/review_ega_record_projection.py', None),
        ('docs/recovery/evidence/td2ega-field-text-context-v1.json', 'tools/review_ega_field_text.py', None),
        ('docs/recovery/evidence/td2ega-block-adjust-context-v1.json', 'tools/review_ega_block_adjust.py', None),
        ('docs/recovery/evidence/td2ega-block-request-context-v1.json', 'tools/review_ega_block_request.py', None),
        ('docs/recovery/evidence/td2ega-block-wrapper-context-v1.json', 'tools/review_ega_block_wrapper.py', None),
        ('docs/recovery/evidence/td2ega-block-tail-context-v2.json', 'tools/review_ega_block_tail.py', None),
        ('docs/recovery/evidence/td2ega-block-align-context-v1.json', 'tools/review_ega_block_align.py', None),
        ('docs/recovery/evidence/td2ega-heap-walk-context-v1.json', 'tools/review_ega_heap_walk.py', None),
        ('docs/recovery/evidence/td2ega-heap-public-context-v1.json', 'tools/review_ega_heap_public.py', None),
        ('docs/recovery/evidence/td2ega-stream-buffer-context-v1.json', 'tools/review_ega_stream_buffer.py', None),
        ('docs/recovery/evidence/td2ega-stream-push-byte-context-v1.json', 'tools/review_ega_stream_push_byte.py', None),
        ('docs/recovery/evidence/td2ega-write-span-context-v1.json', 'tools/review_ega_write_span.py', None),
        ('docs/recovery/evidence/td2ega-record-name-select-context-v1.json', 'tools/review_ega_record_name_select.py', None),
        ('docs/recovery/evidence/td2ega-dual-name-select-context-v1.json', 'tools/review_ega_dual_name_select.py', None),
        ('docs/recovery/evidence/td2ega-plane-fill-context-v2.json', 'tools/review_ega_plane_fill.py', None),
        ('docs/recovery/evidence/td2ega-fallback-mode-context-v1.json', 'tools/review_ega_fallback_mode.py', None),
        ('docs/recovery/evidence/td2ega-video-init-context-v1.json', 'tools/review_ega_video_init.py', None),
        ('docs/recovery/evidence/td2ega-video-reset-context-v1.json', 'tools/review_ega_video_reset.py', None),
        ('docs/recovery/evidence/td2ega-discard-object-context-v1.json', 'tools/review_ega_discard_object.py', None),
        ('docs/recovery/evidence/td2ega-discard-wrappers-context-v1.json', 'tools/review_ega_discard_wrappers.py', None),
        ('docs/recovery/evidence/td2ega-pixel-point-context-v2.json', 'tools/review_ega_pixel_point.py', None),
        ('docs/recovery/evidence/td2ega-exit-video-context-v1.json', 'tools/review_ega_exit_video.py', None),
        ('docs/recovery/evidence/td2ega-plane-byte-copy-context-v1.json', 'tools/review_ega_plane_byte_copy.py', None),
        ('docs/recovery/evidence/td2ega-read-span-context-v2.json', 'tools/review_ega_read_span.py', None),
        ('docs/recovery/evidence/td2ega-stream-pull-byte-context-v1.json', 'tools/review_ega_stream_pull_byte.py', None),
        ('docs/recovery/evidence/td2ega-stream-next-byte-context-v1.json', 'tools/review_ega_stream_next_byte.py', None),
        ('docs/recovery/evidence/td2ega-point-update-context-v1.json', 'tools/review_ega_point_update.py', None),
        ('docs/recovery/evidence/td2ega-point-sequence-context-v1.json', 'tools/review_ega_point_sequence.py', None),
        ('docs/recovery/evidence/td2ega-plane-gather-context-v2.json', 'tools/review_ega_plane_gather.py', None),
        ('docs/recovery/evidence/td2ega-plane-shift-strip-context-v1.json', 'tools/review_ega_plane_shift_strip.py', None),
        ('docs/recovery/evidence/td2ega-view-fill-context-v1.json', 'tools/review_ega_view_fill.py', None),
        ('docs/recovery/evidence/td2ega-sample-adjust-context-v1.json', 'tools/review_ega_sample_adjust.py', None),
        ('docs/recovery/evidence/td2ega-sample-guards-context-v2.json', 'tools/review_ega_sample_guards.py', None),
        ('docs/recovery/evidence/td2ega-threshold-transition-context-v1.json', 'tools/review_ega_threshold_transition.py', None),
        ('docs/recovery/evidence/td2ega-window-controllers-context-v2.json', 'tools/review_ega_window_controllers.py', None),
        ('docs/recovery/evidence/td2ega-indexed-sample-context-v1.json', 'tools/review_ega_indexed_sample.py', None),
        ('docs/recovery/evidence/td2ega-sim-dispatch-bus-context-v1.json', 'tools/review_ega_sim_dispatch_bus.py', None),
        ('docs/recovery/evidence/td2ega-sample-fields-bus-context-v1.json', 'tools/review_ega_sample_fields_bus.py', None),
        ('docs/recovery/evidence/td2ega-sim-controller-context-v2.json', 'tools/review_ega_sim_controller.py', None),
        ('docs/recovery/evidence/td2ega-input-fields-bus-context-v2.json', 'tools/review_ega_input_fields_bus.py', None),
        ('docs/recovery/evidence/td2ega-motion-scan-bus-context-v1.json', 'tools/review_ega_motion_scan_bus.py', None),
        ('docs/recovery/evidence/td2ega-keyboard-bios-bus-context-v1.json', 'tools/review_ega_keyboard_bios_bus.py', None),
        ('docs/recovery/evidence/td2ega-gameport-bus-context-v1.json', 'tools/review_ega_gameport_bus.py', None),
        ('docs/recovery/evidence/td2ega-key-dispatch-bus-context-v1.json', 'tools/review_ega_key_dispatch_bus.py', None),
        ('docs/recovery/evidence/td2ega-input-poll-bus-context-v1.json', 'tools/review_ega_input_poll_bus.py', None),
        ('docs/recovery/evidence/td2ega-motion-flags-bus-context-v1.json', 'tools/review_ega_motion_flags_bus.py', None),
        ('docs/recovery/evidence/td2ega-input-update-bus-context-v1.json', 'tools/review_ega_input_update_bus.py', None),
        ('docs/recovery/evidence/td2ega-input-update-bus-native-diagnostics-v3.json', 'tools/validation/validate_input_update_bus_diagnostics.py', 29),
        ('docs/recovery/evidence/td2ega-input-update-bus-counter-review-v2.json', 'tools/review_ega_input_update_bus_counters.py', None),
        ('docs/recovery/evidence/td2ega-state-tick-bus-context-v2.json', 'tools/review_ega_state_tick_bus.py', None),
        ('docs/recovery/evidence/td2ega-state-tick-bus-native-diagnostics-v2.json', 'tools/validation/validate_state_tick_bus_diagnostics_v2.py', 28),
        ('docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json', 'tools/review_ega_timer_handler_bus.py', None),
        ('docs/recovery/evidence/td2ega-timer-handler-bus-native-diagnostics-v2.json', 'tools/validation/validate_timer_handler_bus_diagnostics.py', 31),
        ('docs/recovery/evidence/td2ega-timer-state-tick-prefix-v2.json', 'tools/validate_timer_state_tick_prefix.py', 12800),
        ('docs/recovery/evidence/td2ega-effect-tick-bus-context-v1.json', 'tools/review_ega_effect_tick_bus.py', None),
        ('docs/recovery/evidence/td2ega-effect-tick-bus-native-diagnostics-v1.json', 'tools/validation/validate_effect_tick_bus_diagnostics.py', 22),
        ('docs/recovery/evidence/td2ega-timer-callback-order-v2.json', 'tools/validate_timer_callback_order.py', 14560),
        ('docs/recovery/evidence/td2ega-timer-handler-bus-flags-context-v1.json', 'tools/review_ega_timer_handler_bus_flags.py', None),
        ('docs/recovery/evidence/td2ega-timer-handler-bus-flags-native-diagnostics-v1.json', 'tools/validation/validate_timer_handler_bus_flags_diagnostics.py', 9),
        ('docs/recovery/evidence/td2ega-timer-control-bus-context-v1.json', 'tools/review_ega_timer_control_bus.py', None),
        ('docs/recovery/evidence/td2ega-timer-control-bus-native-diagnostics-v1.json', 'tools/validation/validate_timer_control_bus_diagnostics.py', 48),
        ('docs/recovery/evidence/td2ega-timer-full-state-tick-v2.json', 'tools/validate_timer_full_state_tick.py', 25024),
        ('docs/recovery/evidence/td2ega-timer-callback-bus-context-v1.json', 'tools/review_ega_timer_callback_bus.py', None),
        ('docs/recovery/evidence/td2ega-timer-callback-bus-native-diagnostics-v1.json', 'tools/validation/validate_timer_callback_bus_diagnostics.py', 22),
        ('docs/recovery/evidence/td2ega-timer-startup-tail-bus-context-v1.json', 'tools/review_ega_timer_startup_tail_bus.py', None),
        ('docs/recovery/evidence/td2ega-timer-startup-tail-bus-native-diagnostics-v1.json', 'tools/validation/validate_timer_startup_tail_bus_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-session-init-bus-context-v1.json', 'tools/review_ega_session_init_bus.py', None),
        ('docs/recovery/evidence/td2ega-session-init-bus-native-diagnostics-v1.json', 'tools/validation/validate_session_init_bus_diagnostics.py', 34),
        ('docs/recovery/evidence/td2ega-runtime-dispatch-bus-context-v2.json', 'tools/review_ega_runtime_dispatch_bus_v2.py', None),
        ('docs/recovery/evidence/td2ega-runtime-dispatch-bus-native-diagnostics-v1.json', 'tools/validation/validate_runtime_dispatch_bus_diagnostics.py', 35),
        ('docs/recovery/evidence/td2ega-runtime-report-bus-context-v1.json', 'tools/review_ega_runtime_report_bus.py', None),
        ('docs/recovery/evidence/td2ega-runtime-report-bus-native-diagnostics-v1.json', 'tools/validation/validate_runtime_report_bus_diagnostics.py', 51),
        ('docs/recovery/evidence/td2ega-runtime-report-bus-alias-validation-v1.json', 'tools/validate_runtime_report_bus_aliases.py', 432),
        ('docs/recovery/evidence/td2ega-motion-flags-bus-native-diagnostics-v1.json', 'tools/validation/validate_motion_flags_bus_diagnostics.py', 22),
        ('docs/recovery/evidence/td2ega-input-poll-bus-native-diagnostics-v3.json', 'tools/validation/validate_input_poll_bus_diagnostics.py', 21),
        ('docs/recovery/evidence/td2ega-key-dispatch-bus-native-diagnostics-v1.json', 'tools/validation/validate_key_dispatch_bus_diagnostics.py', 19),
        ('docs/recovery/evidence/td2ega-gameport-bus-native-diagnostics-v1.json', 'tools/validation/validate_gameport_bus_diagnostics.py', 18),
        ('docs/recovery/evidence/td2ega-keyboard-bios-bus-native-diagnostics-v1.json', 'tools/validation/validate_keyboard_bios_bus_diagnostics.py', 16),
        ('docs/recovery/evidence/td2ega-motion-scan-bus-native-diagnostics-v1.json', 'tools/validation/validate_motion_scan_bus_diagnostics.py', 18),
        ('docs/recovery/evidence/td2ega-input-fields-bus-native-diagnostics-v1.json', 'tools/validation/validate_input_fields_bus_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-sim-controller-native-diagnostics-v2.json', 'tools/validation/validate_sim_controller_diagnostics.py', 12),
        ('docs/recovery/evidence/td2ega-sim-controller-row-cycle-review-v1.json', 'tools/validation/validate_sim_controller_row_cycle.py', 2),
        ('docs/recovery/evidence/td2ega-sample-fields-bus-native-diagnostics-v1.json', 'tools/validation/validate_sample_fields_bus_diagnostics.py', 11),
        ('docs/recovery/evidence/td2ega-sim-dispatch-bus-native-diagnostics-v1.json', 'tools/validation/validate_sim_dispatch_bus_diagnostics.py', 10),
        ('docs/recovery/evidence/td2ega-indexed-sample-native-diagnostics-v2.json', 'tools/validation/validate_indexed_sample_diagnostics.py', 447),
        ('docs/recovery/evidence/td2ega-window-controllers-native-diagnostics-v1.json', 'tools/validation/validate_window_controllers_diagnostics.py', 337),
        ('docs/recovery/evidence/td2ega-threshold-transition-native-diagnostics-v3.json', 'tools/validation/validate_threshold_transition_diagnostics.py', 59),
        ('docs/recovery/evidence/td2ega-sample-guards-native-diagnostics-v1.json', 'tools/validation/validate_sample_guards_diagnostics.py', 59),
        ('docs/recovery/evidence/td2ega-sample-adjust-native-diagnostics-v2.json', 'tools/validation/validate_sample_adjust_diagnostics.py', 80),
        ('docs/recovery/evidence/td2ega-view-fill-native-diagnostics-v1.json', 'tools/validation/validate_view_fill_diagnostics.py', 67),
        ('docs/recovery/evidence/td2ega-plane-shift-strip-native-diagnostics-v1.json', 'tools/validation/validate_plane_shift_strip_diagnostics.py', 48),
        ('docs/recovery/evidence/td2ega-plane-gather-native-diagnostics-v1.json', 'tools/validation/validate_plane_gather_diagnostics.py', 65),
        ('docs/recovery/evidence/td2ega-point-sequence-native-diagnostics-v1.json', 'tools/validation/validate_point_sequence_diagnostics.py', 37),
        ('docs/recovery/evidence/td2ega-point-update-native-diagnostics-v1.json', 'tools/validation/validate_point_update_diagnostics.py', 43),
        ('docs/recovery/evidence/td2ega-stream-next-byte-native-diagnostics-v1.json', 'tools/validation/validate_stream_next_byte_diagnostics.py', 31),
        ('docs/recovery/evidence/td2ega-stream-pull-byte-native-diagnostics-v1.json', 'tools/validation/validate_stream_pull_byte_diagnostics.py', 32),
        ('docs/recovery/evidence/td2ega-read-span-native-diagnostics-v1.json', 'tools/validation/validate_read_span_diagnostics.py', 39),
        ('docs/recovery/evidence/td2ega-plane-byte-copy-native-diagnostics-v1.json', 'tools/validation/validate_plane_byte_copy_diagnostics.py', 36),
        ('docs/recovery/evidence/td2ega-exit-video-native-diagnostics-v2.json', 'tools/validation/validate_exit_video_diagnostics.py', 42),
        ('docs/recovery/evidence/td2ega-pixel-point-native-diagnostics-v1.json', 'tools/validation/validate_pixel_point_diagnostics.py', 37),
        ('docs/recovery/evidence/td2ega-discard-wrappers-native-diagnostics-v1.json', 'tools/validation/validate_discard_wrappers_diagnostics.py', 39),
        ('docs/recovery/evidence/td2ega-discard-object-native-diagnostics-v2.json', 'tools/validation/validate_discard_object_diagnostics.py', 38),
        ('docs/recovery/evidence/td2ega-video-reset-native-diagnostics-v1.json', 'tools/validation/validate_video_reset_diagnostics.py', 33),
        ('docs/recovery/evidence/td2ega-video-init-native-diagnostics-v1.json', 'tools/validation/validate_video_init_diagnostics.py', 37),
        ('docs/recovery/evidence/td2ega-fallback-mode-native-diagnostics-v1.json', 'tools/validation/validate_fallback_mode_diagnostics.py', 33),
        ('docs/recovery/evidence/td2ega-plane-fill-native-diagnostics-v2.json', 'tools/validation/validate_plane_fill_diagnostics.py', 28),
        ('docs/recovery/evidence/td2ega-dual-name-select-native-diagnostics-v1.json', 'tools/validation/validate_dual_name_select_diagnostics.py', 29),
        ('docs/recovery/evidence/td2ega-record-name-select-native-diagnostics-v1.json', 'tools/validation/validate_record_name_select_diagnostics.py', 23),
        ('docs/recovery/evidence/td2ega-write-span-native-diagnostics-v1.json', 'tools/validation/validate_write_span_diagnostics.py', 26),
        ('docs/recovery/evidence/td2ega-stream-push-byte-native-diagnostics-v2.json', 'tools/validation/validate_stream_push_byte_diagnostics.py', 23),
        ('docs/recovery/evidence/td2ega-stream-buffer-native-diagnostics-v2.json', 'tools/validation/validate_stream_buffer_diagnostics.py', 23),
        ('docs/recovery/evidence/td2ega-heap-public-native-diagnostics-v2.json', 'tools/validation/validate_heap_public_diagnostics.py', 22),
        ('docs/recovery/evidence/td2ega-heap-walk-native-diagnostics-v1.json', 'tools/validation/validate_heap_walk_diagnostics.py', 28),
        ('docs/recovery/evidence/td2ega-block-align-native-diagnostics-v1.json', 'tools/validation/validate_block_align_diagnostics.py', 23),
        ('docs/recovery/evidence/td2ega-block-tail-native-diagnostics-v2.json', 'tools/validation/validate_block_tail_diagnostics.py', 20),
        ('docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json', 'tools/validation/validate_twenty_bit_bus.py', 5),
        ('docs/recovery/evidence/td2ega-block-wrapper-native-diagnostics-v2.json', 'tools/validation/validate_block_wrapper_diagnostics.py', 20),
        ('docs/recovery/evidence/td2ega-block-request-native-diagnostics-v2.json', 'tools/validation/validate_block_request_diagnostics.py', 21),
        ('docs/recovery/evidence/td2ega-block-adjust-native-diagnostics-v1.json', 'tools/validation/validate_block_adjust_diagnostics.py', 19),
        ('docs/recovery/evidence/td2ega-field-text-native-diagnostics-v1.json', 'tools/validation/validate_field_text_diagnostics.py', 15),
        ('docs/recovery/evidence/td2ega-record-projection-native-diagnostics-v1.json', 'tools/validation/validate_record_projection_diagnostics.py', 14),
        ('docs/recovery/evidence/td2ega-mode-controller-native-diagnostics-v2.json', 'tools/validation/validate_mode_controller_diagnostics.py', 19),
        ('docs/recovery/evidence/td2ega-number-field-native-diagnostics-v2.json', 'tools/validation/validate_number_field_diagnostics.py', 18),
        ('docs/recovery/evidence/td2ega-ring-selection-save-alias-v1.json', 'tools/validation/validate_ring_selection_save_alias.py', 2048),
        ('docs/recovery/evidence/td2ega-sign-extension-context-v1.json', 'tools/review_ega_sign_extension.py', 60),
        ('docs/recovery/evidence/td2ega-operand-width-context-v1.json', 'tools/review_ega_operand_widths.py', None),
        ('docs/recovery/evidence/td2ega-mask-resource-context-v1.json', 'tools/review_ega_mask_resources.py', None),
        ('docs/recovery/evidence/td2ega-rectangle-resource-context-v1.json', 'tools/review_ega_rectangle_resources.py', None),
        ('docs/recovery/evidence/td2ega-line-resource-context-v1.json', 'tools/review_ega_line_resources.py', None),
        ('docs/recovery/evidence/td2ega-projection-resource-context-v1.json', 'tools/review_ega_projection_resources.py', None),
        ('docs/recovery/evidence/td2ega-plane-resource-context-v1.json', 'tools/review_ega_plane_resources.py', None),
        ('docs/recovery/evidence/td2ega-line-mutation-review-v1.json', 'tools/review_ega_line_mutation.py', None),
        ('docs/recovery/evidence/td2ega-sequence-resource-context-v1.json', 'tools/review_ega_sequence_resources.py', None),
        ('docs/recovery/evidence/td2ega-installed-input-bridge-v1.json', 'tools/validate_installed_input_bridge.py', 3450),
        ('docs/recovery/evidence/td2ega-sequence-platform-composition-v1.json', 'tools/validate_sequence_platform_composition.py', 288),
        ('docs/recovery/evidence/td2ega-state-platform-composition-v1.json', 'tools/validate_state_platform_composition.py', 864),
        ('docs/recovery/evidence/td2ega-prepare-loop-composition-v1.json', 'tools/validate_prepare_loop_composition.py', 1440),
        ('docs/recovery/evidence/td2ega-finish-loop-composition-v1.json', 'tools/validate_finish_loop_composition.py', 1024),
        ('docs/recovery/evidence/td2ega-drawing-composition-v1.json', 'tools/validate_drawing_composition.py', 1792),
        ('docs/recovery/evidence/td2ega-fill-sprite-composition-v1.json', 'tools/validate_fill_sprite_composition.py', 3072),
        ('docs/recovery/evidence/td2ega-message-resource-context-v1.json', 'tools/review_ega_messages.py', None),
    ]:
        record = json.loads((ROOT / path).read_text())
        if record['result'] != 'pass' or record.get('script_sha256', record.get('validator_sha256')) != digest(ROOT / script):
            problems.append('Scoped evidence/script mismatch: ' + path)
        if expected_vectors is not None and record['vectors'] != expected_vectors:
            problems.append('Scoped evidence case count mismatch: ' + path)
        for artifact in record.get('validator_dependencies', []) + record.get('native_libraries', []):
            if digest(ROOT / artifact['path']) != artifact['sha256']:
                problems.append('Scoped dependency/library identity mismatch: ' + artifact['path'])
        if 'native-diagnostics' in path or 'ring-selection-save-alias' in path or 'row-cycle-review' in path:
            diagnostic_hashes = {item['sha256'] for item in record.get('native_libraries', [])}
            if 'library_sha256' in record:
                diagnostic_hashes.add(record['library_sha256'])
            if not diagnostic_hashes or not diagnostic_hashes.issubset(verified_library_hashes):
                problems.append('Native diagnostic library differs from current compiled evidence: ' + path)
        if record['image_sha256'] != digest(ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin'):
            problems.append('Scoped evidence image mismatch: ' + path)
        if 'native_source_sha256' in record:
            if record['native_source_sha256'] != digest(ROOT / 'src/recovered/td2ega_byte_ring.c') or record['library_sha256'] != digest(ROOT / 'analysis/build/byte-ring-repro/td2ega_byte_ring.dll'):
                problems.append('Nested byte-ring source/library mismatch: ' + path)
        for dependency in record.get('validator_dependencies', []) + record.get('native_libraries', []):
            if digest(ROOT / dependency['path']) != dependency['sha256']:
                problems.append('Composition dependency mismatch: ' + dependency['path'])
        if 'sim-controller-row-cycle-review' in path and record.get('counter_erratum', {}).get('targeted_exact_ADD_SI_wraps') != 2:
            problems.append('Exact original source-row wrap witnesses missing')
        scoped_evidence.append({'path': path, 'scope': record.get('limits')})
    mutable_path = ROOT / 'docs/recovery/evidence/td2ega-mutable-control-map-v3.json'
    mutable = json.loads(mutable_path.read_text())
    if mutable['result'] != 'pass' or mutable['script_sha256'] != digest(ROOT / 'tools/map_ega_mutable_flow_v3.py') or mutable['registered_union_entries'] != len(functions):
        problems.append('Mutable-state map identity/count failure')
    for state in mutable['states']:
        ledger_path = ROOT / state['ledger']
        ledger = json.loads(ledger_path.read_text())
        if digest(ledger_path) != state['ledger_sha256'] or digest(ROOT / ledger['image']) != state['image_sha256'] or ledger['overlap_byte_count'] != 0:
            problems.append('Mutable-state ledger/bytes drift: ' + state['name'])
    for filename, ranges in [('td2ega-context-mutator-readback-v2.json', 6), ('td2ega-context-startup-v2.json', 17)]:
        context = json.loads((ROOT / 'docs/recovery/evidence' / filename).read_text())
        if context['result'] != 'pass' or not context['image_bytes_unchanged'] or len(context['fixed_context_ranges']) != ranges:
            problems.append('Saved register context failure: ' + filename)
    readback = json.loads((ROOT / 'docs/recovery/evidence/td2ega-context-import-readback-v2.json').read_text())
    if readback['result'] != 'pass' or readback['mismatched_bytes'] != 0 or readback['image_bytes_checked'] != 130240 or readback['relocations_checked'] != 1652:
        problems.append('Canonical Ghidra v2 byte/relocation readback failure')
    whitespace_check = subprocess.run(['git', '-c', 'core.whitespace=cr-at-eol', 'diff', '--check'],
                                     cwd=ROOT, capture_output=True)
    if whitespace_check.returncode:
        problems.append('Git whitespace check failed (CRLF respected as exact evidence bytes)')
    private_checks = ["reference/dos/TD2EGA.EXE", "analysis/derived/td2ega-v1/TD2EGA.unpacked.exe",
                      "analysis/ghidra-projects/TD2EGA.gpr", "analysis/build/byte-ring-repro/td2ega_byte_ring.dll",
                      "analysis/external/msdos-2d04cacc/SYSCALL.txt"]
    for private in private_checks:
        if subprocess.run(["git", "check-ignore", "--quiet", private], cwd=ROOT).returncode:
            problems.append("Private path not ignored: " + private)
    staged = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"], cwd=ROOT,
                            capture_output=True, check=True).stdout.decode().split("\0")
    for path in filter(None, staged):
        if not (path in ("README.md", ".gitignore", ".gitattributes") or
                path.startswith(("docs/", "src/", "tools/", "tests/"))):
            problems.append("Unexpected staged path: " + path)
        if Path(path).suffix.lower() in (".exe", ".dll", ".bin", ".lha", ".gpr"):
            problems.append("Payload staged: " + path)
    result = {"date": date.today().isoformat(), "scope": "Recovery evidence/custody/dependency audit; not a game runtime or fidelity test.",
              "result": "pass" if not problems else "fail", "problems": problems,
              "original_files": custody["file_count"], "original_hashes_unchanged": custody["result"] == "pass",
              "original_mtimes_attributes_unchanged": same_metadata,
              "task_counts": dict(Counter(t["status"] for t in by.values())),
              "active_requirements": len(requirements), "json_files_parsed": len(json_files),
              "local_links_checked": links, "function_records_validated": len(functions),
              "resource_records_validated": len(resources),
              "helper_checks": helper_checks,
              "scoped_static_or_synthetic_evidence": scoped_evidence,
              "git_whitespace_check": whitespace_check.returncode == 0,
              "mutable_code_states_verified": len(mutable['states']),
              "saved_near_return_mechanisms": mutable['additional_saved_near_return_mechanisms'],
              "differential_vectors": sum(h['vectors'] for h in helper_checks), "private_paths_ignored": private_checks,
              "native_summary": native_summary,
              "historical_api_reference_verified": api_reference_ok,
              "staged_file_count": len(list(filter(None, staged))), "audit_tool_sha256": digest(Path(__file__)),
              "separate_gates": {"phase0": "passed", "EGA_unpack": "passed", "C_helper": "compiled and differential-passed only",
                                 "complete_EGA_core": "pending", "DOS_game_session": "not exercised",
                                 "visual_audio_fidelity": "not established"}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
