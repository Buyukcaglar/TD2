"""Read-only R04 custody, selection, origin and planning verification.

This checker reads preserved evidence. It never runs an old maker, compiler,
candidate, original executable, emulator or differential fixture. Its only write
is a required, fresh JSON receipt below docs/recovery/evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from verify_reference import DEFAULT_MANIFEST, verify


ROOT = Path(__file__).resolve().parents[1]
EP = ROOT / 'docs/recovery/evidence'
CLONE = ROOT / 'reference/repos/kylofon-test-drive-2-sdl3'
CANDIDATE = ROOT / 'analysis/candidates/kylofon-r03-v1/candidate'
BASELINE = ROOT / 'analysis/candidates/kylofon-r03-v1/baseline'
COMMIT = '352b56824d8c91e938b8f0794a71afca9a276193'
MUTABLE_DOCS = {
    'README.md', 'docs/planning/backlog.json', 'docs/recovery/progress.json',
    'docs/planning/continuation.md', 'docs/planning/roadmap.md',
    'docs/planning/architecture.md', 'docs/planning/validation.md',
    'docs/planning/risks-and-estimates.md', 'docs/planning/tooling-and-sources.md',
    'docs/recovery/README.md',
}
HISTORY = {
    'backlog': 'analysis/history/backlog-before-kylofon-r04-v1.json',
    'progress': 'analysis/history/progress-before-kylofon-r04-v1.json',
    'continuation': 'analysis/history/continuation-before-kylofon-r04-v1.md',
}
RECEIPTS = [
    'kylofon-address-admission-v1.json', 'kylofon-source-admission-v1.json',
    'kylofon-candidate-build-v1.json', 'kylofon-representative-validation-v1.json',
    'kylofon-admission-support-v2.json', 'kylofon-candidate-changes-v1.json',
    'kylofon-gap-dispositions-v2.json',
]
FAMILIES = {
    'byte_ring': 278, 'literal_reader': 27, 'literal_subtract': 243,
    'input_vector_set': 128, 'input_vector_get': 128, 'simulation_curve': 320,
    'simulation_drag': 162, 'simulation_rpm': 243, 'graphics_clip': 128,
    'graphics_ram_plot': 384, 'codec_run_stage': 192, 'excluded_ss_alias': 4,
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def equal_numbers(actual, expected, message):
    require(len(actual) == len(expected) and
            all(math.isclose(a, e, rel_tol=0, abs_tol=1e-8)
                for a, e in zip(actual, expected)), message)


def pair_sum(pairs):
    pairs = list(pairs)
    return [sum(pair[i] for pair in pairs) for i in range(2)]


class Pins:
    def __init__(self):
        self.hashes = {}
        self.span_count = 0

    def resolve(self, name):
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path
            if not path.is_file():
                path = CLONE / name
        require(path.is_file(), 'Missing pinned input: ' + str(path))
        return path.resolve()

    def digest(self, path):
        path = path.resolve()
        if path not in self.hashes:
            self.hashes[path] = sha(path)
        return self.hashes[path]

    def check(self, row):
        path = self.resolve(row['path'])
        require(self.digest(path) == row['sha256'], 'Pinned hash differs: ' + str(path))
        if 'bytes' in row:
            require(path.stat().st_size == row['bytes'], 'Pinned length differs: ' + str(path))

    def inspect(self, value):
        if isinstance(value, list):
            for item in value:
                self.inspect(item)
        elif isinstance(value, dict):
            if 'path' in value and 'sha256' in value:
                self.check(value)
            for item in value.values():
                self.inspect(item)

    def ranges(self, rows, inherited_path=None):
        for row in rows:
            path_name = row.get('path', inherited_path)
            require(path_name is not None, 'Source range has no path')
            path = self.resolve(path_name)
            if 'file_sha256' in row:
                require(self.digest(path) == row['file_sha256'], 'Range file hash differs')
            if 'selected_ranges' in row:
                self.ranges(row['selected_ranges'], path_name)
            else:
                start, end = row['start_line'], row['end_line']
                lines = path.read_bytes().splitlines(keepends=True)
                require(isinstance(start, int) and isinstance(end, int) and
                        1 <= start <= end <= len(lines), 'Invalid selected source lines')
                digest = hashlib.sha256(b''.join(lines[start - 1:end])).hexdigest()
                require(digest == row['span_sha256'], 'Selected source span differs: ' + str(path))
                self.span_count += 1


def verify_previous(pins):
    custody = verify(ROOT, DEFAULT_MANIFEST)
    original = read_json(EP / 'custody-baseline.json')
    require(custody['result'] == 'pass' and custody['file_count'] == 250 and
            custody['files'] == original['files'], 'Original custody/content/metadata differs')
    clones = custody['external_repositories']
    require(len(clones) == 1 and clones[0]['result'] == 'pass' and
            clones[0]['commit'] == COMMIT and clones[0]['file_count'] == 113,
            'Frozen clone custody differs')
    before = read_json(ROOT / 'docs/planning/evidence/kylofon-static-crosscheck-v1.json')
    require(sha(ROOT / 'docs/recovery/functions.json') == before['our_registry_sha256'],
            'Existing function registry changed')
    source_rows = before['our_recovered_source_files']
    require(len(source_rows) == 331, 'Recovered-source checkpoint count differs')
    for row in source_rows:
        pins.check(row)
    current_sources = {p.relative_to(ROOT).as_posix()
                       for p in (ROOT / 'src/recovered').rglob('*')
                       if p.is_file() and p.suffix in {'.c', '.h'}}
    require(current_sources == {r['path'] for r in source_rows},
            'Recovered C/header set changed')
    receipts = {name: read_json(EP / name) for name in RECEIPTS}
    for receipt in receipts.values():
        pins.inspect(receipt)
    diff = receipts['kylofon-representative-validation-v1.json']
    require(diff['result'] == 'pass' and diff['vectors'] == 2233 and
            diff['candidate_mismatches'] == {}, 'Representative result incomplete')
    require(diff['vectors_by_family'] == FAMILIES, 'Representative family scope differs')
    require(diff['excluded_ss_alias'] == {'mismatch': 4}, 'Excluded SS aliases lost')
    require(sum(v for k, v in diff['baseline_mismatches'].items()
                if k != 'excluded_ss_alias') == 291, 'Baseline discriminators lost')
    require(diff['original_instructions_executed'] == 116990 and
            diff['original_instruction_sites_exercised'] == 259, 'Original instruction scope differs')
    require(sha(ROOT / 'tools/validate_kylofon_representative_v1.py') == diff['validator_sha256'],
            'Original differential maker changed')
    require(sha(ROOT / diff['library']) == diff['library_sha256'],
            'Representative library changed')
    support = receipts['kylofon-admission-support-v2.json']
    build = receipts['kylofon-candidate-build-v1.json']
    require(support['result'] == build['result'] == 'pass' and
            support['support_cases'] == 380 and sum(support['case_counts'].values()) == 380,
            'Build/support result incomplete')
    require(support['baseline_library']['sha256'] == diff['baseline_library_sha256'],
            'Differential baseline library identity differs')
    changes = receipts['kylofon-candidate-changes-v1.json']['changes']
    require(len(changes) == 8, 'Candidate change count differs')
    for row in changes:
        require(sha(CANDIDATE / row['path']) == row['candidate_sha256'], 'Candidate changed')
        if row['baseline_sha256']:
            require(sha(BASELINE / row['path']) == row['baseline_sha256'], 'Baseline changed')
    snapshot = read_json(ROOT / 'docs/planning/evidence/kylofon-reference-snapshot-v1.json')
    require(snapshot['commit'] == COMMIT and len(snapshot['tracked_files']) == 85 and
            len(snapshot['repository_files']) == 113, 'Frozen snapshot identity differs')
    for row in snapshot['tracked_files']:
        require(sha(BASELINE / row['path']) == row['sha256'], 'Baseline not exact upstream')
    # The pre-R04 verifiers pinned both mutable planning documents and immutable
    # code/receipts. Only the enumerated planning documents may now differ.
    old_pin_count = 0
    for name in ['kylofon-r02-r03-verification-v1.json',
                 'kylofon-r04-baseline-verification-v1.json']:
        previous = read_json(EP / name)
        require(previous['result'] == 'pass', 'Prior verification was not a pass')
        for row in previous['artifacts']:
            if row['path'] not in MUTABLE_DOCS:
                pins.check(row)
                old_pin_count += 1
    return before, receipts, snapshot, old_pin_count


def verify_selection(pins, decision, origin, snapshot, tasks):
    pins.inspect(decision)
    pins.inspect(origin)
    require(decision['task'] == origin['task'] == 'P1-R04' and
            decision['upstream_commit'] == origin['upstream_commit'] == COMMIT,
            'Decision/origin identity differs')
    results = decision['results']
    require(results == {
        'original_entries_selected': 11, 'decision_groups': 10,
        'original_body_vectors': 2233, 'support_cases': 380,
        'excluded_ss_alias_disagreements': 4, 'baseline_admitted_disagreements': 291,
        'observed_corrected_semantic_classes': 2, 'newly_recovered_functions': 0,
        'primary_source_imports': 0, 'new_build_or_test_runs_this_task': 0,
    }, 'Selection result boundaries differ')
    groups = decision['selected']
    require([g['id'] for g in groups] == ['KRU-%02d' % i for i in range(1, 11)],
            'Selected group identities differ')
    require(Counter(g['decision'] for g in groups) == {
        'qualified_value_implementation': 6, 'qualified_support_adapter': 2,
        'qualified_windows_integration_candidate': 2}, 'Selection classes differ')
    registry = {r['id']: r for r in read_json(ROOT / 'docs/recovery/functions.json')['records']}
    tracked = {r['path']: r for r in snapshot['tracked_files']}
    entry_ids, value_families, source_groups = [], [], defaultdict(list)
    for group in groups:
        require(group['whole_file_copy_authorized'] is False and
                group['primary_source_import_performed'] is False and
                group['distribution_admitted'] is False, 'Source admission boundary broadened')
        for field in ['symbols_or_branches', 'native_domain', 'admitted_observations',
                      'excluded', 'independent_fallback',
                      'dependency_closure_status', 'selected_source_ranges']:
            require(bool(group[field]), 'Missing selection boundary: ' + group['id'] + '/' + field)
        require(isinstance(group['tested_transitive_dependencies_only'], list),
                'Missing enumerated transitive dependency field: ' + group['id'])
        require(all(t in tasks and tasks[t]['status'] != 'complete'
                    for t in group['implementation_tasks']), 'Reuse task is absent/already completed')
        require(not any(tasks[t]['phase'] in {4, 5} for t in group['implementation_tasks']),
                'Unsupported Amiga/switching reuse credit')
        source_groups[group['candidate_source']['path']].append(group['id'])
        pins.ranges(group['selected_source_ranges'])
        provenance = group['origin']
        row = tracked[provenance['upstream_path']]
        data = (CLONE / row['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        require(provenance['repository'] == 'https://github.com/kylofon/test-drive-2-sdl3' and
                provenance['commit'] == COMMIT and
                provenance['upstream_file_sha256'] == row['sha256'] == hashlib.sha256(data).hexdigest()
                and provenance['upstream_git_blob'] == row['git_blob'] == blob,
                'Selected upstream Git origin differs: ' + group['id'])
        require(provenance['local_changes'] == 'docs/recovery/evidence/kylofon-candidate-changes-v1.json',
                'Selection lost local modification receipt')
        if group['decision'] == 'qualified_value_implementation':
            value_families.extend(group['fixture_families'])
            require(group['original_entries'], 'Value selection has no existing entries')
        else:
            require(group['original_entries'] == [], 'Support adapter claimed original entry credit')
        for entry in group['original_entries']:
            identity = entry['existing_function_id']
            require(entry['newly_recovered_by_this_decision'] is False,
                    'Already recovered entry relabeled as new')
            record = registry[identity]
            require(record['gates']['code_contract']['status'] == 'passed',
                    'Selected existing entry lacked a passed bounded code contract')
            segment, offset = (int(x, 16) for x in entry['address'].split(':'))
            require(any(e.get('segment') == segment and e.get('segment_offset') == offset
                        for e in record['entries']), 'Existing original entry address differs')
            entry_ids.append(identity)
    require(len(entry_ids) == len(set(entry_ids)) == 11, 'Existing entry coverage differs')
    require(Counter(value_families) == Counter(k for k in FAMILIES if k != 'excluded_ss_alias') and
            sum(FAMILIES[f] for f in value_families) == 2233,
            'Selected value-family coverage does not equal admitted cases')
    require(len(origin['files']) == len(source_groups) == 8, 'Selected source manifest count differs')
    require({r['candidate']['path'] for r in origin['files']} == set(source_groups),
            'Origin manifest does not cover all selected sources')
    for row in origin['files']:
        require(row['selected_decision_ids'] == source_groups[row['candidate']['path']] and
                row['whole_file_copy_authorized'] is False and row['license_notice_required'] is True,
                'Origin file mapping/license boundary differs')
    license_info = origin['license']
    require(license_info['declared_license'] == 'MIT' and
            license_info['retain_notice_on_substantial_copy'] is True and
            license_info['original_game_media_rights_not_included'] is True and
            license_info['upstream_notice']['sha256'] == license_info['candidate_notice']['sha256'],
            'License/media-rights boundary differs')
    require(origin['distribution_admitted'] is False and
            origin['primary_source_import_performed'] is False, 'Manifest claims broader admission')
    require(any(r['candidate'].endswith('/host_paths.c') and
                r['origin'].endswith('/td2port/src/host.c') for r in origin['derived_origin_notes']),
            'Derived host-path provenance omitted')
    deferred = decision['deferred']
    require(len(deferred) == 5 and all(t in tasks for r in deferred for t in r['tasks']),
            'Deferred family task mapping differs')
    require(deferred[-1]['decision'] == 'no_implementation_credit',
            'CGA/Amiga/Northern Germany/switching received implementation credit')
    return entry_ids, source_groups


def verify_effort(pins, effort, decision, tasks):
    pins.inspect(effort)
    require(effort['units'] == {'hours_per_engineer_day': 8,
            'days_per_engineer_week': 5, 'hours_per_engineer_week': 40}, 'Effort units differ')
    require(all(effort['basis'].values()), 'Effort common-baseline/acceptance/judgment premise lost')
    packages = effort['work_packages']
    covered = [t for p in packages for t in p['tasks']]
    remaining = {t for t, r in tasks.items() if r['status'] != 'complete'}
    require(len(covered) == len(set(covered)) == len(remaining) == 54 and set(covered) == remaining,
            'Effort does not cover all 54 remaining tasks exactly once')
    phases = defaultdict(lambda: [0, 0])
    for package in packages:
        require(package['estimate_kind'] == 'engineering judgment' and
                0 < package['low_days'] <= package['high_days'], 'Unsupported effort measurement claim')
        require(all('P' + str(tasks[t]['phase']) == package['phase'] for t in package['tasks']),
                'Effort work package assigned to wrong phase')
        phases[package['phase']][0] += package['low_days']
        phases[package['phase']][1] += package['high_days']
    baseline = effort['route_I']
    require(dict(phases) == {p: [r['low_days'], r['high_days']]
                            for p, r in baseline['phase_days'].items()}, 'Phase effort arithmetic differs')
    equal_numbers(pair_sum(phases.values()), [205, 455], 'Independent route sum differs')
    equal_numbers(baseline['total_days'], [205, 455], 'Independent route total differs')
    equal_numbers(baseline['total_weeks'], [41, 91], 'Independent route weeks differ')
    current = effort['route_Q_current_qualified']
    equal_numbers(current['gross_implementation_credit_days'], [2, 5], 'Current gross credit differs')
    equal_numbers(pair_sum(r['days'] for r in current['extra_costs']), [3, 8], 'Current costs differ')
    equal_numbers(current['total_extra_overhead_days'], [3, 8], 'Current overhead total differs')
    gross, cost = current['gross_implementation_credit_days'], current['total_extra_overhead_days']
    net = [cost[0] - gross[1], cost[1] - gross[0]]
    equal_numbers(net, [-2, 6], 'Current net effort arithmetic differs')
    equal_numbers(current['net_effort_change_days'], net, 'Current net effort differs')
    total = [baseline['total_days'][i] + net[i] for i in range(2)]
    equal_numbers(current['outer_arithmetic_total_days'], total, 'Current total arithmetic differs')
    equal_numbers(total, [203, 461], 'Current total differs')
    equal_numbers(current['outer_arithmetic_total_weeks'], [v / 5 for v in total], 'Current weeks differ')
    require(current['midpoint_extra_days'] == 2 and current['booked_substantial_saving'] is False,
            'Current savings or midpoint claim differs')
    conditional = effort['route_Q_conditional_expansion']
    pairs = conditional['phase_pairs']
    require([r['phase'] for r in pairs] == ['P1', 'P2', 'P3', 'P4', 'P5'], 'Conditional phases differ')
    for row in pairs:
        equal_numbers(row['baseline_days'], phases[row['phase']], 'Conditional baseline differs')
        expected = [row['baseline_days'][i] - row['gross_credit_days'][i] +
                    row['extra_overhead_days'][i] for i in range(2)]
        equal_numbers(row['conditional_days'], expected, 'Conditional phase arithmetic differs')
        if row['phase'] in {'P4', 'P5'}:
            require(row['gross_credit_days'] == row['extra_overhead_days'] == [0, 0],
                    'Amiga/switching conditional credit booked')
    equal_numbers(pair_sum(r['gross_credit_days'] for r in pairs), [45, 95], 'Conditional gross sum differs')
    equal_numbers(pair_sum(r['extra_overhead_days'] for r in pairs), [25, 50], 'Conditional overhead sum differs')
    equal_numbers(pair_sum(r['conditional_days'] for r in pairs), [185, 410], 'Conditional phase sum differs')
    equal_numbers(conditional['matched_total_days'], [185, 410], 'Conditional total differs')
    equal_numbers(conditional['matched_total_weeks'], [37, 82], 'Conditional weeks differ')
    savings = [baseline['total_days'][i] - conditional['matched_total_days'][i] for i in range(2)]
    equal_numbers(conditional['matched_saving_days'], savings, 'Conditional savings arithmetic differs')
    equal_numbers(conditional['matched_saving_weeks'], [4, 9], 'Conditional matched savings differ')
    reserve = effort['reserve']
    equal_numbers(reserve['fraction'], [.25, .40], 'Reserve fraction differs')
    reserved = [total[i] * (1 + reserve['fraction'][i]) for i in range(2)]
    equal_numbers(reserve['qualified_current_exact_total_days_with_reserve'], reserved, 'Reserve days differ')
    equal_numbers(reserve['qualified_current_exact_total_weeks_with_reserve'], [v / 5 for v in reserved],
                  'Reserve weeks differ')
    model = decision['effort']
    for field, expected in {
        'current_qualified_route_days': [203, 461], 'current_qualified_route_weeks': [40.6, 92.2],
        'independent_reference_aided_route_days': [205, 455],
        'current_reuse_gross_credit_days': [2, 5], 'current_extra_adoption_cost_days': [3, 8],
        'current_net_effort_change_days': [-2, 6], 'conditional_expansion_weeks': [37, 82],
        'conditional_matched_savings_weeks': [4, 9],
    }.items():
        equal_numbers(model[field], expected, 'Decision effort differs: ' + field)
    require(model['engineering_judgment_not_machine_measured_throughput'] is True and
            model['substantial_current_saving_booked'] is False and
            model['midpoint_current_net_effort_change_days'] == 2,
            'Decision claims measured throughput or substantial current saving')


def verify_plan(before, backlog, progress, decision):
    old = read_json(ROOT / HISTORY['backlog'])
    old_progress = read_json(ROOT / HISTORY['progress'])
    old_tasks = {t['id']: t for t in old['tasks']}
    tasks = {t['id']: t for t in backlog['tasks']}
    require(len(tasks) == len(old_tasks) == 67 and
            [t['id'] for t in backlog['tasks']] == [t['id'] for t in old['tasks']],
            'Task inventory/order changed')
    require(backlog['phase_order'] == old['phase_order'], 'Required phase order changed')
    for key in set(old) | set(backlog):
        if key not in {'tasks', 'external_reference_review'}:
            require(old.get(key) == backlog.get(key), 'Other backlog authority changed: ' + key)
    status_changes = {t: [old_tasks[t]['status'], tasks[t]['status']]
                      for t in tasks if old_tasks[t]['status'] != tasks[t]['status']}
    require(status_changes == {'P1-R04': ['pending', 'complete']}, 'Other task status changed')
    metadata = {'qualified_reuse_units', 'reuse_selection', 'reuse_integration_condition'}
    r04_completion = {'title', 'acceptance', 'deliverables', 'status', 'evidence',
                      'reference_review', 'completed_on', 'completion_scope'}
    group_by_task = defaultdict(list)
    for group in decision['selected']:
        for task in group['implementation_tasks']:
            group_by_task[task].append(group['id'])
    for identity, task in tasks.items():
        allowed = r04_completion if identity == 'P1-R04' else metadata
        for key in set(old_tasks[identity]) | set(task):
            if key not in allowed:
                require(old_tasks[identity].get(key) == task.get(key),
                        'Existing task obligation changed: ' + identity + '/' + key)
        if identity in group_by_task:
            require(task.get('qualified_reuse_units') == group_by_task[identity] and
                    task.get('reuse_selection') == 'docs/recovery/evidence/kylofon-reuse-decisions-v2.json'
                    and bool(task.get('reuse_integration_condition')), 'Task selection linkage differs')
        elif identity != 'P1-R04':
            require(all(task.get(k) == old_tasks[identity].get(k) for k in metadata),
                    'Unselected task gained reuse metadata')
    counts = dict(Counter(t['status'] for t in tasks.values()))
    require(counts == {'complete': 13, 'in_progress': 1, 'pending': 53} and
            progress['task_counts'] == counts, 'Plan task counts differ')
    for key in set(old_progress) | set(progress):
        if key not in {'task_counts', 'external_reference_review'}:
            require(old_progress.get(key) == progress.get(key), 'Accepted progress changed: ' + key)
    require(tasks['P1-05']['status'] == 'in_progress' and tasks['P1-GATE']['status'] == 'pending',
            'Whole-core task or gate changed')
    previous_continuation = (ROOT / HISTORY['continuation']).read_bytes()
    continuation = (ROOT / 'docs/planning/continuation.md').read_bytes()
    require(len(continuation) > len(previous_continuation) and continuation.endswith(previous_continuation),
            'Previous continuation was not preserved as an exact byte suffix')
    for kind, history in [('backlog.json', HISTORY['backlog']),
                          ('progress.json', HISTORY['progress']),
                          ('continuation.md', HISTORY['continuation'])]:
        old_pin = next(r for r in read_json(EP / 'kylofon-r04-baseline-verification-v1.json')['artifacts']
                       if r['path'].endswith('/' + kind))
        require(sha(ROOT / history) == old_pin['sha256'] and
                (ROOT / history).stat().st_size == old_pin['bytes'], 'Pre-R04 history is not byte-exact')
    audit = read_json(EP / 'p1-kylofon-r04-audit-v1.json')
    require(audit['result'] == 'pass' and audit['problems'] == [] and
            audit['task_counts'] == counts and audit['staged_file_count'] == 0,
            'Full R04 evidence audit failed')
    require(audit['native_summary'] == before['accepted_checkpoint']['native_summary'],
            'Accepted native summary changed')
    require(audit['original_files'] == 250 and audit['original_hashes_unchanged'] is True and
            audit['original_mtimes_attributes_unchanged'] is True, 'Full audit custody differs')
    require(audit['function_records_validated'] == 440 and audit['resource_records_validated'] == 305,
            'Recovery inventory counts changed')
    return tasks, audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output.resolve()
    require(output.is_relative_to(EP) and output.parent.is_dir() and not output.exists(),
            'Required output must be fresh and below recovery evidence')
    pins = Pins()
    before, receipts, snapshot, old_pin_count = verify_previous(pins)
    decision_path = EP / 'kylofon-reuse-decisions-v2.json'
    origin_path = EP / 'kylofon-reuse-origin-manifest-v2.json'
    decision, origin = read_json(decision_path), read_json(origin_path)
    backlog = read_json(ROOT / 'docs/planning/backlog.json')
    progress = read_json(ROOT / 'docs/recovery/progress.json')
    tasks, audit = verify_plan(before, backlog, progress, decision)
    entries, source_groups = verify_selection(pins, decision, origin, snapshot, tasks)
    verify_effort(pins, read_json(ROOT / 'docs/planning/evidence/kylofon-effort-inputs-v1.json'),
                  decision, tasks)
    staged = subprocess.check_output(['git', 'diff', '--cached', '--name-only'],
                                     cwd=ROOT, text=True).splitlines()
    require(not staged, 'Unexpected staged files')
    whitespace = subprocess.run(['git', '-c', 'core.whitespace=cr-at-eol', 'diff', '--check'],
                                cwd=ROOT, capture_output=True, text=True)
    require(whitespace.returncode == 0, 'Whitespace failure: ' + whitespace.stdout + whitespace.stderr)
    for path in [receipts['kylofon-representative-validation-v1.json']['library'],
                 'analysis/candidates/kylofon-r03-v1/native-build-v1/candidate/td2r03_full.exe',
                 'reference/repos/kylofon-test-drive-2-sdl3/README.md']:
        require(subprocess.run(['git', 'check-ignore', '-q', path], cwd=ROOT).returncode == 0,
                'Private artifact not ignored: ' + path)
    artifact_names = set(MUTABLE_DOCS) | set(HISTORY.values()) | {
        'docs/planning/evidence/kylofon-reference-snapshot-v1.json',
        'docs/planning/evidence/kylofon-static-crosscheck-v1.json',
        'docs/planning/kylofon-reuse-assessment.md', 'docs/planning/kylofon-effort-review.md',
        'docs/planning/evidence/kylofon-effort-inputs-v1.json',
        'docs/recovery/kylofon-r04-reuse-decision.md',
        'docs/recovery/kylofon-reuse-selection-review.md',
        'docs/recovery/kylofon-r04-boundary-review.md',
        'docs/recovery/kylofon-r04-final-review.md',
        'docs/recovery/evidence/kylofon-reuse-decisions-v1.json',
        'docs/recovery/evidence/kylofon-reuse-decisions-v2.json',
        'docs/recovery/evidence/kylofon-reuse-origin-manifest-v1.json',
        'docs/recovery/evidence/kylofon-reuse-origin-manifest-v2.json',
        'docs/recovery/evidence/kylofon-reuse-selection-review-v1.json',
        'docs/recovery/evidence/kylofon-r04-baseline-verification-v1.json',
        'docs/recovery/evidence/p1-kylofon-r04-audit-v1.json',
        'tools/record_kylofon_reuse_decision_v1.py', 'tools/record_kylofon_reuse_decision_v2.py',
        'tools/record_kylofon_reuse_plan_v1.py', 'tools/verify_kylofon_reuse_decision_v1.py',
    }
    artifact_names.update('docs/recovery/evidence/' + name for name in RECEIPTS)
    # Include additional independently written R04 reviews if present at final
    # verification. This never recursively opens or executes their producers.
    artifact_names.update(p.relative_to(ROOT).as_posix()
                          for p in (ROOT / 'docs/recovery').glob('kylofon-r04-*.md'))
    require(output.relative_to(ROOT).as_posix() not in artifact_names, 'Output cannot pin itself')
    artifacts = []
    for name in sorted(artifact_names):
        path = ROOT / name
        require(path.is_file(), 'Missing final R04 artifact: ' + name)
        artifacts.append({'path': name, 'bytes': path.stat().st_size, 'sha256': sha(path)})
    result = {
        'schema': 1, 'date': '2026-10-22', 'result': 'pass', 'problems': [],
        'scope': 'Read-only custody/hash/origin/selection/estimate/planning checks; no accepted maker, '
                 'compiler, candidate, original or differential fixture rerun',
        'normative_decision': decision_path.relative_to(ROOT).as_posix(),
        'normative_origin_manifest': origin_path.relative_to(ROOT).as_posix(),
        'original_files_unchanged': 250, 'frozen_clone_files_unchanged': 113,
        'baseline_tracked_files_exact': 85, 'existing_recovered_source_headers_unchanged': 331,
        'function_registry_unchanged': True, 'old_artifact_pins_rechecked': old_pin_count,
        'current_nested_pinned_files_verified': len(pins.hashes),
        'selected_groups': 10, 'original_body_value_groups': 6, 'support_adapter_groups': 4,
        'already_passed_existing_entry_ids': entries, 'newly_recovered_functions': 0,
        'selected_source_files': len(source_groups), 'source_spans_verified': pins.span_count,
        'git_blob_origins_verified': 10, 'representative_vectors': 2233,
        'support_cases': 380, 'baseline_admitted_disagreements': 291,
        'excluded_ss_alias_witnesses': 4, 'primary_source_imports': 0,
        'remaining_tasks_estimated_once': 54,
        'independent_remaining_days': [205, 455], 'qualified_remaining_days': [203, 461],
        'qualified_net_effort_change_days': [-2, 6], 'conditional_remaining_days': [185, 410],
        'conditional_matched_saving_weeks': [4, 9], 'P4_P5_reuse_implementation_credit_days': 0,
        'effort_is_engineering_judgment_not_machine_throughput': True,
        'task_status_changes': {'P1-R04': ['pending', 'complete']},
        'task_counts': audit['task_counts'], 'native_summary_unchanged': audit['native_summary'],
        'prior_continuation_byte_suffix_unchanged': True, 'staged_files': 0,
        'artifacts': artifacts,
    }
    # Exclusive creation prevents replacing a consumed receipt, even if another
    # actor creates the requested path while the read-only verification runs.
    with output.open('xb') as stream:
        stream.write((json.dumps(result, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'result': 'pass', 'originals': 250, 'clone': 113,
                      'selected_groups': 10, 'existing_entries': 11,
                      'representative_vectors': 2233, 'support_cases': 380,
                      'remaining_tasks': 54, 'task_counts': audit['task_counts'],
                      'output': output.relative_to(ROOT).as_posix()}, indent=2))


if __name__ == '__main__':
    main()
