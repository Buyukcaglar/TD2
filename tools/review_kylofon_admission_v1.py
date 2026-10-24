"""Read-only source/media admission inventory for the frozen Kylofon candidate.

Public evidence contains locators, hashes and classifications, never copied game
text, font pixels, initialized game-data bytes or extracted payloads. Output paths
must be fresh and outside reference. No compiler, decoder or game is executed.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "reference/repos/kylofon-test-drive-2-sdl3"
COMMIT = "352b56824d8c91e938b8f0794a71afca9a276193"
IMAGE = ROOT / "analysis/derived/td2ega-v1/TD2EGA.image.bin"
IMAGE_SHA = "8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lexical(source):
    """Mask comments/chars/strings without changing offsets; retain string tokens.

    This is lexical, not a C preprocessor. Every occurrence in every .c/.h is
    inventoried, including inactive preprocessor branches and quoted includes.
    Comments are deliberately excluded from compiled-string counts.
    """
    mask = list(source)
    strings = []
    i = 0
    while i < len(source):
        start = i
        if source.startswith("//", i):
            j = source.find("\n", i)
            i = len(source) if j < 0 else j
        elif source.startswith("/*", i):
            j = source.find("*/", i + 2)
            if j < 0:
                raise ValueError("Unterminated C comment")
            i = j + 2
        elif source[i] in "\"'":
            quote = source[i]
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("Unterminated C literal")
            if quote == '"':
                strings.append((start, i, source[start:i]))
        else:
            i += 1
            continue
        for k in range(start, min(i, len(mask))):
            if mask[k] != "\n":
                mask[k] = " "
    return "".join(mask), strings


def line_at(source, offset):
    return source.count("\n", 0, offset) + 1


def decoded_literal(token):
    try:
        value = ast.literal_eval(token)
        return value.encode("latin1")
    except (ValueError, SyntaxError, UnicodeEncodeError):
        # Source-token coverage remains complete even for an unsupported escape.
        return None


def offsets_of(image, data):
    if data is None or len(data) < 4:
        return []
    results = []
    pos = image.find(data)
    while pos >= 0:
        results.append(pos)
        pos = image.find(data, pos + 1)
    return results


def string_classification(path, source, start, end, data, original_offsets):
    line = line_at(source, start)
    left = source[source.rfind("\n", 0, start) + 1:start]
    context = "\n".join(source.splitlines()[max(0, line - 2):line + 2])
    if re.match(r"\s*#\s*include\b", left):
        return "build_include_identifier", "Preprocessor header name; code dependency metadata", "permitted_code_metadata"
    if re.match(r"\s*#\s*(?:error|pragma)\b", left):
        return "build_diagnostic", "Compiler diagnostic/control metadata", "permitted_host_code"
    if path == "td2port/src/game/flow_stage.c" and 43 <= line <= 396:
        return "original_or_adapted_game_format", "Game result/score display format; original DS locators accompany source; must load externally", "blocked_for_distribution"
    if path == "td2port/src/game/flow_scores.c" and 110 <= line <= 148:
        return "original_or_adapted_game_format", "Score-screen format with original DS locators; must load externally", "blocked_for_distribution"
    if path == "td2port/src/game/flow_screens.c" and line == 446:
        return "original_or_adapted_game_format", "Scenery disk label rendered in game; exact original-image match establishes an external text source", "blocked_for_distribution"
    if path == "td2port/src/mem.c" and line == 179:
        return "original_runtime_message", "Recovered runtime diagnostic is game-image text; externalize or explicitly replace before distribution", "blocked_for_distribution"
    marker_call = re.search(r"\bmemcmp\([^;{}]*$", left) is not None and "set_err(" not in left
    if path == "td2port/src/mem.c" and (marker_call or "static const char msg" in left):
        return "external_image_identity_marker", "Marker used for loader/admission, not rendered artwork; replace English marker text with pinned identity admission where possible", "review_before_distribution"
    if data is None:
        return "candidate_unknown", "Literal decode unsupported; token hash/offset retained", "blocked_pending_classification"
    if data == b"" or re.fullmatch(rb"(?:%[-+ #0-9.*hljztL]*[A-Za-z%]|[ :/\\.,\r\n_-])*", data):
        return "format_or_path_syntax", "Formatting or path syntax only; no original prose", "permitted_algorithm_constant"
    if path == "td2port/src/host.c" and "digits_shift" in context:
        return "host_keyboard_map", "ASCII shift mapping for host keyboard adapter", "permitted_hardware_adapter"
    if path == "td2port/src/main.c" or path == "td2port/src/host.c":
        return "host_cli_diagnostic_or_identifier", "Host command, path, environment, title or diagnostic; independent host interface", "permitted_host_code"
    if original_offsets:
        return "original_image_matching_literal", "Literal exactly occurs in admitted image; role requires explicit review, not a rights inference", "review_before_distribution"
    if b"%" in data or b" " in data or b"\n" in data:
        return "host_diagnostic_or_format", "Diagnostic/adapter text; no exact original-image match of this token", "permitted_host_code"
    return "algorithm_or_resource_identifier", "File mode, extension, selector or algorithm token; no original media bytes established", "permitted_code_metadata"


def braced_end(mask, start):
    depth = 0
    for i in range(start, len(mask)):
        if mask[i] == "{":
            depth += 1
        elif mask[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError("Unbalanced initializer")


ARRAY_CLASSES = {
    "letter_scan": ("host_hardware_keymap", "XT scan codes mapped to host keys; hardware adapter table"),
    "digits_shift": ("host_hardware_keymap", "ASCII shifted digits; hardware adapter table"),
    "kp": ("host_hardware_keymap", "Host keypad mapping to XT scan code and ASCII"),
    "op_gcfunc": ("algorithm_hardware_constant", "Four EGA graphics-controller raster-operation selectors"),
    "op_flags": ("algorithm_control_constant", "Four blitter operation/control flags"),
    "mode0d_default_palette": ("standard_hardware_default", "BIOS EGA mode0D default palette; hardware default, not a game picture palette"),
    "preload": ("original_address_map", "Offsets of external EXE names, not copied names or graphics"),
    "stage_handles": ("original_address_map", "DS handle locations and release ordering; algorithm/control mapping"),
    "car_names": ("original_address_map", "DS pointers into external EXE string names"),
    "car_arcs": ("original_address_map", "DS handle locations, not archived asset bytes"),
    "codes": ("original_address_map", "DS offsets for selection records"),
    "scene_front_view": ("algorithm_and_original_address_map", "Front-view code constants and DS field offsets; no sprite/font/route payload"),
    "scene_mirror_view": ("algorithm_and_original_address_map", "Mirror-view code constants and DS field offsets; no sprite/font/route payload"),
    "dis4": ("original_address_map", "Offsets/phase mask locating external dissolve tables"),
    "dis8": ("original_address_map", "Offsets/phase mask locating external dissolve tables"),
    "dta": ("zero_initialized_scratch", "Local directory buffer initialized to zero"),
    "tab": ("zero_initialized_scratch", "Decoder lookup scratch, populated from external input"),
    "n": ("zero_initialized_scratch", "Local normalized shape-name scratch"),
    "msg": ("external_image_identity_marker", "Original EXEPACK marker; same token also appears in string inventory"),
    "mem": ("mutable_zero_initialized_state", "External EXE memory model; implicit zero initialization contains no original payload"),
    "table": ("mutable_zero_initialized_state", "Native function dispatch registrations; no original payload"),
    "frame": ("mutable_zero_initialized_state", "Host framebuffer; implicit zero state only"),
    "kbd_buf": ("mutable_zero_initialized_state", "Host keyboard queue; implicit zero state only"),
    "silence": ("mutable_zero_initialized_state", "Zero PCM lead-in; no original music/sample data"),
}


def inventories(image):
    strings, initializers, inputs = [], [], []
    for file in sorted((REF / "td2port/src").rglob("*")):
        if file.suffix not in (".c", ".h"):
            continue
        data = file.read_bytes()
        source = data.decode("utf-8")
        path = file.relative_to(REF).as_posix()
        mask, tokens = lexical(source)
        inputs.append({"path": path, "sha256": digest(data), "bytes": len(data), "lines": len(source.splitlines()), "string_tokens": len(tokens)})
        for start, end, token in tokens:
            value = decoded_literal(token)
            hits = offsets_of(image, value)
            classification, reason, decision = string_classification(path, source, start, end, value, hits)
            line = line_at(source, start)
            nearby = "\n".join(source.splitlines()[max(0, line - 1):line + 3])
            ds = re.findall(r"\bDS:\s*([0-9a-fA-F]{4})\b", nearby)
            strings.append({"path": path, "line": line, "end_line": line_at(source, end - 1), "source_character_offset": start,
                            "token_sha256": digest(token.encode()), "decoded_bytes": len(value) if value is not None else None,
                            "decoded_sha256": digest(value) if value is not None else None, "classification": classification,
                            "reason": reason, "distribution_decision": decision, "original_image_exact_match_offsets": hits,
                            "original_ds_comment_offsets": sorted(set(ds)), "private_build_evaluation": "allowed; not distribution acceptance"})
        # Named array initializers, including anonymous-struct keypad initializer.
        pattern = r"\b(?P<name>[A-Za-z_]\w*)\s*(?P<dims>(?:\[[^\]\n]*\]\s*)+)\s*="
        seen = set()
        for match in re.finditer(pattern, mask):
            start = match.end()
            while start < len(source) and source[start].isspace():
                start += 1
            if start < len(mask) and mask[start] == "{":
                end = braced_end(mask, start)
            else:
                token = next((t for t in tokens if t[0] >= start and not source[start:t[0]].strip()), None)
                if token is None:
                    continue
                end = token[1]
            seen.add(match.start("name"))
            name = match.group("name")
            cls, reason = ARRAY_CLASSES.get(name, ("candidate_unknown", "Initializer requires manual classification"))
            initializers.append({"path": path, "line": line_at(source, match.start()), "end_line": line_at(source, end),
                                 "name": name, "kind": "array_initializer", "initializer_sha256": digest(source[start:end].encode()),
                                 "classification": cls, "reason": reason,
                                 "distribution_decision": "blocked_pending_classification" if cls == "candidate_unknown" else "review_before_distribution" if cls == "external_image_identity_marker" else "permitted_code_or_zero_state"})
        # Global/const aggregate descriptors also carry resource-related offsets.
        for match in re.finditer(r"\b(?:static\s+)?const\s+\w+\s+(?P<name>\w+)\s*=\s*(?P<brace>\{)", mask):
            start = match.start("brace")
            end = braced_end(mask, start)
            name = match.group("name")
            cls, reason = ARRAY_CLASSES.get(name, ("candidate_unknown", "Aggregate requires manual classification"))
            initializers.append({"path": path, "line": line_at(source, match.start()), "end_line": line_at(source, end),
                                 "name": name, "kind": "constant_aggregate_initializer", "initializer_sha256": digest(source[start:end].encode()),
                                 "classification": cls, "reason": reason, "distribution_decision": "permitted_code_or_zero_state" if cls != "candidate_unknown" else "blocked_pending_classification"})
        # Complete known static/global arrays with only implicit zero initializers.
        for name in ("mem", "table", "frame", "kbd_buf", "silence"):
            for match in re.finditer(r"\b" + name + r"\s*(?:\[[^\]\n]+\]\s*)+;", mask):
                left = source[source.rfind("\n", 0, match.start()) + 1:match.start()]
                if "static" not in left and not (name == "mem" and re.fullmatch(r"\s*u8\s+", left)):
                    continue
                if name == "mem" and path.endswith("mem.h"):
                    continue  # extern declaration is not an initializer.
                if path not in ("td2port/src/mem.c", "td2port/src/codeptr.c", "td2port/src/host.c"):
                    continue
                cls, reason = ARRAY_CLASSES[name]
                initializers.append({"path": path, "line": line_at(source, match.start()), "end_line": line_at(source, match.end()),
                                     "name": name, "kind": "implicit_zero_static_storage", "initializer_sha256": None,
                                     "classification": cls, "reason": reason, "distribution_decision": "permitted_code_or_zero_state"})
    return inputs, strings, initializers


# Source locators are pinned to the upstream snapshot, never candidate line numbers.
# Original entries identify the relevant original bodies; none implies full body
# admission when our code_contract gate is pending.
DEVIATIONS = [
 ("KAD-01","platform/timer.c",207,216,["06c9:5d83","06c9:5d8d"],"Literal low-memory address normalized","fix_candidate", "Canonical helpers read0040:046C physical086C and preserve modulo16 subtraction. Host BIOS clock046C is separate; no units inferred."),
 ("KAD-02","mem.h",10,13,["13a8:03f8"],"Global DS/SS invariant assumed","restrict_test_domain", "No global historical SS=DS admission. Native sample adapters must declare DS=SS or use original bus helpers; alias/allwriter/lifetime obligations remain pending."),
 ("KAD-03","mem.h",17,37,[],"Unwrapped 21-bit linear storage and contiguous word access","fix_accessors_or_exclude", "Use20bit byte accessors in candidate. Direct lvalue macros still require in-range disjoint native domains until replaced; high physical aliases remain raw-oracle evidence."),
 ("KAD-04","mem.h",42,54,[],"Unaligned native typed lvalue access","restrict_test_domain", "Windows little-endian x64 private candidate builds may exercise bounded aligned spans; no second-host or portable-core admission. Replace typed overlays before portable import."),
 ("KAD-05","mem.h",82,90,[],"IDIV INT32_MIN/-1 evaluation before overflow check","fix_candidate", "Check both zero and signed-minimum-over-minus-one before C division; preserve original quotient-overflow terminal behavior."),
 ("KAD-06","platform/input.c",291,297,["06c9:6601"],"SS!=DS keyboard peek path removed","reject_general_raw_substitution", "Representative native DS=SS keyboard interface is a narrow profile. IndependentSS/raw FLAGS/frame fixture must continue to use our admitted original-byte oracle."),
 ("KAD-07","platform/res.c",1116,1135,[],"Synthetic zeroed near-stack allocator","restrict_test_domain", "No borrowed actualSS stack/frame equivalence. Require explicit disjoint near scratch and stable callbacks; exclude stack aliases/return-word mutation from native-value tests."),
 ("KAD-08","platform/res.c",302,331,["06c9:7866","06c9:7874"],"Original directory receives score/selection writes","fix_candidate_or_disable_io", "Separate writable profile root from original resource lookup. No candidate write may target reference; representative pure-memory tests disable host I/O."),
 ("KAD-09","mem.c",26,148,["13a8:03f8"],"Heuristic image admission and partial relocation bounds","fix_candidate_or_bypass_with_pinned_image", "P1-R03 loader must check admitted exact input/image/ordered relocations before execution. Representative tests may load pinned validated image directly, clearly bypassing unadmitted loader paths."),
 ("KAD-10","mem.c",158,168,["13a8:002e","06c9:424a","06c9:4275","06c9:42ad","06c9:1bf7"],"Protection passed-state forced","retain_declared_native_adaptation", "Private native evaluation may select passed mutable state, recorded separately from raw initial/prepared code forms. No recovery closure for removed protection/runtime branches."),
 ("KAD-11","game/flow.c",253,263,["0432:0000"],"Disk verification succeeds unconditionally","retain_declared_native_adaptation", "External-file native disk adapter only; original diskID/device/error paths remain original-function dispositions, not semantically ported bodies."),
 ("KAD-12","game/flow.c",581,584,[],"Install entry is no-op","retain_declared_native_adaptation", "Native installer/play-disk UI excluded from product requirements; preserve omitted original-function disposition and do not count it recovered."),
 ("KAD-13","game/flow_stage.c",518,529,["0267:16c1"],"ShortDAT zero-fill replaces heap-tail reads","reject_subsystem_pending_lifetime", "Do not import full stage loader or claim authentic zeros. Original fixed7774-byte reads and actual short-resource allocation/tail lifetime require consumer proof inP2."),
 ("KAD-14","game/scene_project.c",388,406,["06c9:088e"],"Zero/wrapped clamp LOOP normalized to empty","fix_selected_helper_or_exclude_domain", "Full raw zero-count executes65536 iterations per pass. Native bounded rendering may reject malformed domain explicitly; never replace our complete raw clamp contract with early return."),
 ("KAD-15","game/scene_draw.c",121,140,["06c9:0b0d","06c9:284f"],"Ground-span empty-return narrows LOOP domain","reject_subsystem_pending_bounds", "Projection/resource bounds must establish admitted positive span counts. Raw zero/full-cycle behavior remains a separate original-instruction contract."),
 ("KAD-16","game/scene_cockpit.c",207,210,["06c9:3c3a"],"Steering-marker CH forced zero","reject_subsystem_pending_register_proof", "Do not fabricate inheritedCH. Need blitter postcondition and actual caller/corpus bounds; cockpit import remains rejected until resolved."),
 ("KAD-17","game/scene_cockpit.c",251,260,["06c9:3cef"],"Instrument SI forced slotzero on branch","reject_subsystem_pending_register_proof", "Need incomingSI and actual car-field combinations; source assertion about shipped cars is not a corpus receipt."),
 ("KAD-18","game/sim.c",265,273,["06c9:4281","06c9:4441"],"Neutral inheritedCX/DX clutch tone omitted","reject_subsystem_pending_register_proof", "Preserve omission as known native audio difference. Candidate decode_controls is not admitted for neutral-clutch fidelity; test narrower independent simulation leaf instead."),
 ("KAD-19","game/sim_motion.c",436,439,["06c9:4c85"],"Billboard staleBP branch forced crash","reject_subsystem_pending_register_proof", "Retain actualBP for types>=50h or prove valid native domain; no crash/collision family admission from unrelated simulation sample."),
 ("KAD-20","game/sim_traffic.c",360,374,["06c9:5c30"],"Nearest-ahead inheritedDI seeded listbase","reject_subsystem_pending_register_proof", "Need original caller DI and zero/all-ahead/tie profiles. Preserve65536iteration zeroCX domain and raw register evidence."),
 ("KAD-21","game/sim_traffic.c",241,247,["06c9:595f"],"Pass-collision CX initialized from assumed count","reject_subsystem_pending_register_proof", "Need actual enteredCX and inactive-position caller sequence; no inferred native count admitted solely from source comment."),
 ("KAD-22","game/sim_ai.c",447,451,["06c9:56ed"],"Police out-of-table drive state replaced by braking","retain_bounded_safety_policy", "Native safety fallback may reject unsupported states; record changed behavior and keep original raw target-domain obligation open."),
 ("KAD-23","game/flow.h",22,22,["0432:0000"],"Catalogue cap30 differs from raw31","retain_bounded_safety_policy", "Candidate cap is host robustness, not original parity. User supplied12car corpus unaffected by inventory count, but full catalogue/overflow semantics stay pending."),
 ("KAD-24","game/flow_screens.c",237,317,[],"Showroom frame arrays enlarged/bounded","retain_bounded_safety_policy", "Only admitted in-range frame lists may be used; orderedSS labels/corpus coverage remainP2 and original memory-overwrite behavior is not inherited."),
 ("KAD-25","game/flow_scores.c",27,43,["0645:0000"],"Highscore bounded read ignores actual fread count","fix_candidate_before_io_admission", "Reject truncated records atomically before checksum/state commit; size cap alone is insufficient. No scoreI/O tests may touch original source directories."),
 ("KAD-26","game/flow.c",184,201,[],"CPU-speed dissolve effects timer-paced","retain_declared_native_adaptation", "Record host presentation pacing separately from original tick/gameplay/RNG semantics; no physical timing acceptance from deterministic sample."),
 ("KAD-27","game/scene.c",411,411,["06c9:1b2c"],"Host frame pacing and synchronous state sampling","retain_declared_native_adaptation", "Do not claim original interrupt interleavings. Candidate runner must expose deterministic tick order; no whole-runner gameplay admission inR03."),
 ("KAD-28","game/scene_cockpit.c",169,170,["06c9:3b95"],"UI gate delay depends on draw count","reject_subsystem_pending_schedule", "Preserve frame-count dependence unless justified original mapping; presentation speed settings do not establish timer fidelity."),
 ("KAD-29","platform/timer.c",275,305,["06c9:c692","06c9:c69c","06c9:c6b3","06c9:c6c5"],"Slow-clock wait policy differs around rollover","retain_declared_native_adaptation", "Compare original disjunctive high/low deadline rule separately from host-safe wait policy; record wrap and stalled-clock domains."),
 ("KAD-30","platform/sound.c",54,406,["06c9:6269"],"Tick-quantized PCM transport and voices adjacency","reject_audio_fidelity_admission", "Separate ordered PIT/gate/sequencer events fromPCM. VOICES heap adjacency and audible timbre require later source/allocation/corpus evidence, not copied song bytes."),
 ("KAD-31","platform/res.c",335,540,["06c9:6b02","06c9:6c6e","06c9:6b97","06c9:7c16"],"Decoder normalizations and malformed-state guards","restrict_test_domain", "Compare representative synthetic codec family under explicit positive/count/capacity inputs; full raw zero-lowword/65536 behavior and safe external parser are separate contracts."),
 ("KAD-32","platform/gfx.c",207,260,["06c9:b0fe"],"Descriptor bounds and terminal allocation assumptions","reject_constructor_admission", "Original wrapped arithmetic,height0 LOOP, allocator-beforecapacity ordering and fatalfallthrough require original caller evidence; no constructor import fromprimitive sample."),
 ("KAD-33","platform/gfx_blit.c",185,477,[],"Blit clipping/negative-size/descriptor domains narrowed","restrict_test_domain", "Representative EGA primitive uses admitted dimensions/planes/descriptor ownership; preserve untested latches, clipping,overlap and raw alias domains as open."),
 ("KAD-34","game/flow_stage.c",43,396,["0267:118b","0267:1224","0267:0039"],"Original result formats compiled intoC","block_distribution", "Private source/build evaluation only. Every classified game-format token must be externalized from admitted EXE or explicitly replaced; retainDSlocators and formatting proof."),
 ("KAD-35","game/flow_scores.c",139,144,["0645:0470"],"Original score formats compiled intoC","block_distribution", "Load/format externalEXE text before packaging; no source-license inference overrides no-original-media requirement."),
 ("KAD-36","game/flow_stage.c",246,321,["0267:0039"],"Signed32 product/shift chains require bounds","reject_unbounded_arithmetic_admission", "Use defined unsigned/widened operations or prove state bounds; no general signedoverflow portability claim fromMSVC compilation."),
 ("KAD-37","platform/input.c",81,150,["06c9:6907","06c9:69b7"],"DeviceEOI/ack and realinterrupt delivery adapted","retain_declared_native_adaptation", "Pure-memory key translation/handler tests do not prove realIRQ nesting,allwriters,device timing or callback lifetime."),
 ("KAD-38","game/flow_screens.c",444,447,[],"Original scenery disk label compiled intoC","block_distribution", "Load original matching EXE text rather than copying the literal into a distributable. Exact image occurrence is recorded in the literal inventory."),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/recovery/evidence/kylofon-source-admission-v1.json")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to((ROOT / "reference").resolve()):
        raise ValueError("Choose fresh output outside reference")
    image = IMAGE.read_bytes()
    if digest(image) != IMAGE_SHA:
        raise ValueError("Original image identity mismatch")
    snapshot = json.loads((ROOT / "docs/planning/evidence/kylofon-reference-snapshot-v1.json").read_bytes())
    if snapshot["commit"] != COMMIT:
        raise ValueError("Upstream snapshot identity mismatch")
    for row in snapshot["tracked_files"]:
        if digest((REF / row["path"]).read_bytes()) != row["sha256"]:
            raise ValueError("Frozen source changed: " + row["path"])
    registry_path = ROOT / "docs/recovery/functions.json"
    registry = json.loads(registry_path.read_bytes())["records"]
    def original_locator(address):
        seg, off = (int(x, 16) for x in address.split(":"))
        at = seg * 16 + off
        owner = next((row for row in registry if any(e["segment"] == seg and e["segment_offset"] == off for e in row["entries"])), None)
        return {"address": address, "image_offset": at, "image_sha256": IMAGE_SHA,
                "function_id": owner["id"] if owner else None,
                "original_record_ranges": owner["ranges"] if owner else [],
                "code_contract_status": owner["gates"].get("code_contract", {}).get("status") if owner else "not_registered_exact_entry",
                "qualification": "Relevant original body/entry locator, not acceptance of every upstream statement about that body"}
    deviations = []
    for ident, path, start, end, originals, title, treatment, decision in DEVIATIONS:
        fullpath = "td2port/src/" + path
        source = (REF / fullpath).read_bytes()
        lines = source.decode().splitlines()
        if not 1 <= start <= end <= len(lines):
            raise ValueError("Bad source lines: " + ident)
        deviations.append({"id": ident, "title": title, "source": {"path": fullpath, "start_line": start, "end_line": end,
                           "file_sha256": digest(source), "selected_lines_sha256": digest("\n".join(lines[start-1:end]).encode())},
                           "original_locators": [original_locator(x) for x in originals], "selected_treatment": treatment,
                           "admission_decision": decision, "status": "source_admission_disposition_not_general_runtime_acceptance"})
    inputs, strings, arrays = inventories(image)
    result = {"schema": 1, "date": "2026-10-22", "upstream_commit": COMMIT, "scope": "Complete compiled C/H literal/initializer inventory and source-deviation admission decisions; no runtime/parity/packaging acceptance",
              "method": {"strings": "Lexically scan all .c/.h including inactive preprocessing branches; exclude comments/chars; include quoted header names; tokens individually inventoried even if adjacent",
                         "arrays": "All named array explicit initializers, constant aggregate descriptors and known implicit-zero static/global storage arrays. Static/global fields without initializer are type layout, not copied resources.",
                         "original_matching": "Find each decodable Latin1 literal of at least4bytes anywhere in independently admitted unrelocated image. Exact occurrence is an address clue, not semantic/provenance proof.",
                         "public_payload_policy": "No literal text or initialized data copied into evidence; source/image hashes and locators only"},
              "maker": {"path": Path(__file__).relative_to(ROOT).as_posix(), "sha256": digest(Path(__file__).read_bytes())},
              "original_image": {"path": IMAGE.relative_to(ROOT).as_posix(), "sha256": IMAGE_SHA, "bytes": len(image)},
              "function_registry_sha256": digest(registry_path.read_bytes()),
              "candidate_build_admission": "Allowed only in private separate writable workspace with MIT notice, exact source provenance, pinned dependency/compiler and declared sample domains. Not a distributable or whole-core admission.",
              "candidate_distribution_admission": "REJECTED: original/adapted result and runtime text, identity-marker review, unresolved behavior/caller contracts, missing complete resource and package checks. No resource payload may be published.",
              "representative_native_domain": {"state": "Fixed relocatedDGROUP, supported scalar/data inputs selected independently from original code; explicit source-image and relocation state",
                  "memory": "Stable owned memory, declared nonoverlapping code/state/scratch. Sample accessors may wrap20bits; directDS lvalues remain host little-endian assumptions unless separately repaired.",
                  "stack": "DS=SS only where sample declares it; C value calls do not model original stack byte writes, changed return words or arbitrary aliasing. Raw bus evidence remains authoritative.",
                  "timing": "Serialized deterministic calls, no real device/IRQ/nesting, audio/render transport or physical timing claim",
                  "comparison": "Compare only explicit observable memory/state/output/ports from the chosen original byte routine; register/FLAGS/return cleanup not exported by candidate remain excluded",
                  "exclusions": ["whole-main/state-machine", "allwriters/reset/lifetime", "arbitraryDS!=SS", "liveSSalias/changedreturntargets", "unboundedmalformedresourceinputs", "cockpitCH/SI", "neutralclutchCX/DX", "billboardBP", "trafficDI/CX", "shortDATtail", "descriptorconstructor", "fullCGA/Amiga/media switching", "gameplay/pixels/audio/fidelity"]},
              "source_files": inputs, "deviations": deviations, "string_literals": strings, "array_and_aggregate_initializers": arrays,
              "additional_private_reference_media": [{"path": "port/spec/platform.md", "lines": [1280,1297], "classification": "original_font_hex", "distribution_decision": "blocked_for_distribution", "scope": "Reference documentation; not a C initializer or a second copy in public evidence"}],
              "counts": {"source_files": len(inputs), "deviation_sites": len(deviations), "string_tokens": len(strings), "initializer_records": len(arrays),
                         "string_classes": dict(Counter(s["classification"] for s in strings)), "initializer_classes": dict(Counter(x["classification"] for x in arrays)),
                         "strings_blocked_for_distribution": sum(s["distribution_decision"].startswith("blocked") for s in strings),
                         "strings_needing_review": sum(s["distribution_decision"] == "review_before_distribution" for s in strings),
                         "unknown_initializer_records": sum(s["classification"] == "candidate_unknown" for s in arrays)}}
    if result["counts"]["unknown_initializer_records"]:
        raise ValueError("Unclassified initializer; inspect inventory before output")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(json.dumps(result["counts"], indent=2))


if __name__ == "__main__":
    main()
