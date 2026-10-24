"""Validate native admission infrastructure, separate from original-body tests.

Loads only a private candidate DLL. Original EXE/image are read-only inputs;
copies, malformed samples, synthetic path fixtures and exact attempt archives
remain under analysis. No game session, original x86 execution or device runs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
PACKED = ROOT / "reference/dos/TD2EGA.EXE"
IMAGE = ROOT / "analysis/derived/td2ega-v1/TD2EGA.image.bin"
RELOCS = ROOT / "analysis/derived/td2ega-v1/relocations.json"
PACKED_SHA = "eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182"
IMAGE_SHA = "8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4"
MASK = (1 << 20) - 1


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def metadata(path):
    st = path.stat()
    return {"bytes": st.st_size, "sha256": sha(path.read_bytes()), "mtime_ns": st.st_mtime_ns,
            "file_attributes": getattr(st, "st_file_attributes", None)}


class Probe:
    def __init__(self, library, candidate):
        self.library = library
        self.dll = ctypes.CDLL(str(library))
        self.dll.td2r03_memory.argtypes = []
        self.dll.td2r03_memory.restype = ctypes.POINTER(ctypes.c_uint8)
        self.dll.td2r03_memory_size.argtypes = []
        self.dll.td2r03_memory_size.restype = ctypes.c_uint32
        self.dll.td2r03_call.argtypes = [ctypes.c_uint32] * 5
        self.dll.td2r03_call.restype = ctypes.c_uint32
        self.dll.td2r03_error.argtypes = []
        self.dll.td2r03_error.restype = ctypes.c_int
        self.dll.td2r03_error_message.argtypes = []
        self.dll.td2r03_error_message.restype = ctypes.c_char_p
        self.dll.td2r03_load.argtypes = [ctypes.c_char_p]
        self.dll.td2r03_load.restype = ctypes.c_int
        self.mem = self.dll.td2r03_memory()
        self.size = self.dll.td2r03_memory_size()
        require(self.size >= 1 << 20, "Probe has insufficient memory")
        if candidate:
            self.dll.td2r03_paths_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            self.dll.td2r03_paths_init.restype = ctypes.c_int
            self.dll.td2r03_path.argtypes = [ctypes.c_char_p, ctypes.c_int]
            self.dll.td2r03_path.restype = ctypes.c_void_p
            self.dll.td2r03_free_path.argtypes = [ctypes.c_void_p]
            self.dll.td2r03_free_path.restype = None
            self.dll.td2r03_paths_shutdown.argtypes = []
            self.dll.td2r03_paths_shutdown.restype = None
            self.dll.td2r03_write.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
            self.dll.td2r03_write.restype = ctypes.c_int

    def read(self):
        return ctypes.string_at(self.mem, self.size)

    def seed(self, data):
        require(len(data) == self.size, "Seed size differs")
        ctypes.memmove(self.mem, data, self.size)

    def call(self, entry, a=0, b=0, c=0, d=0):
        result = self.dll.td2r03_call(entry, a, b, c, d)
        return result, self.dll.td2r03_error()

    def path(self, name, create):
        encoded = name.encode("utf-8") if isinstance(name, str) else name
        address = self.dll.td2r03_path(encoded, int(create))
        if not address:
            return None
        try:
            return Path(ctypes.string_at(address).decode("utf-8")).resolve()
        finally:
            self.dll.td2r03_free_path(address)


def loader_checks(candidate, baseline, work, cases):
    packed = PACKED.read_bytes()
    image = IMAGE.read_bytes()
    require(sha(packed) == PACKED_SHA and sha(image) == IMAGE_SHA, "Unadmitted original input")
    relocations = json.loads(RELOCS.read_bytes())
    require(len(image) == 130240 and len(relocations) == 1652, "Original image/relocation count differs")
    canonical = work / "loader" / "canonical.exe"
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(packed)
    canonical.chmod(stat.S_IREAD)
    pre = metadata(canonical)
    unpatched = bytearray(image)
    for row in relocations:
        at = row["image_relative"]
        require(at == row["segment"] * 16 + row["offset"] and at + 2 <= len(unpatched), "Invalid admitted relocation")
        old = struct.unpack_from("<H", unpatched, at)[0]
        struct.pack_into("<H", unpatched, at, (old + 0x1000) & 65535)
    patched = bytearray(unpatched)
    patch_offsets = [0x6c90 + ip for ip in (0x424a, 0x4275, 0x42ad)]
    patch_value = patched[0x13a80 + 0x03d2]
    for at in patch_offsets:
        patched[at] = patch_value
    patched[0x6c90 + 0x1bf7] = 0xcb
    patched[0x178f0 + 0x5656] = 0
    changes = [i for i, (a, b) in enumerate(zip(unpatched, patched)) if a != b]
    require(len(changes) == 5, "Expected five deliberate passed-state byte changes")
    loader_results = []
    for label, probe in (("baseline", baseline), ("candidate", candidate)):
        result = probe.dll.td2r03_load(str(canonical).encode())
        expected = bytes(0x10000) + bytes(patched) + bytes(probe.size - 0x10000 - len(patched))
        actual = probe.read()
        require(result == 1 and actual == expected, label + " canonical EXE load differs from admitted image/relocations/passed-state edits")
        cases.append({"family": "loader_canonical", "implementation": label, "result": "pass"})
        loader_results.append({"implementation": label, "loaded_memory_sha256": sha(actual), "all_memory_bytes_compared": len(actual)})
    mutations = [("empty", b""), ("one_byte", packed[:1]), ("short_mz", packed[:27]),
                 ("header_only", packed[:512]), ("half", packed[:len(packed)//2]),
                 ("missing_last_byte", packed[:-1]), ("oversized", packed + bytes(65536))]
    for name, at in (("changed_header", 8), ("changed_packed_body", 0x1000), ("changed_tail", len(packed)-1)):
        changed = bytearray(packed)
        changed[at] ^= 1
        mutations.append((name, bytes(changed)))
    expected_after_load = candidate.read()
    for name, data in mutations:
        path = canonical.parent / (name + ".exe")
        path.write_bytes(data)
        require(candidate.dll.td2r03_load(str(path).encode()) == 0, "Candidate accepted unsupported EXE: " + name)
        require(candidate.read() == expected_after_load, "Rejected EXE changed loaded memory: " + name)
        require(bool(candidate.dll.td2r03_error_message()), "Missing loader rejection diagnostic: " + name)
        cases.append({"family": "loader_identity_rejection", "fixture": name, "bytes": len(data), "fixture_sha256": sha(data), "result": "pass"})
    require(metadata(canonical) == pre, "Canonical private read-only EXE copy was changed")
    return {"canonical_copy": canonical.relative_to(ROOT).as_posix(), "copy_metadata_unchanged": True,
            "input_sha256": PACKED_SHA, "image_sha256": IMAGE_SHA, "image_bytes": len(image),
            "relocation_count": len(relocations), "relocations_sha256": sha(RELOCS.read_bytes()),
            "relocated_unpatched_image_sha256": sha(unpatched), "passed_state_image_sha256": sha(patched),
            "intentional_patch_image_offsets": changes, "results": loader_results,
            "scope": "Exact input identity and resulting native memory are compared. Rejected malformed inputs stop at the exact-fingerprint gate; this does not exercise each deeper parser branch."}


def memory_checks(candidate, baseline, cases):
    patterns = {}
    for probe in (candidate, baseline):
        patterns[probe.size] = bytes(((i * 37) ^ (i >> 8) ^ ((i >> 16) * 23) ^ 97) & 255 for i in range(probe.size))
    addresses = [(seg, off) for seg in (0, 0x40, 0x1000, 0xefff, 0xf000, 0xffff)
                 for off in (0, 1, 0xf, 0x10, 0x11, 0xfff0, 0xfffe, 0xffff)]
    baseline_differences = Counter()
    candidate_cases = 0
    for seg, off in addresses:
        for width, entry in ((1, 0xd100), (2, 0xd101), (4, 0xd102)):
            for label, probe in (("baseline", baseline), ("candidate", candidate)):
                pattern = patterns[probe.size]
                probe.seed(pattern)
                expected = sum(pattern[((seg << 4) + off + k) & MASK] << (8*k) for k in range(width))
                result, error = probe.call(entry, seg, off)
                passed = error == 0 and result == expected and probe.read() == pattern
                if label == "candidate":
                    require(passed, f"Candidate scalar read mismatch {seg:04x}:{off:04x}/{width}")
                    candidate_cases += 1
                elif not passed:
                    baseline_differences["read" + str(width)] += 1
            cases.append({"family": "memory_scalar_read", "segment": seg, "offset": off, "width": width, "result": "pass"})
        for width, entry, value in ((2, 0xd103, 0xa53c), (4, 0xd104, 0x80fea53c)):
            for label, probe in (("baseline", baseline), ("candidate", candidate)):
                pattern = patterns[probe.size]
                probe.seed(pattern)
                expected = bytearray(pattern)
                for k in range(width):
                    expected[((seg << 4) + off + k) & MASK] = (value >> (8*k)) & 255
                _, error = probe.call(entry, seg, off, value)
                passed = error == 0 and probe.read() == bytes(expected)
                if label == "candidate":
                    require(passed, f"Candidate scalar write mismatch {seg:04x}:{off:04x}/{width}")
                    candidate_cases += 1
                elif not passed:
                    baseline_differences["write" + str(width)] += 1
            cases.append({"family": "memory_scalar_write", "segment": seg, "offset": off, "width": width, "result": "pass"})
    require(all(baseline_differences.get(k, 0) > 0 for k in ("read1", "read2", "read4", "write2", "write4")), "Memory corpus must discriminate every baseline scalar accessor family")
    return {"candidate_cases": candidate_cases, "baseline_expected_model_disagreements": dict(baseline_differences),
            "pattern": "Address mixed with bits8+ and16+; does not repeat across20bit wrap. Every scalar accessor family must have a baseline discriminator.",
            "model": "Independent Python byte-address model: every byte masks(segment*16+offset+byte_index,20bits). Full native memory compared after reads/writes.",
            "scope": "Infrastructure accessors, not original instruction bodies; direct typed DS lvalues remain outside this test."}


def division_checks(candidate, baseline, cases):
    dividends = (-2147483648, -65536, -32769, -32768, -1, 0, 1, 32767, 32768, 65535, 2147483647)
    divisors = (-32768, -2, -1, 0, 1, 2, 32767)
    faults, normal, skips = 0, 0, 0
    for dividend in dividends:
        for divisor in divisors:
            q = None if divisor == 0 else (abs(dividend) // abs(divisor)) * (-1 if (dividend < 0) != (divisor < 0) else 1)
            fault = divisor == 0 or q < -32768 or q > 32767
            for label, probe in (("baseline", baseline), ("candidate", candidate)):
                if label == "baseline" and dividend == -2147483648 and divisor == -1:
                    skips += 1
                    continue  # Original C expression has undefined signed overflow.
                result, error = probe.call(0xd105, dividend & 0xffffffff, divisor & 65535)
                require(bool(error) == fault, label + " division fault outcome differs")
                if not fault:
                    require(result == (q & 65535), label + " division quotient differs")
            faults += int(fault)
            normal += int(not fault)
            cases.append({"family": "division_guard", "dividend": dividend, "divisor": divisor,
                          "expected_fault": fault, "baseline_skipped_undefined_case": dividend == -2147483648 and divisor == -1,
                          "result": "pass"})
    return {"candidate_cases": faults + normal, "fault_cases": faults, "normal_cases": normal,
            "baseline_undefined_cases_deliberately_not_executed": skips,
            "scope": "Native division guard against an independent integer quotient/fault model; not an original x86-body comparison."}


def path_checks(candidate, work, cases):
    base = work / "paths"
    original = base / "original"
    profile = base / "profile"
    original.mkdir(parents=True)
    profile.mkdir()
    originals = {"RESOURCE.DAT": b"synthetic resource input", "SELECT.DAT": b"synthetic selection baseline"}
    for name, data in originals.items():
        path = original / name
        path.write_bytes(data)
        path.chmod(stat.S_IREAD)
    before = {name: metadata(original / name) for name in originals}
    init = candidate.dll.td2r03_paths_init
    require(init(str(original).encode(), str(profile).encode()) == 1, "Separate path roots rejected")
    cases.append({"family": "profile_init", "fixture": "disjoint_existing_roots", "result": "pass"})
    require(candidate.path("resource.dat", False) == (original / "RESOURCE.DAT").resolve(), "Read-only original fallback/case lookup differs")
    cases.append({"family": "profile_lookup", "fixture": "case_insensitive_original_fallback", "result": "pass"})
    require(candidate.path("missing.dat", False) is None, "Missing resource unexpectedly resolves")
    cases.append({"family": "profile_lookup", "fixture": "missing_read", "result": "pass"})
    require(candidate.path("select.dat", True) == (profile / "select.dat").resolve(), "Create targets originals")
    cases.append({"family": "profile_lookup", "fixture": "create_uses_profile", "result": "pass"})
    (profile / "SELECT.DAT").write_bytes(b"synthetic profile override")
    require(candidate.path("select.dat", False) == (profile / "SELECT.DAT").resolve(), "Profile override missing")
    cases.append({"family": "profile_lookup", "fixture": "existing_profile_override", "result": "pass"})
    require(candidate.path("select.dat", True) == (profile / "SELECT.DAT").resolve(), "Create misses existing case-folded profile file")
    cases.append({"family": "profile_lookup", "fixture": "existing_profile_create_case", "result": "pass"})
    for name in ("", ".", "..", "../escape.dat", "..\\escape.dat", "C:\\escape.dat", "sub/file.dat", "sub\\file.dat", "data:stream", ".. ", "NUL", "CON", "COM1", "bad?name", "bad*name", "name.", "name ", "bad\x01name"):
        for create in (False, True):
            require(candidate.path(name, create) is None, "Unsafe filename accepted: " + repr(name))
            cases.append({"family": "profile_name_rejection", "fixture_name_sha256": sha(name.encode()), "create": create, "result": "pass"})
    directory = profile / "directory.dat"
    directory.mkdir()
    for create in (False, True):
        require(candidate.path(directory.name, create) is None, "Directory accepted as file")
        cases.append({"family": "profile_name_rejection", "fixture": "directory_as_file", "create": create, "result": "pass"})
    link = profile / "linked.dat"
    os.link(original / "RESOURCE.DAT", link)
    require(candidate.path(link.name, True) is None, "Hardlinked profile target accepted for writing")
    cases.append({"family": "profile_hardlink_rejection", "fixture": "write_hardlink_to_original", "result": "pass"})
    payload = b"synthetic writable-profile payload\n"
    address = 0x50000
    ctypes.memmove(ctypes.addressof(candidate.mem.contents) + address, payload, len(payload))
    require(candidate.dll.td2r03_write(b"newscore.dat", 0x50000000, len(payload)) == 0, "Actual profile write failed")
    require((profile / "newscore.dat").read_bytes() == payload and not (original / "newscore.dat").exists(), "Write was not isolated to profile")
    cases.append({"family": "profile_actual_write", "fixture": "new_profile_file", "bytes": len(payload), "result": "pass"})
    link_before = metadata(link)
    quiet_result = candidate.dll.td2r03_write(b"linked.dat", 0x50000000, len(payload))
    require(metadata(link) == link_before, "Actual writer changed a hardlinked original")
    cases.append({"family": "profile_actual_write", "fixture": "hardlink_write_has_no_effect",
                  "quiet_api_return": quiet_result, "return_qualification": "Quiet original-style API returns0 on both success and error; denial established by path rejection and unchanged bytes/metadata", "result": "pass"})
    candidate.dll.td2r03_paths_shutdown()
    root_pairs = [(original, original), (original, original / "nested"), (original, base), (original / "missing", profile)]
    for o, p in root_pairs:
        require(init(str(o).encode(), str(p).encode()) == 0, "Unsafe/missing roots accepted")
        candidate.dll.td2r03_paths_shutdown()
        cases.append({"family": "profile_root_rejection", "original": o.relative_to(work).as_posix(), "profile": p.relative_to(work).as_posix(), "result": "pass"})
    require(before == {name: metadata(original / name) for name in originals}, "Synthetic original content/mtime/attributes changed")
    return {"fixture_root": base.relative_to(ROOT).as_posix(), "original_file_count": len(originals),
            "originals_content_mtime_attributes_unchanged": True,
            "source_inputs": "Synthetic file fixtures only; actual reference originals are never passed to candidate write/path APIs.",
            "scope": "Read/create resolution, explicit disjoint roots, basic Win32 filename rules and existing hardlink rejection. No adversarial concurrent filesystem race or complete final-host acceptance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    library, baseline, work, output = (x.resolve() for x in (args.library, args.baseline, args.work, args.output))
    require(library.is_relative_to(ROOT / "analysis") and baseline.is_relative_to(ROOT / "analysis"), "Only private probe libraries admitted")
    require(work.is_relative_to(ROOT / "analysis") and not work.exists(), "Choose fresh private attempt directory")
    require(output.is_relative_to(ROOT / "docs/recovery/evidence") and not output.exists(), "Choose fresh evidence output")
    work.mkdir(parents=True)
    maker = Path(__file__).read_bytes()
    (work / "executed-maker.py").write_bytes(maker)
    inputs_before = {p.relative_to(ROOT).as_posix(): metadata(p) for p in (PACKED, IMAGE, RELOCS)}
    started = time.monotonic()
    result = {"schema": 1, "date": "2026-10-22", "scope": "Native admission support checks; counts are not original-instruction differential vectors",
              "result": "fail", "problems": [], "maker": {"path": Path(__file__).relative_to(ROOT).as_posix(), "sha256": sha(maker)},
              "attempt_directory": work.relative_to(ROOT).as_posix(),
              "candidate_library": {"path": library.relative_to(ROOT).as_posix(), "sha256": sha(library.read_bytes())},
              "baseline_library": {"path": baseline.relative_to(ROOT).as_posix(), "sha256": sha(baseline.read_bytes())},
              "cases": []}
    build_path = ROOT / "docs/recovery/evidence/kylofon-candidate-build-v1.json"
    build = json.loads(build_path.read_bytes())
    require(build.get("result") == "pass", "Final candidate build receipt must pass")
    result["build_receipt"] = {"path": build_path.relative_to(ROOT).as_posix(), "sha256": sha(build_path.read_bytes())}
    result["prior_attempt"] = {"path": "docs/recovery/evidence/kylofon-admission-support-v1.json",
                               "qualification": "Preserved initial support pass used a64Kperiodicpattern; fullRAMwritecases discriminated wrapping but boundaryreads did not. This refinement requires independent highaddress pattern and baseline discriminators for allfive scalar accessor families."}
    try:
        candidate, original = Probe(library, True), Probe(baseline, False)
        result["loader"] = loader_checks(candidate, original, work, result["cases"])
        result["memory"] = memory_checks(candidate, original, result["cases"])
        result["division"] = division_checks(candidate, original, result["cases"])
        result["paths"] = path_checks(candidate, work, result["cases"])
        require(inputs_before == {p.relative_to(ROOT).as_posix(): metadata(p) for p in (PACKED, IMAGE, RELOCS)}, "Original/derived input metadata changed")
        require(result["candidate_library"]["sha256"] == sha(library.read_bytes()), "Candidate changed during support validation")
        result["inputs_unchanged"] = True
        result["result"] = "pass"
    except Exception as error:
        result["problems"].append(str(error))
        (work / "failure.txt").write_bytes(traceback.format_exc().encode())
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    result["case_counts"] = dict(Counter(c["family"] for c in result["cases"]))
    result["support_cases"] = len(result["cases"])
    output.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({k: result[k] for k in ("result", "problems", "case_counts", "support_cases", "elapsed_seconds")}, indent=2))
    return 0 if result["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
