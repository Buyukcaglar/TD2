"""Audit recovery metadata, original custody, dependencies and public-file scope.

This does not rerun game, decoder, compiler or differential tests. It verifies
the persisted evidence and the expected private/public boundaries.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_reference import verify, DEFAULT_MANIFEST


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    build = json.loads((ROOT / "docs/recovery/evidence/td2ega-byte-ring-build.json").read_text())
    comparison = json.loads((ROOT / "docs/recovery/evidence/td2ega-byte-ring-validation.json").read_text())
    for item in build["sources"] + build["outputs"]:
        if digest(ROOT / item["path"]) != item["sha256"]:
            problems.append("Build artifact mismatch: " + item["path"])
    if comparison["source_sha256"] != digest(ROOT / "src/recovered/td2ega_byte_ring.c"):
        problems.append("Differential source identity mismatch")
    if comparison["validator_sha256"] != digest(ROOT / "tools/validate_byte_ring.py"):
        problems.append("Differential validator identity mismatch")
    if comparison["library_sha256"] != build["outputs"][1]["sha256"]:
        problems.append("Build/differential DLL identity mismatch")
    if comparison["result"] != "pass":
        problems.append("Differential result not passing")
    private_checks = ["reference/dos/TD2EGA.EXE", "analysis/derived/td2ega-v1/TD2EGA.unpacked.exe",
                      "analysis/ghidra-projects/TD2EGA.gpr", "analysis/build/byte-ring-repro/td2ega_byte_ring.dll"]
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
    result = {"date": "2026-10-13", "scope": "Recovery evidence/custody/dependency audit; not a game runtime or fidelity test.",
              "result": "pass" if not problems else "fail", "problems": problems,
              "original_files": custody["file_count"], "original_hashes_unchanged": custody["result"] == "pass",
              "original_mtimes_attributes_unchanged": same_metadata,
              "task_counts": dict(Counter(t["status"] for t in by.values())),
              "active_requirements": len(requirements), "json_files_parsed": len(json_files),
              "local_links_checked": links, "function_records_validated": len(functions),
              "differential_vectors": comparison["vectors"], "private_paths_ignored": private_checks,
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
