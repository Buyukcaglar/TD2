"""Read-only reference custody checks against an immutable path/hash manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs/planning/evidence/reference-manifest.json"


def verify(root: Path, manifest_path: Path) -> dict:
    root = root.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = []
    problems = []
    expected_paths = set()
    reference = (root / "reference").resolve()
    for expected in manifest["files"]:
        relative = expected["path"]
        path = (root / relative).resolve()
        if not path.is_relative_to(reference):
            raise ValueError(f"Manifest path escapes reference: {relative}")
        if relative in expected_paths:
            raise ValueError(f"Duplicate manifest path: {relative}")
        expected_paths.add(relative)
        if not path.is_file():
            problems.append({"path": relative, "problem": "missing"})
            continue
        before = path.stat()
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = path.stat()
        actual = {
            "path": relative,
            "bytes": after.st_size,
            "sha256": digest,
            "mtime_ns": after.st_mtime_ns,
            "file_attributes": getattr(after, "st_file_attributes", None),
        }
        rows.append(actual)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            problems.append({"path": relative, "problem": "changed during read"})
        if after.st_size != expected["bytes"] or digest != expected["sha256"]:
            problems.append({"path": relative, "problem": "size/hash differs"})
    actual_paths = {
        p.relative_to(root).as_posix()
        for p in reference.rglob("*") if p.is_file()
    }
    for relative in sorted(actual_paths - expected_paths):
        problems.append({"path": relative, "problem": "not in baseline"})
    return {
        "schema": 1,
        "reference_manifest": manifest_path.relative_to(root).as_posix(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "result": "pass" if not problems else "fail",
        "file_count": len(rows),
        "total_bytes": sum(row["bytes"] for row in rows),
        "problems": problems,
        "files": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path,
                        help="Also compare mtime and file attributes to a prior check")
    args = parser.parse_args()
    result = verify(ROOT, args.manifest.resolve())
    if args.compare:
        previous = json.loads(args.compare.read_text(encoding="utf-8"))
        prior = {row["path"]: row for row in previous["files"]}
        for row in result["files"]:
            if row != prior.get(row["path"]):
                result["problems"].append({"path": row["path"],
                                           "problem": "metadata/hash differs from session baseline"})
        if result["problems"]:
            result["result"] = "fail"
    if args.output:
        output = args.output.resolve()
        if output.is_relative_to((ROOT / "reference").resolve()):
            raise ValueError("Refusing to write an audit into reference")
        if output.exists():
            raise FileExistsError(f"Audit already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "files"}, indent=2))
    return 0 if result["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
