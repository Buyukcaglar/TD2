"""Read-only reference custody checks against an immutable path/hash manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs/planning/evidence/reference-manifest.json"
EXTERNAL_REGISTRY = Path("docs/planning/evidence/external-repositories.json")


def verify_external_repositories(root: Path) -> tuple[set[str], list[dict], list[dict]]:
    """Admit exact frozen clone files, never an unverified directory exclusion.

    Original media remain in their original manifest. External source clones have
    separate inventories, including Git administration files. Unknown files still
    fail the enclosing reference check, and a missing or changed clone fails here.
    """
    registry_path = root / EXTERNAL_REGISTRY
    if not registry_path.exists():
        return set(), [], []
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    if registry.get("schema") != 1:
        raise ValueError("Unsupported external repository registry")
    allowed, results, problems = set(), [], []
    roots = []
    reference_repos = (root / "reference/repos").resolve()
    evidence = (root / "docs/planning/evidence").resolve()
    for entry in registry["repositories"]:
        repo = (root / entry["path"]).resolve()
        manifest_path = (root / entry["snapshot_manifest"]).resolve()
        if repo == reference_repos or not repo.is_relative_to(reference_repos):
            raise ValueError("External clone must be a child of reference/repos")
        if any(repo.is_relative_to(p) or p.is_relative_to(repo) for p in roots):
            raise ValueError("Overlapping external repository roots")
        roots.append(repo)
        if not manifest_path.is_relative_to(evidence):
            raise ValueError("External snapshot must stay in planning evidence")
        snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
        if snapshot.get("repository_path") != entry["path"] or snapshot.get("commit") != entry["commit"]:
            raise ValueError("External snapshot identity mismatch")
        start = len(problems)
        for row in snapshot["repository_files"]:
            path = (repo / row["path"]).resolve()
            if not path.is_relative_to(repo) or path == repo:
                raise ValueError("External snapshot file escapes clone")
            relative = path.relative_to(root).as_posix()
            if relative in allowed:
                raise ValueError("Duplicate external snapshot file")
            allowed.add(relative)
            if not path.is_file():
                problems.append({"path": relative, "problem": "external reference missing"})
                continue
            before = path.stat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                problems.append({"path": relative, "problem": "external reference changed during read"})
            actual = (after.st_size, digest, after.st_mtime_ns, getattr(after, "st_file_attributes", None))
            expected = (row["bytes"], row["sha256"], row["mtime_ns"], row["file_attributes"])
            if actual != expected:
                problems.append({"path": relative, "problem": "external reference content/metadata differs"})
            if hasattr(after, "st_file_attributes") and not after.st_file_attributes & 1:
                problems.append({"path": relative, "problem": "external reference is not read only"})
        if not snapshot["repository_files"]:
            raise ValueError("Empty external snapshot")
        results.append({"path": entry["path"], "commit": entry["commit"],
                        "file_count": len(snapshot["repository_files"]),
                        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        "result": "pass" if len(problems) == start else "fail"})
    return allowed, results, problems


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
    external_paths, external_results, external_problems = verify_external_repositories(root)
    if expected_paths & external_paths:
        raise ValueError("External clone overlaps original media manifest")
    problems.extend(external_problems)
    actual_paths = {
        p.relative_to(root).as_posix()
        for p in reference.rglob("*") if p.is_file()
    }
    for relative in sorted(actual_paths - expected_paths - external_paths):
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
        "external_repositories": external_results,
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
