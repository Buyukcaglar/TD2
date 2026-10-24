"""Inventory the frozen upstream clone and compare metadata with our EGA work.

Read-only inspection: no unpacker, decoder, original code, compiler or game is
executed. Output paths must be fresh. Invoke after making the clone read only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = Path("reference/repos/kylofon-test-drive-2-sdl3")
COMMIT = "352b56824d8c91e938b8f0794a71afca9a276193"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(ROOT / REPO), *args],
                                   text=True, encoding="utf-8").strip()


def group(path):
    if path.startswith("td2port/src/game/") or path.startswith(("port/spec/game_flow", "port/spec/scene_render", "port/spec/simulation")):
        return "kylofon-game-core-review.md"
    if path.startswith("td2port/") or path in ("README.md", "LICENSE") or path.startswith("port/spec/platform"):
        return "kylofon-platform-review.md"
    return "kylofon-formats-tools-review.md"


def write_fresh(path, obj):
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def validate_output_paths(paths, root=ROOT):
    resolved = [path.resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ValueError("Choose distinct evidence outputs")
    for path in resolved:
        if path.is_relative_to((root / "reference").resolve()):
            raise ValueError("Refusing to write inspection evidence into reference")
        if path.exists():
            raise FileExistsError("Choose fresh evidence paths")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--crosscheck", type=Path, required=True)
    args = parser.parse_args()
    validate_output_paths([args.snapshot, args.crosscheck])
    if git("rev-parse", "HEAD") != COMMIT or git("status", "--porcelain"):
        raise ValueError("Expected a clean pinned clone")
    clone = ROOT / REPO
    tracked = []
    for line in git("ls-files", "-s").splitlines():
        metadata, path = line.split("\t", 1)
        mode, blob, stage = metadata.split()
        data = (clone / path).read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual_blob != blob or stage != "0":
            raise ValueError("Working tree differs from Git blob: " + path)
        tracked.append({"path": path, "bytes": len(data), "sha256": sha(data), "git_blob": blob,
                        "git_mode": mode, "lines": len(data.splitlines()), "review": "docs/planning/" + group(path)})
    files = []
    for path in sorted(clone.rglob("*")):
        if not path.is_file():
            continue
        stat = path.stat()
        attrs = getattr(stat, "st_file_attributes", None)
        if attrs is not None and not attrs & 1:
            raise ValueError("Clone file not read only: " + str(path))
        files.append({"path": path.relative_to(clone).as_posix(), "bytes": stat.st_size,
                      "sha256": sha(path.read_bytes()), "mtime_ns": stat.st_mtime_ns, "file_attributes": attrs})
    snapshot = {"schema": 1, "inspection_date": "2026-10-22", "repository_path": REPO.as_posix(),
                "url": "https://github.com/kylofon/test-drive-2-sdl3", "commit": COMMIT,
                "tree": git("rev-parse", "HEAD^{tree}"), "branch": git("branch", "--show-current"),
                "remote_head": git("rev-parse", "refs/remotes/origin/master"),
                "commit_date": git("show", "-s", "--format=%aI", "HEAD"),
                "full_history": git("rev-parse", "--is-shallow-repository") == "false",
                "push_url": git("config", "--get", "remote.origin.pushurl"),
                "read_only": "All clone files including .git have Windows ReadOnly set; push URL disabled. Attributes are an accidental-write guard, not an ACL security boundary. No fetch/pull/edit/build/run in this clone.",
                "tracked_file_count": len(tracked), "tracked_bytes": sum(x["bytes"] for x in tracked),
                "repository_file_count": len(files), "tracked_files": tracked, "repository_files": files}
    our_registry = ROOT / "docs/recovery/functions.json"
    ours = json.loads(our_registry.read_bytes())["records"]
    primary = {f'{r["entries"][0]["segment"]:04x}:{r["entries"][0]["segment_offset"]:04x}': r["id"] for r in ours}
    all_entries = {f'{e["segment"]:04x}:{e["segment_offset"]:04x}': r["id"] for r in ours for e in r["entries"]}
    upstream = json.loads((clone / "port/td2ega_functions.json").read_bytes())
    candidates = {r["start"].lower(): r for r in upstream["functions"]}
    image_path = ROOT / "analysis/derived/td2ega-v1/TD2EGA.image.bin"
    image = image_path.read_bytes()
    if sha(image) != "8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4":
        raise ValueError("Original image identity mismatch")
    anchors = []
    for offset, literal in [(0x0473, b"testdrv2.pes"), (0x651a, b"locateshape"), (0x5fe8, b"NO ROOM LEFT ON TIMER")]:
        expected = literal
        anchors.append({"dgroup_offset": f'{offset:04x}', "image_offset": 0x178f0 + offset,
                        "length": len(expected), "matches_upstream_loader_anchor": image[0x178f0 + offset:0x178f0 + offset + len(expected)] == expected})
    source_files = []
    for path in sorted((ROOT / "src/recovered").glob("*")):
        if path.is_file():
            source_files.append({"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
                                 "sha256": sha(path.read_bytes())})
    variants = {}
    for variant in ("ega", "cga", "tdy"):
        index = json.loads((clone / f"port/td2{variant}_functions.json").read_bytes())
        variants[variant] = {"candidate_functions": len(index["functions"]), "entry": index["entry"], "dgroup": index["dgroup"]}
    symbols = list(csv.DictReader((clone / "port/symbols.csv").read_text().splitlines()))
    progress_path = ROOT / "docs/recovery/progress.json"
    progress = json.loads(progress_path.read_bytes())
    audit_path = ROOT / "docs/recovery/evidence/p1-runtime-report-bus-audit-v1.json"
    audit = json.loads(audit_path.read_bytes())
    crosscheck = {"schema": 1, "inspection_date": "2026-10-22", "method": "Static metadata/full-file inventory and direct anchor comparison; no game or upstream code executed",
                  "upstream_commit": COMMIT, "our_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  "our_registry_sha256": sha(our_registry.read_bytes()), "our_registry_records": len(ours),
                  "our_primary_entries": len(primary), "our_all_entries": len(all_entries),
                  "upstream_ega_candidates": len(candidates), "exact_primary_entry_matches": len(set(primary) & set(candidates)),
                  "matches": [{"address": k, "our_id": primary[k], "upstream_image_offset": candidates[k]["image"]} for k in sorted(set(primary) & set(candidates))],
                  "upstream_only_primary_starts": sorted(set(candidates) - set(primary)),
                  "ours_only_primary_starts": [{"address": k, "our_id": primary[k]} for k in sorted(set(primary) - set(candidates))],
                  "address_limits": "Unrelocated exact segmented primary starts only. Candidate boundary differences are investigation leads, not proof of missing functions or semantic parity. Upstream publishes no input-image cryptographic pin.",
                  "our_image": {"path": image_path.relative_to(ROOT).as_posix(), "bytes": len(image), "sha256": sha(image)},
                  "upstream_loader_size_matches": len(image) == 0x1fcc0,
                  "upstream_loader_anchors": anchors, "upstream_indices": variants,
                  "upstream_symbols": dict(Counter(x["kind"] for x in symbols)),
                  "accepted_checkpoint": {"path": audit_path.relative_to(ROOT).as_posix(), "sha256": sha(audit_path.read_bytes()),
                                          "result": audit["result"], "native_summary": progress["native_summary"],
                                          "progress_sha256_at_inspection": sha(progress_path.read_bytes())},
                  "our_recovered_source_files": source_files,
                  "runtime": "Not attempted. No current upstream compilation, game launch, complete resource parse, original session, pixels or audio accepted."}
    if not all(x["matches_upstream_loader_anchor"] for x in anchors):
        raise ValueError("Upstream build anchors do not match supplied EGA")
    write_fresh(args.snapshot, snapshot)
    write_fresh(args.crosscheck, crosscheck)
    print(json.dumps({"tracked_files": len(tracked), "clone_files": len(files), "primary_start_matches": crosscheck["exact_primary_entry_matches"],
                      "our_candidates": len(primary), "upstream_candidates": len(candidates), "loader_anchors": "all match", "review_coverage": dict(Counter(x["review"] for x in tracked))}, indent=2))


if __name__ == "__main__":
    main()
