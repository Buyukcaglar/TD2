"""A frozen clone never becomes a blanket exception to original custody."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from verify_reference import verify
from inspect_kylofon_reference import validate_output_paths


class ExternalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "docs/planning/evidence"
        self.evidence.mkdir(parents=True)
        original = self.root / "reference/dos/original.dat"
        original.parent.mkdir(parents=True)
        original.write_bytes(b"original")
        self.original = original
        self.manifest = self.evidence / "reference-manifest.json"
        self.write(self.manifest, {"files": [dict(path="reference/dos/original.dat", **self.row(original))]})
        self.clone = self.root / "reference/repos/example"
        self.clone.mkdir(parents=True)
        self.source = self.clone / "README.md"
        self.source.write_bytes(b"reference source")
        self.source.chmod(0o444)
        self.snapshot = self.evidence / "snapshot.json"
        self.write(self.snapshot, {"repository_path": "reference/repos/example", "commit": "abc",
                                  "repository_files": [dict(path="README.md", **self.row(self.source))]})
        self.registry = self.evidence / "external-repositories.json"
        self.write(self.registry, {"schema": 1, "repositories": [{"path": "reference/repos/example",
                   "commit": "abc", "snapshot_manifest": "docs/planning/evidence/snapshot.json"}]})

    def tearDown(self):
        self.source.chmod(0o666)
        self.tmp.cleanup()

    @staticmethod
    def row(path):
        st = path.stat()
        return {"bytes": st.st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mtime_ns": st.st_mtime_ns, "file_attributes": getattr(st, "st_file_attributes", None)}

    @staticmethod
    def write(path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")

    def test_exact_clone_keeps_original_count(self):
        result = verify(self.root, self.manifest)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(result["external_repositories"][0]["file_count"], 1)

    def test_changed_original_still_fails(self):
        self.original.write_bytes(b"changed!")
        self.assertEqual(verify(self.root, self.manifest)["result"], "fail")

    def test_changed_clone_fails(self):
        self.source.chmod(0o666)
        self.source.write_bytes(b"changed source")
        self.source.chmod(0o444)
        self.assertEqual(verify(self.root, self.manifest)["result"], "fail")

    def test_unknown_clone_file_fails(self):
        (self.clone / "unexpected.txt").write_text("unexpected")
        self.assertEqual(verify(self.root, self.manifest)["result"], "fail")

    def test_unknown_original_file_fails(self):
        (self.original.parent / "unexpected.dat").write_bytes(b"unknown")
        self.assertEqual(verify(self.root, self.manifest)["result"], "fail")

    def test_missing_clone_fails(self):
        self.source.chmod(0o666)
        self.source.unlink()
        self.assertEqual(verify(self.root, self.manifest)["result"], "fail")
        self.source.write_bytes(b"reference source")

    def test_escaping_inventory_rejected(self):
        snapshot = json.loads(self.snapshot.read_text())
        snapshot["repository_files"][0]["path"] = "../escape"
        self.write(self.snapshot, snapshot)
        with self.assertRaises(ValueError):
            verify(self.root, self.manifest)

    def test_original_directory_cannot_be_excluded(self):
        registry = json.loads(self.registry.read_text())
        registry["repositories"][0]["path"] = "reference/dos"
        self.write(self.registry, registry)
        with self.assertRaises(ValueError):
            verify(self.root, self.manifest)

    def test_inspection_cannot_write_reference(self):
        with self.assertRaises(ValueError):
            validate_output_paths([self.clone / "new.json", self.evidence / "new.json"], self.root)

    def test_inspection_outputs_must_be_distinct(self):
        with self.assertRaises(ValueError):
            validate_output_paths([self.evidence / "new.json", self.evidence / "new.json"], self.root)

    def test_inspection_accepts_fresh_separate_evidence(self):
        validate_output_paths([self.evidence / "one.json", self.evidence / "two.json"], self.root)


if __name__ == "__main__":
    unittest.main()
