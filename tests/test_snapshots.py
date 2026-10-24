"""EGA output against the committed snapshot hashes (tools/snapshots.py). Takes about 30 s.

Needs build/td2port.exe (build.ps1) and runs/game (run.ps1 once).
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import snapshots                                                        # noqa: E402


@unittest.skipUnless(snapshots.EXE.exists() and (snapshots.GAME / 'TD2EGA.EXE').exists(),
                     'needs build/td2port.exe and runs/game')
class SnapshotTest(unittest.TestCase):
    def test_ega_frames_match_the_baseline(self):
        self.assertEqual(snapshots.compare(snapshots.take(), snapshots.read_baseline()), [])


if __name__ == '__main__':
    unittest.main()
