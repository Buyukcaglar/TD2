"""EGA, CGA and Hercules output against the committed snapshot hashes, and the live graphics switch's
round trip (tools/snapshots.py). Takes about two minutes.

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
    def check(self, adapter):
        shots = snapshots.take(adapter)
        self.assertEqual(snapshots.round_trip(shots, adapter), [])
        self.assertEqual(snapshots.compare(shots, snapshots.read_baseline(adapter)), [])

    def test_ega_frames_match_the_baseline(self):
        self.check('ega')

    def test_cga_frames_match_the_baseline(self):
        self.check('cga')

    def test_hercules_frames_match_the_baseline(self):
        self.check('herc')


if __name__ == '__main__':
    unittest.main()
