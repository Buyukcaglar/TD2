"""Tests for the differential harness itself (tools/diffharness).

Needs build/td2diff.dll (build.ps1), analysis/derived/td2ega-v1 and a game copy in runs/game
(run.ps1 once). Run with:  $env:PYTHONPATH = "analysis/tools/python;tools"; python -m unittest tests.test_diffharness
"""
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))

from diffharness import cases                                           # noqa: E402
from diffharness.harness import (DGROUP, DLL, MEM, UNPACKED_EXE, Case, Harness, Spec, default_regs,  # noqa: E402
                                 lin)

GAME_EXE = ROOT / 'runs/game/TD2EGA.EXE'


@unittest.skipUnless(DLL.exists() and UNPACKED_EXE.exists(), 'needs build/td2diff.dll and the unpacked image')
class HarnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = Harness()
        cases.bind(cls.h)

    def spec(self, name):
        return next(s for s in cases.SPECS if s.name == name)

    def test_address_wrap(self):
        self.assertEqual(lin(0xFFFF, 0x0010), 0)
        self.assertEqual(lin(0xFFFF, 0x0011), 1)

    @unittest.skipUnless(GAME_EXE.exists(), 'needs runs/game')
    def test_image_matches_port_loader(self):
        """The harness snapshot is byte-identical to what the port's mem_load_exe builds."""
        self.assertEqual(self.h.port.load_exe(GAME_EXE), self.h.base)

    def test_matching_function(self):
        for r in self.h.run(self.spec('rand8'), 10, 7):
            self.assertTrue(r.ok, r)
            self.assertGreaterEqual(r.changed, 1)

    def test_detects_memory_difference(self):
        """The original free_rev against the port's curve_sum must not match."""
        orig = self.spec('free_rev')
        wrong = Spec('curve_sum', orig.addr, orig.far, [], orig.cases)
        results = self.h.run(wrong, 10, 3)
        self.assertTrue(any(not r.ok and not r.error and 'memory bytes differ' in r.problems[-1] for r in results))

    def test_detects_register_difference(self):
        """rand8 returns its byte in AX; an adapter that leaves AX alone must be caught."""
        orig = self.spec('rand8')
        wrong = Spec('curve_sum', orig.addr, orig.far, ['ax'], orig.cases)
        results = self.h.run(wrong, 5, 3)
        self.assertTrue(all(any(p.startswith('AX:') for p in r.problems) for r in results))

    def test_interrupt_is_an_error_not_a_mismatch(self):
        """06c9:5d2e calls INT 1Ah: the harness stops and reports it."""
        spec = Spec('rand8', '06c9:5d2e', True, ['ax'], cases.SPECS[0].cases)
        r = self.h.run(spec, 1, 1)[0]
        self.assertFalse(r.ok)
        self.assertIn('interrupt 1Ah', r.error)

    def test_stack_frame_is_not_compared(self):
        """Bytes the original writes below its entry SP (its locals) do not count as differences."""
        rng = random.Random(5)
        mem = bytearray(self.h.base)
        case = Case(mem, default_regs(rng))
        orig, port, regs = self.h.call(self.spec('rand8'), case)
        si_slot = lin(DGROUP, regs['sp'] - 2)          # rand8 pushes SI there
        self.assertNotEqual(orig.mem[si_slot:si_slot + 2], port.mem[si_slot:si_slot + 2])
        case = Case(bytearray(self.h.base), default_regs(random.Random(5)))
        self.assertTrue(self.h.compare(self.spec('rand8'), case).ok)

    @unittest.skipUnless(GAME_EXE.exists(), 'needs runs/game')
    def test_unpackers_write_their_output(self):
        for name in ('huff_decode', 'rle_decode'):
            for r in self.h.run(self.spec(name), 3, 11):
                self.assertTrue(r.ok, r)
                self.assertGreater(r.changed, 100, r)


if __name__ == '__main__':
    unittest.main()
