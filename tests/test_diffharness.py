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

    def billboard_case(self, bp):
        """A billboard (type 55h) right on the car's path, with BP = bp at the crash test."""
        mem = bytearray(self.h.base)
        put = cases.ds_put
        put(mem, 'DS_ring_counter', 0x10, 2)
        put(mem, cases.S['DS_roadside_type'] + 0x10, 0x55)
        put(mem, cases.S['DS_roadside_side'] + 0x10, 0)          # x = 500
        sgn = 0x5000
        put(mem, 'DS_sgn_seg', sgn, 2)
        mem[sgn * 16 + 0x16:sgn * 16 + 0x18] = (0x100).to_bytes(2, 'little')   # (55h-1Eh)/5 = 11, rem 0: word 11
        mem[sgn * 16 + 0x100:sgn * 16 + 0x102] = (80).to_bytes(2, 'little')    # sign width 80
        put(mem, 'DS_region_flags', 0)
        put(mem, 'DS_car_left', 450, 2)
        put(mem, 'DS_car_right', 450 + 0xB4, 2)
        put(mem, 'DS_run_state', 0)
        put(mem, 'DS_speed', 0x3000, 2)
        regs = default_regs(random.Random(9))
        regs['bp'] = bp
        return Case(mem, regs)

    def test_billboard_crash_depends_on_stale_bp(self):
        """Below 14h a stale BP makes a billboard only bump the car (roadside_hit, 06c9:4d18)."""
        run_state = lin(DGROUP, cases.S['DS_run_state'])
        for bp, crashes in ((0x05, False), (0x13, False), (0x14, True), (0x3C00, True)):
            case = self.billboard_case(bp)
            orig, port, _ = self.h.call(self.spec('roadside_hit'), case)
            self.assertEqual(orig.mem[run_state] == 2, crashes, f'original, BP={bp:X}')
            self.assertEqual(port.mem[run_state] == 2, crashes, f'port, BP={bp:X}')
            self.assertTrue(self.h.compare(self.spec('roadside_hit'), self.billboard_case(bp)).ok, bp)

    def neutral_tap_case(self, cx):
        """Fire released in neutral without a shift, with CX = cx left by sound_tick (the rpm)."""
        mem = bytearray(self.h.base)
        put = cases.ds_put
        put(mem, 'DS_gear', 0)
        put(mem, 'DS_knob_anim', 0)
        put(mem, 'DS_fire_held', 1)
        put(mem, 'DS_input', 0)
        put(mem, 'DS_finished', 0)
        put(mem, 'DS_demo_mode', 0, 2)
        put(mem, 'DS_auto_trans', 0)
        put(mem, 'DS_rpm', cx, 2)
        put(mem, 'DS_car_engine_strength', 0x80)
        put(mem, 'DS_engine_damage', 0)
        put(mem, 'DS_gear_ratio', 0x8000, 2)              # still the last gear's ratio
        put(mem, 'DS_grind_timer', 0)
        regs = default_regs(random.Random(4))
        regs['cx'] = cx
        return Case(mem, regs)

    def test_neutral_fire_tap_grinds_at_high_rpm(self):
        """In neutral the clutch check compares the leftover CX (rpm, CL replaced) with DX = 0100h."""
        grind = lin(DGROUP, cases.S['DS_grind_timer'])
        throttle_dir_0 = self.h.base[lin(DGROUP, cases.S['DS_THROTTLE_DIR'])]
        for cx, expect in ((0x1800, (0x1800 & 0xFF00 | throttle_dir_0) - 0x100 >> 8), (0x0300, 0)):
            orig, port, _ = self.h.call(self.spec('decode_controls'), self.neutral_tap_case(cx))
            self.assertEqual(orig.mem[grind], expect, f'original, CX={cx:X}')
            self.assertEqual(port.mem[grind], expect, f'port, CX={cx:X}')

    @unittest.skipUnless(GAME_EXE.exists(), 'needs runs/game')
    def test_traffic_leaves_same_count8_for_pass_collisions(self):
        """pass_collisions relies on traffic() leaving CX = same_count8 (sim_traffic.c); the traffic
        adapter reports exactly that, so a match on CX proves it for these states."""
        for r in self.h.run(self.spec('traffic'), 8, 21):
            self.assertTrue(r.ok, r)

    @unittest.skipUnless(GAME_EXE.exists(), 'needs runs/game')
    def test_unpackers_write_their_output(self):
        for name in ('huff_decode', 'rle_decode'):
            for r in self.h.run(self.spec(name), 3, 11):
                self.assertTrue(r.ok, r)
                self.assertGreater(r.changed, 100, r)


if __name__ == '__main__':
    unittest.main()
