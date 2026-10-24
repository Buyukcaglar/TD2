"""TD2EGA against TD2CGA (tools/cga_compare.py, docs/cga.md). Needs runs/game (run.ps1 once)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import cga_compare as cc                                                # noqa: E402
import exepack                                                          # noqa: E402

SIMULATION = ['06b3:0008', '06c9:403b', '06c9:4281', '06c9:448a', '06c9:4639', '06c9:4674', '06c9:4c85',
              '06c9:4d3f', '06c9:4f92', '06c9:5022', '06c9:5299', '06c9:5334', '06c9:5427', '06c9:5446',
              '06c9:56ed']


@unittest.skipUnless((cc.GAME / 'TD2CGA.EXE').exists(), 'needs runs/game')
class CgaCompareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = cc.Compare()

    def test_unpack_matches_the_known_ega_image(self):
        ref = ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin'
        if not ref.exists():
            self.skipTest('no reference EGA image')
        image, relocations, meta = exepack.unpack((cc.GAME / 'TD2EGA.EXE').read_bytes())
        self.assertEqual(image, ref.read_bytes())
        self.assertEqual(len(relocations), 1652)

    def test_simulation_is_the_same_program(self):
        for e in SIMULATION:
            ea, ca = self.c.norm_pair(e)
            self.assertEqual(cc.classify(ea, ca, self.c.addr)[0], 'same after relink', e)

    def test_a_real_difference_is_reported(self):
        """draw_steering aligns the marker to 4 pixels in CGA instead of 8."""
        ea, ca = self.c.norm_pair('06c9:3c3a')
        kind, diff = cc.classify(ea, ca, self.c.addr)
        self.assertIn('-and dx, 0xfff8', diff)
        self.assertIn('+and dx, 0xfffc', diff)

    def test_scenery_colours_come_from_the_cga_words(self):
        """stage_load reads the stage file's CGA colour words, 2 bytes before EGA's."""
        ea, ca = self.c.norm_pair('06c9:1c8f')
        kind, diff = cc.classify(ea, ca, self.c.addr)
        self.assertIn('-mov ax, word ptr [0x378c]', diff)
        self.assertIn('+mov ax, word ptr [0x3686]', diff)

    def test_instruments_differ_only_in_the_needle_colour(self):
        """The digit handle table moved with its base (DS:3010 -> 2F18); only colour 15 -> FFFFh is left."""
        ea, ca = self.c.norm_pair('06c9:3cef')
        _, diff = cc.classify(ea, ca, self.c.addr)
        self.assertEqual([d for d in diff if d[0] in '+-'], ['-mov dx, 0xf', '+mov dx, 0xffff'] * 2)

    def test_a_constant_only_change_is_listed(self):
        """credits has the same size and calls in both builds; only its text colours differ."""
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cc.main([])
        self.assertRegex(out.getvalue(), r'010c:0285 credits .* 2 EGA / 2 CGA lines differ')

    def test_unrelated_functions_do_not_compare_equal(self):
        ea, _ = self.c.norm_pair('06c9:4d3f')            # traffic
        _, ca = self.c.norm_pair('06c9:4674')            # motion
        self.assertNotEqual(cc.classify(ea, ca, self.c.addr)[0], 'same after relink')


if __name__ == '__main__':
    unittest.main()
