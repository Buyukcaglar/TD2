"""The Northern Germany Challenge the app builds from the Amiga game (app/northern_germany.c).

Starts the port headless with the Amiga setting, which builds the scenery into the profile, then checks:
- the catalogue lists it with its seven stages;
- each stage is its DOS twin with the sprite archive of its Amiga sprite file, and the original game's
  own unpacker (rle_decode, run under the harness) reads each packed file;
- the signs are Northern Germany's own, each in the DOS slot its Amiga sign has on the road;
- the traffic cars are the DOS twins of Northern Germany's Amiga copies.

Needs build/td2port.exe, build/td2diff.dll, the unpacked image, runs/game with the California and European
Challenges, and the unpacked Amiga game in runs/amiga; skipped without them.
"""
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'analysis/tools/python')]
import dos_unpack                                                       # noqa: E402

EXE = ROOT / 'build/td2port.exe'
GAME = ROOT / 'runs/game'
AMIGA = ROOT / 'runs/amiga'
TWINS = [('CCC6', 'TDS2TRES'), ('TDS22', 'EC_1'), ('EC_3', 'EC_1'), ('CCC2', 'TDS2TRES'), ('TDS24', 'EC_2'),
         ('EC_5', 'EC_2'), ('EC_1', 'EC_2')]


def signs(path):
    d = path.read_bytes()
    return {k: d[o + 26:d.index(0, o + 26)].decode() for k, o in enumerate(struct.unpack_from('<20H', d)) if o}


@unittest.skipUnless(EXE.exists() and (GAME / 'CCC6.DAT').exists() and (GAME / 'EC_1.DAT').exists()
                     and (AMIGA / 'scen3').exists(), 'needs build/td2port.exe, runs/game with expansions, runs/amiga')
class NorthernGermanyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.profile = Path(cls.tmp.name)
        (cls.profile / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}\n')
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS='1')
        subprocess.run([str(EXE), '--game-dir', str(GAME), '--user-dir', str(cls.profile)], env=env,
                       capture_output=True, timeout=120)
        cls.out = cls.profile / 'Northern Germany'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_catalogue(self):
        lines = (self.profile / 'SCENES.DAT').read_bytes().split(b'\r\n')
        self.assertIn(b'NGC Northern_Germany 7', lines)

    def test_stages(self):
        for s, (twin, archive) in enumerate(TWINS):
            packed = (self.out / f'NGC{s}.DAT').read_bytes()
            dos = dos_unpack.unpack((GAME / f'{twin}.DAT').read_bytes())
            want = archive.encode().ljust(20, b'\0') + dos[20:]
            self.assertEqual(dos_unpack.unpack(packed), want, s)
            if harness:
                self.assertEqual(game_unpack(packed), want, f'stage {s} through the game\'s rle_decode')

    def test_signs(self):
        self.assertEqual(sorted(p.name for p in self.out.glob('*.SGN')),
                         ['NGC0.SGN', 'NGC2.SGN', 'NGC3.SGN', 'NGC5.SGN', 'NGC6.SGN'])   # 1 and 4: no sign on the road
        s0 = signs(self.out / 'NGC0.SGN')
        self.assertEqual(s0[0], 'UDEDOM ')
        self.assertNotIn(9, s0)                     # California 6's DOS road skips sign 9 ...
        self.assertEqual(s0[10], ' FEHMARN ')       # ... so the Amiga's tenth sign is DOS sign 10
        self.assertEqual(s0[13], 'ACHTUNG             ')
        s5 = signs(self.out / 'NGC5.SGN')
        self.assertEqual(s5[0], '  GOTT \nZUM GRUSSE')
        self.assertEqual(s5[3], '  VORSICHT \n STEINSCHLAG ')   # Europe 5 numbers its signs alike in both
        self.assertEqual(s5[4], ' OKERTAL \nSPERRE 900M')
        self.assertNotIn(9, s5)                     # its road's sign 9 has no text on the Amiga

    def test_traffic(self):
        """duel's euro_van, euro_thunderbird and euro_mercedes are copies of the Master van, the Master mercedes
        and the European thunderbird; their DOS twins fill the three slots."""
        for slot, twin in ((1, 'TDS2CAR3'), (2, 'TDS2CAR1'), (3, 'EC_CAR2')):
            for ext in ('PES', 'PCS'):
                self.assertEqual((self.out / f'NGCCAR{slot}.{ext}').read_bytes(),
                                 (GAME / f'{twin}.{ext}').read_bytes(), f'NGCCAR{slot}.{ext}')

    def test_icons(self):
        """The title picture as the choice screen's picl and the menu's pics, row-major (storage mode 0)."""
        for ext, wb in (('PES', 8), ('PCS', 4)):
            packed = (self.out / f'NGCICON.{ext}').read_bytes()
            arc = dos_unpack.unpack(packed)
            self.assertEqual(struct.unpack_from('<I', arc)[0], len(arc))
            sprites = dict(dos_unpack.entries(arc))
            self.assertEqual(list(sprites), ['picl', 'pics'])
            for name, (w, h, x, y) in {'picl': (320, 178, 0, 13), 'pics': (64, 36, 168, 154)}.items():
                b = sprites[name]
                self.assertEqual(struct.unpack_from('<6H', b), (w // wb, h, 0, 0, x, y), name)
                self.assertEqual(b[12:16], b'\1\2\4\x08' if ext == 'PES' else bytes(4), name)
                self.assertEqual(len(b), 16 + w * h // 2 if ext == 'PES' else 16 + w * h // 4, name)
                self.assertGreater(len(set(b[16:])), 8, f'{name}: a picture, not a blank')
            if harness:
                self.assertEqual(game_unpack(packed), arc, f'{ext} through the game\'s rle_decode')


harness = None
try:
    from diffharness import cases                                       # noqa: E402
    from diffharness.harness import DLL, UNPACKED_EXE, Harness, default_regs   # noqa: E402
    if DLL.exists() and UNPACKED_EXE.exists():
        harness = Harness()
except Exception:                                                       # noqa: BLE001
    harness = None


def game_unpack(packed):
    """The packed file through the original game's rle_decode, laid out as unpack_file does it."""
    rng = random.Random(1)
    spec = next(s for s in cases.SPECS if s.name == 'rle_decode')
    mem = bytearray(harness.base)
    blk, total, in_seg = cases.place_packed(rng, mem, packed)
    case = cases.Case(mem, default_regs(rng), [0, in_seg, 0, blk, total])
    orig, port, _ = harness.call(spec, case)
    if orig.error or port.error:
        raise AssertionError(orig.error or port.error)
    size = int.from_bytes(packed[1:4], 'little')
    out = orig.mem[blk * 16:blk * 16 + size]
    if out != port.mem[blk * 16:blk * 16 + size]:
        raise AssertionError("the port's rle_decode differs from the original's")
    return out


if __name__ == '__main__':
    unittest.main()
