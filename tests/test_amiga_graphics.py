"""The Amiga graphics backend with the Amiga game's files (platform/gfx_amiga.c).

Runs the port headless with --amiga-graphics and the amiga setting, through the menus to the scenery
choice and to the difficulty screen, and checks the option screen's title, the difficulty screen and the
scenery choice against their Amiga pictures (pics/gameoptionscreen, pics/gamedifficulty and the Master
scenery's scen/sc1_icon), the intro's showroom against the F40's side view, the car choice against
its pictures and the high scores against the cars' logos, in their own colours, as the Amiga shows them
(the top 4 bits of each component).

Needs build/td2port.exe, runs/game and the unpacked Amiga game in runs/amiga; skipped without them.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools/amiga'), str(ROOT / 'tools')]

EXE = ROOT / 'build/td2port.exe'
GAME = ROOT / 'runs/game'
AMIGA = ROOT / 'runs/amiga'
# tools/snapshots.py's menu keys up to the scenery choice, the last ones later: duel's wipes take their
# time (the option screen comes back from the car choice with bands until 61 s), and keys pressed
# during a wipe are flushed as after a dissolve. The scenery choice opens at 63 s.
KEYS = ('30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,42:Down,43:Return,46:Up,49:Down,52:Down,'
        '55:Escape,62:Right,62.5:Right,63:Return')


def amiga_colours(pic):
    return [tuple((c >> 4) * 17 for c in rgb) for rgb in pic.palette]


def last_frames(keys, seconds, windows):
    """Runs the port headless with the Amiga graphics; the last frame shown in each (t0, t1) window."""
    return run(keys, seconds, lambda times: [max(n for t, n in times if t0 <= t < t1) for t0, t1 in windows])


def frames_after(keys, seconds, t0):
    """Runs the port headless with the Amiga graphics; every frame shown from t0 s on."""
    return run(keys, seconds, lambda times: [n for t, n in times if t >= t0])


def run(keys, seconds, pick, files=None):
    """Runs the port headless with the Amiga graphics; the frames pick chooses from (time, file name).
    files: more files for the profile, {name: bytes}."""
    from PIL import Image
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}' + chr(10))
        (tmp / 'select.dat').write_text('0 0 0 F40 P959 TDS2' + chr(10))   # the intro's cars set its length
        for name, data in (files or {}).items():
            (tmp / name).write_bytes(data)
        shots = tmp / 'shots'
        shots.mkdir()
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(shots), TD2_SNAPSHOT_MS='20', TD2_KEYS=keys)
        p = subprocess.run([str(EXE), '--amiga-graphics', '--game-dir', str(GAME), '--user-dir', str(tmp)],
                           env=env, capture_output=True, text=True, timeout=300)
        assert p.returncode == 0, p.stderr
        times = [(float(w[2]), w[0]) for w in (ln.split() for ln in p.stderr.splitlines())
                 if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at']
        return [Image.open(shots / n).convert('RGB') for n in pick(times)]


@unittest.skipUnless(EXE.exists() and GAME.exists() and (AMIGA / 'scen/sc1_icon').exists(),
                     'needs build/td2port.exe, runs/game and runs/amiga')
class AmigaGraphicsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # the option screen part way through the circle that brings it in, the option screen before the
        # first key there, and the scenery choice once its box has grown
        cls.option_circle, cls.option_screen, cls.scenery_choice = last_frames(
            KEYS, 66, [(30, 30.35), (30.35, 39), (63, 66)])
        # Return on the clock opens the difficulty screen
        cls.difficulty, = last_frames('30:Return,35:Return', 38, [(35, 38)])
        # the scenery box, Up to Northern Germany, and back to the option screen
        cls.option_ngc, = last_frames('30:Return,33:Down,33.5:Right,34:Right,35:Return,40:Up,44:Return', 50,
                                      [(45.2, 50)])

    def assert_picture(self, frame, file, rows):
        import ilbm
        pic = ilbm.parse((AMIGA / file).read_bytes())
        pal = amiga_colours(pic)
        diff = [(x, y) for y in rows for x in range(320)
                if frame.getpixel((x, y)) != pal[pic.pixels[y * 320 + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ from {file}')

    def test_option_screen_circle(self):
        # duel's circle (step 6, two frames a step): black in the corners, the picture in the middle
        import ilbm
        pic = ilbm.parse((AMIGA / 'pics/gameoptionscreen').read_bytes())
        pal = amiga_colours(pic)
        for x, y in [(0, 0), (319, 0), (0, 199), (319, 199)]:
            self.assertEqual(self.option_circle.getpixel((x, y)), (0, 0, 0), (x, y))
        self.assertEqual([(x, y) for y in range(95, 106) for x in range(154, 163)
                          if self.option_circle.getpixel((x, y)) != pal[pic.pixels[y * 320 + x]]], [])

    def test_northern_germany_icon(self):
        # Northern Germany has no gameoption.shp: the middle of its title picture's heath photo fills the
        # 62 x 35 the other sceneries' icons fill, in the screen's colours, instead of "N/A"
        box = [self.option_ngc.getpixel((x, y)) for y in range(155, 190) for x in range(167, 229)]
        self.assertLess(sum(c == (0, 0, 0) for c in box), len(box) // 20)
        self.assertTrue(any(c[2] > 200 and c[0] < 100 for c in box[:62 * 5]), 'no sky at the top')

    def test_option_screen_picture(self):
        # the title above the boxes, in the picture's colours above its split line
        self.assert_picture(self.option_screen, 'pics/gameoptionscreen', range(0, 27))

    def test_difficulty_picture(self):
        # above and below the arrow (rows 53 to 103)
        self.assert_picture(self.difficulty, 'pics/gamedifficulty', [*range(0, 53), *range(104, 200)])

    def test_showroom_side_view(self):
        # the intro's showroom: the F40's side view (gcar of cars/f40.sideview.shp) in its own colours
        # (cars/f40.st.p), its bottom on the bottom line, the window box (wnd0, 64 x 15 at 144, 21 of the
        # sprite's place) left out because it opens
        import ilbm
        import shp
        pal = amiga_colours(ilbm.parse((AMIGA / 'cars/f40.st.p').read_bytes()))
        car = {s.name: s for s in shp.read((AMIGA / 'cars/f40.sideview.shp').read_bytes())}['gcar']
        top = 200 - car.height
        want = {(car.x + x, top + y): pal[car.pixels[y * car.width + x]]
                for y in range(car.height) for x in range(car.width)
                if not (144 <= car.x + x < 208 and 21 <= car.y + y < 36)}
        best = min(sum(f.getpixel(xy) != c for xy, c in want.items()) for f in frames_after('60:Return', 12, 3))
        self.assertEqual(best, 0)

    def test_car_choice(self):
        # YOUR CAR: the F40 on pics/bluestat in its colours in the top 84 lines (each pixel twice, the
        # frame being 640 wide), and its data, rows 84 on of cars/f40.sb, in high resolution under them
        import ilbm
        import shp
        frame, = last_frames('30:Return,33:Down,35:Return', 40, [(35, 40)])   # the last, once in
        self.assertEqual(frame.size, (640, 200))
        pal = amiga_colours(ilbm.parse((AMIGA / 'cars/f40.st.p').read_bytes()))
        top = list(ilbm.parse((AMIGA / 'pics/bluestat').read_bytes()).pixels[:84 * 320])
        for s in shp.read((AMIGA / 'cars/f40.sideview.shp').read_bytes()):
            if s.name in ('gcar', 'logo'):
                for y in range(s.height):
                    for x in range(s.width):
                        if s.mask[y * s.width + x] and 0 <= s.y + y < 84 and 0 <= s.x + x < 320:
                            top[(s.y + y) * 320 + s.x + x] = s.pixels[y * s.width + x]
        diff = [(x, y) for y in range(84) for x in range(640) if frame.getpixel((x, y)) != pal[top[y * 320 + x // 2]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the car')
        sb = ilbm.parse((AMIGA / 'cars/f40.sb').read_bytes())
        sb_pal = amiga_colours(sb)
        diff = [(x, y) for y in range(84, 200) for x in range(640)
                if frame.getpixel((x, y)) != sb_pal[sb.pixels[y * 640 + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the data')

    def test_high_scores(self):
        # the attract loop's table after the credits (the last frame before 31 s): five entries, the
        # F40's logo first and the Camaro's third (a data disk's car, its colours a CMAP alone), each in
        # its car's colours 3 to 31 from two lines above the logo, colours 0 to 2 the screen's; no
        # sixth line
        import ilbm
        import shp
        import struct
        table = bytearray((GAME / 'TDS2HISC.DAT').read_bytes())
        entries = [(912345, 'F40'), (654321, 'P959'), (500000, 'CAMA'), (400000, 'F40'), (300000, 'P959')]
        for i, (score, car) in enumerate(entries):
            struct.pack_into('<l5s17s', table, 26 * i, score, car.encode(), b'Driver')
        sum_ = struct.unpack_from('<L', table, 0x150)[0] + sum(s for s, _ in entries)
        struct.pack_into('<L', table, 0x150, sum_ & 0xFFFFFFFF)
        frame, = run('1000:Escape', 31, lambda times: [max(times)[1]],
                     {'TDS2HISC.DAT': bytes(table)})
        screen = [(0, 0, 0), (0, 136, 238), (255, 102, 102)]
        for i, car in [(0, 'cars/f40'), (2, 'cars1/cars/camo')]:
            rear = amiga_colours(ilbm.parse((AMIGA / f'{car}.rear.p').read_bytes()))
            logo = {s.name: s for s in shp.read((AMIGA / f'{car}logo.shp').read_bytes())}['logo']
            x0, y0 = 40 - logo.hot_x, i * 35 + 50 - logo.hot_y
            diff = [(x, y) for y in range(logo.height) for x in range(logo.width) if logo.mask[y * logo.width + x]
                    and frame.getpixel((x0 + x, y0 + y)) != (lambda c: screen[c] if c < 3 else rear[c])(
                        logo.pixels[y * logo.width + x])]
            self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the logo of {car}')
        self.assertIn(screen[2], {frame.getpixel((x, y)) for y in range(1, 9) for x in range(320)})
        for i in range(4):
            self.assertIn(screen[1], {frame.getpixel((x, y)) for y in range(i * 35 + 35, i * 35 + 43)
                                      for x in range(74, 320)}, f'entry {i}')
        self.assertIn(screen[1], {frame.getpixel((x, y)) for y in range(162, 170) for x in range(74, 320)})
        self.assertEqual({frame.getpixel((x, y)) for y in range(172, 180) for x in range(320)}, {(0, 0, 0)})

    def test_scenery_choice_picture(self):
        # below the disk name
        self.assert_picture(self.scenery_choice, 'scen/sc1_icon', range(8, 200))


if __name__ == '__main__':
    unittest.main()
