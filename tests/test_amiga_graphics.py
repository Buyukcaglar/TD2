"""The Amiga graphics backend with the Amiga game's files (platform/gfx_amiga.c).

Runs the port headless with --amiga-graphics and the amiga setting, through the menus to the scenery
choice and to the difficulty screen, and checks the option screen's title, the difficulty screen and the
scenery choice against their Amiga pictures (pics/gameoptionscreen, pics/gamedifficulty and the Master
scenery's scen/sc1_icon), the intro's showroom against the F40's side view, the car choice against
its pictures, the high scores against the cars' logos and the gas station against its picture and
the car, and the race's cockpit against the F40's dashboard and the road colours, in their own
colours, as the Amiga shows them (the top 4 bits of each component). The gas station's run takes about
two minutes.

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
# tools/snapshots.py's menu keys up to the scenery choice, 5 s later (the Amiga form's DSI logo and
# credits are duel's, so its high scores show from 29 s), the last ones later still: duel's wipes take
# their time (the option screen comes back from the car choice with bands until 66 s), and keys pressed
# during a wipe are flushed as after a dissolve. The scenery choice opens at 68 s.
KEYS = ('35:Return,44:Up,44.5:Right,45:Down,45.5:Right,46:Up,47:Down,48:Return,51:Up,54:Down,57:Down,'
        '60:Escape,67:Right,67.5:Right,68:Return')


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
            KEYS, 71, [(35, 35.35), (35.35, 44), (68, 71)])
        # Return on the clock opens the difficulty screen
        cls.difficulty, = last_frames('35:Return,40:Return', 43, [(40, 43)])
        # the scenery box, Up to Northern Germany, and back to the option screen
        cls.option_ngc, = last_frames('35:Return,38:Down,38.5:Right,39:Right,40:Return,45:Up,49:Return', 55,
                                      [(50.2, 55)])

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
        frame, = last_frames('35:Return,38:Down,40:Return', 45, [(40, 45)])   # the last, once in
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
        # the attract loop's table after the credits (the last frame before 36 s): five entries, the
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
        frame, = run('1000:Escape', 36, lambda times: [max(times)[1]],
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

    def test_gas_station(self):
        # a race against the clock with Up held from 53 s ends its first section at the gas station
        # (about 329 s): scen/sc1_gasstation above its split at line 103 (but for the section's sign),
        # and the F40 (gcar of cars/f40.sideview.shp, its bottom on line 180) in cars/f40.gas.p's colours
        import ilbm
        import shp
        keys = ['35:Return', '40:Return', '43:Return', '53:Up/400', '57:Left/0.5']
        keys += [f'{t}:Return' for t in range(75, 336, 12)]
        frame, = run(','.join(keys), 339, lambda times: [max(n for t, n in times if 331 <= t < 339)])
        pic = ilbm.parse((AMIGA / 'scen/sc1_gasstation').read_bytes())
        pal = amiga_colours(pic)
        sign = {s.name: s for s in shp.read((AMIGA / 'scen/sc1_gasstation.shp').read_bytes())}['bruc']
        diff = [(x, y) for y in range(103) for x in range(320)
                if not (sign.x <= x < sign.x + sign.width and sign.y <= y < sign.y + sign.height)
                and frame.getpixel((x, y)) != pal[pic.pixels[y * 320 + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the station')
        gas = amiga_colours(ilbm.parse((AMIGA / 'cars/f40.gas.p').read_bytes()))
        cars = {s.name: s for s in shp.read((AMIGA / 'cars/f40.sideview.shp').read_bytes())}
        car, shade = cars['gcar'], cars['care']
        top = 180 - car.height
        # duel XORs the shadow into the car's bitmap and draws it where the result is not 0
        want = {(x, y): (car.pixels[i] if car.mask[i] else 0) ^ (shade.pixels[i] if shade.mask[i] else 0)
                for y in range(car.height) for x in range(car.width) for i in [y * car.width + x]}
        diff = [(x, y) for (x, y), v in want.items() if v and frame.getpixel((car.x + x, top + y)) != gas[v]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the car and its shadow')

    def test_race_cockpit(self):
        # a race against the clock, standing at the start: the F40's dashboard picture (cars/f40dash)
        # from line 118 in its own colours where nothing moves, with the small gauges' needles; the roof (roof of cars/f40dash.shp) in
        # the section's road colours (32 words at 0A6h of scen/sc1_roaddata0) left of its digits, below
        # the progress dots and but for the radar detector's lights; and TD2's view, between the windscreen pillar and the mirror, in
        # those colours only
        import ilbm
        import rpck
        import shp
        import struct
        frame, = last_frames('35:Return,40:Return,43:Return', 51, [(49, 51)])
        dash = ilbm.parse((AMIGA / 'cars/f40dash').read_bytes())
        pal = amiga_colours(dash)
        still = [(x, y) for y in range(118, 131) for x in range(176, 250)]
        still += [(x, y) for y in range(190, 200) for x in range(200, 224)]
        diff = [(x, y) for x, y in still if frame.getpixel((x, y)) != pal[dash.pixels[y * 320 + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the dashboard')
        # the small gauges' needles in pen 16 (cars/f40.b from 0DAh: turbo, oil temperature, oil pressure,
        # fuel, each the centre and 32 tips): each from its centre, the full tank's to its last tip and,
        # standing, the turbo's (the turbo sample's volume) to its first
        b = rpck.read((AMIGA / 'cars/f40.b').read_bytes())
        for g in range(4):
            hub = struct.unpack_from('>2h', b, 0xDA + 0x84 * g)
            self.assertEqual(frame.getpixel(hub), pal[16], f'gauge {g}')
        self.assertEqual(frame.getpixel(struct.unpack_from('>2h', b, 0x266 + 4 + 4 * 31)), pal[16], 'fuel')
        self.assertEqual(frame.getpixel(struct.unpack_from('>2h', b, 0xDA + 4)), pal[16], 'turbo')
        road = rpck.read((AMIGA / 'scen/sc1_roaddata0').read_bytes())
        top = [struct.unpack_from('>H', road, 0xA6 + 2 * i)[0] for i in range(32)]
        top = [((c >> 8 & 15) * 17, (c >> 4 & 15) * 17, (c & 15) * 17) for c in top]
        sprites = {s.name: s for s in shp.read((AMIGA / 'cars/f40dash.shp').read_bytes())}
        roof, lights = sprites['roof'], sprites['rad5']          # the radar detector's lights blink
        diff = [(x, y) for y in range(1, roof.height) for x in range(240) if roof.mask[y * roof.width + x]
                and not (lights.x <= x < lights.x + lights.width and lights.y <= y < lights.y + lights.height)
                and frame.getpixel((x, y)) != top[roof.pixels[y * roof.width + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ in the roof')
        view = {frame.getpixel((x, y)) for y in range(40, 100) for x in range(40, 320)}
        self.assertLessEqual(view, set(top))
        # the sky in duel's pen for it (the road data's word 1Ah)
        sky = top[struct.unpack_from('>H', road, 0x1A)[0]]
        self.assertEqual({frame.getpixel((x, y)) for y in range(22, 28) for x in range(100, 220)}, {sky})

    def test_race_view_moves(self):
        # driving off, TD2's view in the cockpit changes on most frames shown (the car moves on two of
        # three): the small gauges' needles once left TD2's line routine's bit mask at 0, so the next
        # copy of the view onto the screen kept the old road
        from PIL import ImageChops
        frames = frames_after('35:Return,40:Return,43:Return,50:Up/8000', 58, 53)
        views = [f.crop((40, 30, 300, 100)) for f in frames]
        moved = sum(ImageChops.difference(a, b).getbbox() is not None for a, b in zip(views, views[1:]))
        self.assertGreater(len(views), 40)
        self.assertGreater(moved, len(views) // 2, f'the view changed on {moved} of {len(views) - 1} frames')

    def test_scenery_choice_picture(self):
        # below the disk name
        self.assert_picture(self.scenery_choice, 'scen/sc1_icon', range(8, 200))


if __name__ == '__main__':
    unittest.main()
