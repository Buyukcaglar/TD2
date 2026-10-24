"""The Amiga graphics backend with the Amiga game's files (platform/gfx_amiga.c).

Runs the port headless with --amiga-graphics and the amiga setting, through the menus to the scenery
choice and to the difficulty screen, and checks the option screen's title, the difficulty screen and the
scenery choice against their Amiga pictures (pics/gameoptionscreen, pics/gamedifficulty and the Master
scenery's scen/sc1_icon), in their own colours, as the Amiga shows them (the top 4 bits of each
component).

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
    from PIL import Image
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}' + chr(10))
        shots = tmp / 'shots'
        shots.mkdir()
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(shots), TD2_SNAPSHOT_MS='20', TD2_KEYS=keys)
        p = subprocess.run([str(EXE), '--amiga-graphics', '--game-dir', str(GAME), '--user-dir', str(tmp)],
                           env=env, capture_output=True, text=True, timeout=300)
        assert p.returncode == 0, p.stderr
        times = [(float(w[2]), w[0]) for w in (ln.split() for ln in p.stderr.splitlines())
                 if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at']
        return [Image.open(shots / max(n for t, n in times if t0 <= t < t1)).convert('RGB')
                for t0, t1 in windows]


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

    def test_option_screen_picture(self):
        # the title above the boxes, in the picture's colours above its split line
        self.assert_picture(self.option_screen, 'pics/gameoptionscreen', range(0, 27))

    def test_difficulty_picture(self):
        # above and below the arrow (rows 53 to 103)
        self.assert_picture(self.difficulty, 'pics/gamedifficulty', [*range(0, 53), *range(104, 200)])

    def test_scenery_choice_picture(self):
        # below the disk name
        self.assert_picture(self.scenery_choice, 'scen/sc1_icon', range(8, 200))


if __name__ == '__main__':
    unittest.main()
