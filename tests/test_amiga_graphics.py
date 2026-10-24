"""The Amiga graphics backend with the Amiga game's files (platform/gfx_amiga.c).

Runs the port headless with --amiga-graphics and the amiga setting, through the menus to the scenery
choice, and checks that the screen there is the Master scenery's Amiga picture (scen/sc1_icon) in its
own colours, as the Amiga shows them (the top 4 bits of each component), below the disk name.

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
# tools/snapshots.py's menu keys up to the scenery choice, which opens at 61 s
KEYS = ('30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,42:Down,43:Return,46:Up,49:Down,52:Down,'
        '55:Escape,60:Right,60.5:Right,61:Return')


@unittest.skipUnless(EXE.exists() and GAME.exists() and (AMIGA / 'scen/sc1_icon').exists(),
                     'needs build/td2port.exe, runs/game and runs/amiga')
class AmigaGraphicsTest(unittest.TestCase):
    def test_scenery_choice_picture(self):
        from PIL import Image
        import ilbm
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}\n')
            shots = tmp / 'shots'
            shots.mkdir()
            env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                       TD2_RUN_SECONDS='64', TD2_SNAPSHOT_DIR=str(shots), TD2_SNAPSHOT_MS='20', TD2_KEYS=KEYS)
            p = subprocess.run([str(EXE), '--amiga-graphics', '--game-dir', str(GAME), '--user-dir', str(tmp)],
                               env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(p.returncode, 0, p.stderr)
            # the last frame of the dissolve that opens the scenery choice
            times = [(float(w[2]), w[0]) for w in (ln.split() for ln in p.stderr.splitlines())
                     if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at']
            name = max(n for t, n in times if 61 <= t < 63)
            frame = Image.open(shots / name).convert('RGB')
        pic = ilbm.parse((AMIGA / 'scen/sc1_icon').read_bytes())
        pal = [tuple((c >> 4) * 17 for c in rgb) for rgb in pic.palette]
        diff = [(x, y) for y in range(8, 200) for x in range(320)
                if frame.getpixel((x, y)) != pal[pic.pixels[y * 320 + x]]]
        self.assertEqual(diff[:5], [], f'{len(diff)} pixels differ from the Amiga picture')


if __name__ == '__main__':
    unittest.main()
