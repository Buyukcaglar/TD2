"""The intro's showroom shows the chosen cars, the player's and then the computer's, as the Amiga game
does (duel $2b776); TD2's own intro always shows cars 0 and 1.

Runs the port headless twice, with the player's car the F40 and the Camaro in select.dat, and checks that
the car standing in the showroom differs and is the Camaro's red in the second run.

Needs build/td2port.exe and runs/game with the Camaro (CAMA); skipped without them.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'build/td2port.exe'
GAME = ROOT / 'runs/game'


def showroom_frame(select):
    """The last frame shown before 7 s of the intro, when the first car stands in the showroom."""
    from PIL import Image
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'select.dat').write_text(select + chr(10))
        shots = tmp / 'shots'
        shots.mkdir()
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS='7', TD2_SNAPSHOT_DIR=str(shots), TD2_SNAPSHOT_MS='100',
                   TD2_KEYS='30:Return')   # a key script makes the port log each frame's time
        p = subprocess.run([str(EXE), '--game-dir', str(GAME), '--user-dir', str(tmp)],
                           env=env, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        times = [(float(w[2]), w[0]) for w in (ln.split() for ln in p.stderr.splitlines())
                 if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at']
        return Image.open(shots / max(n for t, n in times if t < 7)).convert('RGB')


@unittest.skipUnless(EXE.exists() and (GAME / 'CAMAST.PES').exists(), 'needs build/td2port.exe and runs/game')
class IntroCarsTest(unittest.TestCase):
    def test_the_intro_shows_the_players_car(self):
        f40 = showroom_frame('0 0 0 F40 P959 TDS2')
        camaro = showroom_frame('0 0 0 CAMA COUN TDS2')
        self.assertNotEqual(f40.tobytes(), camaro.tobytes())
        # the Camaro is red; the car stands in rows 110 to 190
        body = [camaro.getpixel((x, y)) for x in range(0, 320, 2) for y in range(110, 190, 2)]
        self.assertGreater(sum(r > 150 and g < 80 and b < 80 for r, g, b in body), len(body) // 10)


if __name__ == '__main__':
    unittest.main()
