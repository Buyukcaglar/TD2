"""The live graphics switch during a race keeps the memory it frees (game/flow_stage.c, stage_shapes_switch).

Starts a European Challenge race (the largest scenery files), switches the graphics every two seconds
through two full rounds of the modes (EGA, CGA, Hercules and, with runs/amiga, the Amiga form), and
checks the game neither stops nor reports a fatal error. The signs and their font used to stay above
the reloaded archives, so each switch left the old archives' memory as holes and the third switch ran
out of memory ("reservememory - OUT OF MEMORY LOADING"). Takes about a minute.

Needs build/TD2.exe and runs/game with the European Challenge files; skipped without them.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'build/TD2.exe'
GAME = ROOT / 'runs/game'
AMIGA = ROOT / 'runs/amiga'


@unittest.skipUnless(EXE.exists() and (GAME / 'EC_0.PES').exists(), 'needs build/TD2.exe and runs/game')
class RaceSwitchTest(unittest.TestCase):
    def test_switches_in_a_european_race(self):
        amiga = (AMIGA / 'duel').exists()
        switches = 2 * (4 if amiga else 3)
        # Return through the intro, the menus and the difficulty screen; the race starts by 58 s
        keys = ['23:Return'] + [f'{t}:Return' for t in range(24, 57, 2)] + ['58:Up/60000']
        keys += [f'{62 + 2 * i}:Ctrl+Shift+G' for i in range(switches)]
        seconds = 64 + 2 * switches
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            if amiga:
                (tmp / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}' + chr(10))
            (tmp / 'select.dat').write_text('0 0 0 F40 P959 ec_' + chr(10))
            env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                       TD2_RUN_SECONDS=str(seconds), TD2_KEYS=','.join(keys))
            env.pop('TD2_STATE_DIR', None)
            p = subprocess.run([str(EXE), '--game-dir', str(GAME), '--user-dir', str(tmp)],
                               env=env, capture_output=True, text=True, timeout=600)
        self.assertNotIn('fatal', p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])


if __name__ == '__main__':
    unittest.main()
