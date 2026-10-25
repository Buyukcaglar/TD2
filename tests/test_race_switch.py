"""The live graphics switch during a race keeps the memory it frees (game/flow_stage.c, stage_shapes_switch),
and at a section's end, at game over and in the name entry it draws the screen again in the new mode.

Starts a European Challenge race (the largest scenery files), switches the graphics every two seconds
through two full rounds of the modes (EGA, CGA, Hercules and, with runs/amiga, the Amiga form), and
checks the game neither stops nor reports a fatal error. The signs and their font used to stay above
the reloaded archives, so each switch left the old archives' memory as holes and the third switch ran
out of memory ("reservememory - OUT OF MEMORY LOADING"). Takes about a minute.

The section end's test drives tools/snapshots.py's race run to the first section's end (about 300 s of
game time, half a minute) and switches EGA to CGA on the gas station and CGA to Hercules on the record
book's page: each must show at once in the new mode, not wait for the next race frame. The game's end
test drives that run on to game over (about 438 s, a minute and a half) and switches EGA to CGA there
and CGA to Hercules in the name entry after the first letter: game over shows the crashed race again in
CGA, the name entry goes on in Hercules, and both letters reach the score table.

Needs build/TD2.exe and runs/game with the European Challenge files; skipped without them.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
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


@unittest.skipUnless(EXE.exists() and (GAME / 'TDS2HISC.DAT').exists(), 'needs build/TD2.exe and runs/game')
class SectionEndSwitchTest(unittest.TestCase):
    def race(self, until, switches, seconds, windows):
        """tools/snapshots.py's race run with its keys before `until` and the switches; the last frame in
        each (t0, t1) window and the score table it saved."""
        from PIL import Image
        from snapshots import RACE_KEYS
        keys = [k for k in RACE_KEYS.split(',') if float(k.split(':')[0]) < until]
        keys += [f'{t}:Ctrl+Shift+G' for t in switches]
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / 'select.dat').write_text('0 0 0 F40 P959 TDS2' + chr(10))
            (tmp / 'TDS2HISC.DAT').write_bytes(bytes(0x154))      # empty: the section makes the record book
            shots = tmp / 'shots'
            shots.mkdir()
            env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                       TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(shots), TD2_SNAPSHOT_MS='500',
                       TD2_KEYS=','.join(sorted(keys, key=lambda k: float(k.split(':')[0]))))
            env.pop('TD2_STATE_DIR', None)
            p = subprocess.run([str(EXE), '--game-dir', str(GAME), '--user-dir', str(tmp)],
                               env=env, capture_output=True, text=True, timeout=600)
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            times = [(float(w[2]), w[0]) for w in (ln.split() for ln in p.stderr.splitlines())
                     if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at']

            frames = []
            for t0, t1 in windows:
                names = [n for t, n in times if t0 <= t < t1]
                self.assertTrue(names, f'no frame between {t0} and {t1} s')
                frames.append(Image.open(shots / names[-1]).convert('RGB'))
            scores = (tmp / 'TDS2HISC.DAT').read_bytes()
        return frames, scores

    def assert_cga_picture(self, frame):
        """CGA's four colours, and mostly not black above the bottom rows."""
        self.assertEqual(frame.size, (320, 200))
        self.assertLessEqual(len(frame.getcolors(1 << 16)), 4)
        self.assertGreater(sum(1 for px in frame.crop((0, 0, 320, 160)).getdata() if px != (0, 0, 0)), 30000)

    def test_gas_station_and_results_page(self):
        # the gas station shows from 307 s, the record book's page from 310 s until Return at 316 s
        (gas, page), _ = self.race(317, [308.5, 313], 315.5, [(308.5, 310), (313, 316)])
        self.assert_cga_picture(gas)
        self.assertEqual(page.size, (640, 300))     # the record book in Hercules
        self.assertEqual(len(page.getcolors(1 << 16)), 2)

    def test_game_over_and_name_entry(self):
        # game over from 438 s until Return at 442 s; the name entry from 466 s, T at 470 s, D at 470.5 s
        # and Return at 471 s
        (over, entry), scores = self.race(472, [439, 470.2], 472, [(439, 442), (470.6, 471)])
        self.assert_cga_picture(over)               # the crashed race again, in CGA
        self.assertEqual(entry.size, (640, 300))    # the name entry in Hercules
        self.assertEqual(len(entry.getcolors(1 << 16)), 2)
        self.assertIn(b'td', scores)


if __name__ == '__main__':
    unittest.main()
