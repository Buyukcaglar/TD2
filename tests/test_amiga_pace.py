"""The intro's pace follows the sound (host_amiga_pace): with the Amiga sound it waits as long as duel.

Runs the game headless twice, with the PC speaker and with the Amiga sound, takes a frame every 50 ms
and finds the spans of time in which the picture changes. With the PC speaker the first showroom car
waits 150 ticks (1.5 s) before its window opens, as the DOS game does. With the Amiga sound:
"Accolade presents" ends with its speech, the car's reveal follows at once, the car waits 200 frames
(80 to the starter, 120 more) and the title stays until both speeches end and 220 frames more.

Needs build/td2port.exe, runs/game and the unpacked Amiga game in runs/amiga; skipped without them.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'build/td2port.exe'
AMIGA = ROOT / 'runs/amiga'
FRAME = 1 / 60.05                                           # an NTSC frame


def spans(sound, seconds):
    """The (start, end) times in which the picture changes, with gaps of 0.15 s or more between."""
    with tempfile.TemporaryDirectory() as tmp:
        out, profile = Path(tmp) / 'out', Path(tmp) / 'profile'
        out.mkdir()
        profile.mkdir()
        if sound == 'amiga':
            (profile / 'settings.ini').write_text(f'amiga={AMIGA.as_posix()}\nsound=Amiga\n')
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(out), TD2_SNAPSHOT_MS='50',
                   TD2_KEYS='999:Return')                   # a key script makes the log give frame times
        p = subprocess.run([str(EXE), '--game-dir', str(ROOT / 'runs/game'), '--user-dir', str(profile)],
                           env=env, capture_output=True, text=True, timeout=300)
        times = [(w[0], float(w[2])) for w in (ln.split() for ln in p.stderr.splitlines())
                 if len(w) == 4 and w[1] == 'at']
        changes, prev = [], None
        for name, t in times:
            b = (out / name).read_bytes()[54::97]
            if prev is not None and b != prev:
                changes.append(t)
            prev = b
    result = []
    for t in changes:
        if result and t - result[-1][1] < 0.15:
            result[-1][1] = t
        else:
            result.append([t, t])
    return result


@unittest.skipUnless(EXE.exists() and (ROOT / 'runs/game').exists() and (AMIGA / 'duel').exists(),
                     'needs build/td2port.exe, runs/game and runs/amiga')
class IntroPaceTest(unittest.TestCase):
    def test_dos_pace(self):
        s = spans('pcs', 8)
        # the Accolade screen, 3 s, the car's reveal, 150 ticks, the window
        self.assertAlmostEqual(s[1][0] - s[0][1], 3.0, delta=0.15)
        self.assertAlmostEqual(s[2][0] - s[1][1], 1.5, delta=0.15)

    def test_amiga_pace(self):
        s = spans('amiga', 19.5)
        sys.path.insert(0, str(ROOT / 'tests'))
        from test_amiga_audio import speech_seconds
        # the car's reveal follows the Accolade speech at once (within the first span), then 200 frames
        self.assertLess(s[0][1], speech_seconds('accolade') + 0.6)
        self.assertAlmostEqual(s[1][0] - s[0][1], 200 * FRAME, delta=0.15)
        # the title picture stays for both speeches and 220 frames; the credits come next
        title, credits = s[-2], s[-1]
        hold = speech_seconds('the_duel') + speech_seconds('test_drive_ii') + 220 * FRAME
        self.assertAlmostEqual(credits[0] - title[0], hold, delta=0.15)


if __name__ == '__main__':
    unittest.main()
