"""The Amiga audio backend (amiga/audio_amiga.c) as the game drives it: what it plays for each event.

Opens the Amiga game folder, then: the title song, and the speech over it; a race on the F40 with the car's state ten times a
second (revving up, the siren, a bump, a crash and the end); the game over sound; the song again. Each
part must sound (not be silent), the engine's pitch must follow the rpm, and the end of a race must
fade the car out.

Needs the unpacked Amiga game in runs/amiga and build/td2diff.dll; skipped without them.
"""
import ctypes
import math
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AMIGA = ROOT / 'runs/amiga'
DLL = ROOT / 'build/td2diff.dll'
RATE = 22050
SONG, RACE_START, RACE_END, BUMP, CRASH, GAME_OVER, TITLE = range(7)


class Backend:
    def __init__(self):
        self.dll = ctypes.CDLL(str(DLL))
        f = self.dll.dh_audio_amiga
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                      ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int16)]
        self.f = f

    def open(self, folder):
        return self.f(0, str(folder).encode(), 0, 0, None, None)

    def reset(self):
        self.f(1, None, RATE, 0, None, None)

    def event(self, e, n=0, car=None):
        self.f(2, car.encode() if car else None, e, n, None, None)

    def drive(self, rpm=800, mph=0, throttle=0, gear=0, siren=False, gap=200, running=True):
        pos = 0x4000 << 16
        d = [1, int(running), rpm, mph * 256, throttle, gear, int(gear != 0), 0, int(siren), 0,
             pos, pos - (gap << 16), max(0, mph - 10) * 256]
        arr = (ctypes.c_int32 * len(d))(*[ctypes.c_int32(x & 0xFFFFFFFF).value for x in d])
        self.f(3, None, 0, 0, arr, None)

    def render(self, seconds):
        n = int(RATE * seconds)
        buf = (ctypes.c_int16 * n)()
        self.f(4, None, n, 0, None, buf)
        return list(buf)


def rms(s):
    return math.sqrt(sum(x * x for x in s) / len(s)) if s else 0.0


def crossings(s):
    return sum(1 for i in range(1, len(s)) if (s[i - 1] < 0) != (s[i] < 0)) / 2 / (len(s) / RATE)


@unittest.skipUnless((AMIGA / 'duel').exists() and DLL.exists(), 'needs runs/amiga and build/td2diff.dll')
class AmigaAudioTest(unittest.TestCase):
    def test_events_sound(self):
        b = Backend()
        self.assertFalse(b.open(ROOT / 'runs'))
        self.assertTrue(b.open(AMIGA))
        b.reset()
        self.assertLess(rms(b.render(0.5)), 1)                  # silent until the game says what plays

        b.event(SONG, 1)
        song = b.render(3)
        self.assertGreater(rms(song), 300)                      # the title song
        b.event(SONG, 1)
        b.event(TITLE)
        speech = b.render(3)
        self.assertGreater(rms(speech), 300)
        self.assertNotEqual(speech, song)                       # the speech over the song
        b.render(3)

        b.event(RACE_START, car='F40')
        b.render(0.3)
        pitch = []
        for step in range(40):                                  # four seconds, revving up in gear
            b.drive(rpm=1000 + step * 120, mph=step * 2, throttle=1, gear=1)
            s = b.render(0.1)
            if step in (5, 35):
                pitch.append(crossings(s))
        self.assertGreater(pitch[1], pitch[0] * 1.5)            # the engine follows the rpm
        engine = rms(s)
        self.assertGreater(engine, 300)

        for step in range(30):                                  # the siren closing in, then a bump
            b.drive(rpm=5000, mph=90, throttle=1, gear=4, siren=True, gap=60 - step * 2)
            if step == 20:
                b.event(BUMP)
            b.render(0.1)
        b.drive(rpm=5000, mph=90, throttle=1, gear=4, siren=False)
        b.event(CRASH)
        b.event(RACE_END)
        crash = b.render(0.5)
        self.assertGreater(rms(crash), 300)                     # the crash sound
        for _ in range(40):                                     # the crash sample lasts 3 s
            b.drive(rpm=800, mph=0, running=False)
            tail = b.render(0.1)
        self.assertLess(rms(tail), engine / 20)                 # the car faded out

        b.event(GAME_OVER)
        self.assertGreater(rms(b.render(1)), 300)               # the game over sound
        b.event(SONG, 1)
        self.assertGreater(rms(b.render(3)), 300)               # and the song again
        b.event(SONG, 3)
        b.render(0.2)
        self.assertLess(rms(b.render(0.5)), 1)                  # no Amiga song for the police ending


if __name__ == '__main__':
    unittest.main()
