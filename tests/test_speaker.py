"""Tests for the PC-speaker synthesis (port/td2/td2port/src/speaker.c) through build/td2diff.dll.

Run with:  python -m unittest tests.test_speaker   (needs numpy and build.ps1)
"""
import ctypes as C
import unittest
from pathlib import Path

try:
    import numpy as np
except ImportError:          # pragma: no cover
    np = None

ROOT = Path(__file__).resolve().parents[1]
DLL = ROOT / 'build/td2diff.dll'
RATE = 44100
PIT_HZ = 1193182
AMP = 5000
GATE, DATA = 1, 2


@unittest.skipUnless(np is not None and DLL.exists(), 'needs numpy and build/td2diff.dll')
class SpeakerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = C.CDLL(str(DLL))
        cls.dll.dh_speaker_reset.argtypes = [C.c_int]
        cls.dll.dh_speaker_play.argtypes = [C.c_uint16, C.c_uint8, C.POINTER(C.c_int16), C.c_int, C.c_int]

    def setUp(self):
        self.dll.dh_speaker_reset(RATE)

    def play(self, divisor, bits, n):
        buf = (C.c_int16 * n)()
        self.dll.dh_speaker_play(divisor, bits, buf, n, AMP)
        return np.frombuffer(buf, dtype=np.int16).astype(float)

    @staticmethod
    def alias_db(x, divisor):
        """Energy away from the square wave's odd harmonics, relative to the energy on them."""
        n = 32768
        spec = np.abs(np.fft.rfft(x[-n:] * np.hanning(n))) ** 2
        freq = np.fft.rfftfreq(n, 1 / RATE)
        f0 = PIT_HZ / divisor
        on = freq < 20
        for k in range(1, int(RATE / 2 / f0) + 1, 2):
            on |= np.abs(freq - k * f0) < 4 * RATE / n
        return 10 * np.log10(spec[~on].sum() / spec[on].sum())

    @staticmethod
    def naive(divisor, n):
        """The port's previous synthesis: an unfiltered +-AMP square wave."""
        phase = (np.arange(n) * PIT_HZ / divisor / RATE) % 1
        return np.where(phase < 0.5, AMP, -AMP).astype(float)

    def test_tones_are_band_limited(self):
        for divisor in (4000, 1193, 600, 300):                  # 298 Hz .. 4 kHz
            new = self.alias_db(self.play(divisor, GATE | DATA, RATE), divisor)
            old = self.alias_db(self.naive(divisor, RATE), divisor)
            self.assertLess(new, -35, divisor)
            self.assertLess(new, old - 20, divisor)

    def test_ultrasonic_tone_is_silent(self):
        """59.7 kHz: the speaker cannot follow it, and it must not fold into an audible tone."""
        x = self.play(20, GATE | DATA, RATE)
        self.assertLess(x[-20000:].std(), AMP * 0.01)

    def test_stopping_settles_to_silence(self):
        for bits in (0, GATE, DATA):                            # data off, or gate off (PIT output held high)
            self.setUp()
            self.play(1193, GATE | DATA, 4410)
            x = self.play(1193, bits, RATE // 2)
            self.assertEqual(np.abs(x[-5000:]).max(), 0, bits)

    def test_gate_restarts_the_wave_high(self):
        """Raising the gate reloads the PIT count, so the wave restarts with its high half. A low gate
        already holds the output high, so stopping in the low half and restarting makes no new edge."""
        self.play(1193, GATE | DATA, 4410 + 33)                 # 1 kHz, 22 samples per half: now in a low half
        held = self.play(1193, DATA, 100)                       # gate low: output held high
        x = self.play(1193, GATE | DATA, 18)                    # still inside the restarted high half
        self.assertGreater(x.min(), held[-1] - 0.05 * AMP)


if __name__ == '__main__':
    unittest.main()
