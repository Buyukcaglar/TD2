"""The Amiga race sound logic in C (amiga/race_logic.c) against duel's own 68000 code.

The original's routines run under Unicorn with its race driver, the C runs from td2diff.dll with the
C driver. Both get the same car state (written into duel's variables for the original), the same calls
and the vertical blank every frame, with the audio interrupts a Paula timing model takes from the
original's register writes. Every custom chip write must be the same, in the same order.

Needs the unpacked Amiga game in runs/amiga and build/td2diff.dll; skipped without them.
"""
import ctypes
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tests')]

import test_amiga_race_sound as drv  # noqa: E402

AMIGA, DLL = drv.AMIGA, drv.DLL
# Delay (dos.library) and WaitTOF (graphics.library) are OS calls: they become rts, as the OS call in
# the driver's init does. The siren sweep the vertical blank server calls first is kept.
STUBS = (0x218AA, 0x2199A, 0x218E0)
START, FADE, STEP, SQUEAL_OFF = 0x1D044, 0x1D0E2, 0x1D118, 0x1D206
RADAR, CRASH, SIREN_START, SIREN_STOP = 0x1CDE4, 0x1CE10, 0x1CE50, 0x1CEC2
SOUND_ON, CRASHED, SIREN_ON, GEAR, GEAR_OK = 0x22932, 0x289E2, 0x28A8E, 0x26292, 0x262DE
# RaceCar's fields: duel's address and size
FIELDS = [
    ('rpm', 0x261FA, 2), ('speed', 0x2619C, 4), ('throttle', 0x260F8, 2), ('in_gear', None, 1),
    ('engine_on', 0x26B38, 2), ('squeal_held', 0x262D2, 2), ('squeal_volume', 0x289D2, 2),
    ('pos', 0x25228, 4), ('cop_pos', 0x26178, 4), ('cop_speed', 0x26180, 4), ('bump', 0x262D8, 2),
    ('bump2', 0x277BA, 2), ('low_rev_turbo', None, 2), ('shift_squeal', 0x234EE, 2),
]
NAMES = [f[0] for f in FIELDS]
# the seven sample pointers in RaceSamples' order, the file and where both sides load it
SAMPLES = [
    (0x250F0, 'sfx/radar', 0x50000), (0x250FC, 'sfx/Squeal', drv.SAMPLES['Squeal']),
    (0x25100, 'sfx/Bump', 0x52000), (0x25104, 'sfx/crash', drv.SAMPLES['crash']),
    (0x25108, 'sfx/siren', drv.SAMPLES['siren']), (0x250F4, 'cars/f40engine', 0x54000),
    (0x250F8, 'cars/f40turbo', 0x56000),
]
LEAVE = 0x7FFFFFFF


class Port(drv.Port):
    def __init__(self):
        super().__init__()
        self.dll.dh_race_logic.restype = None
        self.dll.dh_race_logic.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int32),
                                           ctypes.POINTER(ctypes.c_int32), ctypes.c_uint32]
        self.mem = (ctypes.c_uint8 * 0x80000).from_address(self.dll.dh_amiga_mem())

    def logic(self, cmd, values, a=0):
        vals = [int(values.get(n, LEAVE)) for n in NAMES] + [at for _, _, at in SAMPLES]
        arr = (ctypes.c_int32 * len(vals))(*[ctypes.c_int32(v & 0xFFFFFFFF).value for v in vals])
        out = (ctypes.c_int32 * 2)()
        self.dll.dh_race_logic(cmd, arr, out, a)
        return out[0], out[1]


class Original(drv.Original):
    def __init__(self):
        super().__init__(stubs=STUBS)

    def set_car(self, values):
        for name, addr, size in FIELDS:
            if name not in values:
                continue
            v = int(values[name])
            if name == 'in_gear':
                self.wr(GEAR, 1, 2)
                self.wr(GEAR_OK + 1, 0xFF if v else 0, 1)
            elif name == 'low_rev_turbo':
                self.wr(0x25254, 0 if v else 1, 2)
            elif name in ('bump', 'bump2'):
                self.wr(addr, 0xFF00 if v else 0, 2)
            else:
                self.wr(addr, v, size)

    def car_out(self):
        return self.rd(0x289D2, 2), ctypes.c_int16(self.rd(0x234EE, 2)).value


def car_state(rng, frame):
    """A drive: rev up through the gears, brake, coast, and a police car closing and falling back."""
    t = frame / 60
    rpm = int(800 + (t * 1900) % 5800)
    mph = min(150, int(t * 14))
    throttle = 1 if (frame // 90) % 4 != 3 else (-1 if frame % 180 < 90 else 0)
    gap = int((300 - frame) * 0.7)
    return {
        'rpm': rpm, 'speed': (mph << 16) | rng.randrange(0x10000), 'throttle': throttle,
        'in_gear': (frame // 45) % 5 != 0, 'engine_on': frame < 420, 'squeal_held': (frame // 100) % 4 == 2,
        'squeal_volume': rng.choice([0, 0, 25, 40, 64]), 'pos': (0x3B51 << 16) + frame * 0x9000,
        'cop_pos': (0x3B51 << 16) + frame * 0x9000 - (gap << 16), 'cop_speed': (mph + rng.randint(-20, 20)) << 10,
        'low_rev_turbo': frame >= 330,
    }


@unittest.skipUnless((AMIGA / 'duel').exists() and DLL.exists(), 'needs runs/amiga and build/td2diff.dll')
class RaceLogicTest(unittest.TestCase):
    def test_logic_matches_the_original(self):
        orig, port, paula = Original(), Port(), drv.Paula()
        for ptr, name, at in SAMPLES:
            data = (AMIGA / name).read_bytes()
            orig.uc.mem_write(at, data)
            port.mem[at:at + len(data)] = data
            orig.wr(ptr, at, 4)
        orig.wr(SOUND_ON, 1, 2)
        orig.wr(CRASHED, 0, 2)
        orig.wr(SIREN_ON, 0, 2)
        rng = random.Random(7)
        events = {
            2: [('start', START, 1)], 20: [('radar', RADAR, 5)], 32: [('radar', RADAR, 5)],
            40: [('shift', 5)], 50: [('bump', 'bump')], 51: [('bump', 'bump2')], 70: [('siren', SIREN_START, 7)],
            100: [('radar', RADAR, 5)], 125: [('shift', 0xB)], 150: [('siren', SIREN_STOP, 8)],
            155: [('radar', RADAR, 5)], 170: [('off', SQUEAL_OFF, 4)], 190: [('bump', 'bump2')],
            200: [('siren', SIREN_START, 7)], 260: [('crash', CRASH, 6)], 265: [('radar', RADAR, 5)],
            270: [('siren', SIREN_START, 7)], 280: [('fade', FADE, 2)], 300: [('start', START, 1)],
            310: [('siren', SIREN_START, 7)], 360: [('shift', 20)],
        }
        now, step = 0.0, 0
        starts = 0
        writes = []

        def check(what):
            nonlocal step, starts
            lo, lp = orig.take_log(), port.take_log()
            self.assertEqual(lp, lo, f'register writes differ at step {step} ({what})')
            writes.extend(lo)
            starts += sum(1 for a, v, s in lo if a == 0xDFF096 and v & 0x8000)
            paula.feed(lo, now)
            step += 1

        orig.call(drv.INIT)
        port.call(0)
        port.logic(0, {})
        check('init')
        pending = {}                                # what the game sets for the next physics step
        for frame in range(450):
            car = car_state(rng, frame)
            for ev in events.get(frame, []):
                if ev[0] == 'shift':
                    pending['shift_squeal'] = ev[1]
                elif ev[0] == 'bump':
                    pending[ev[1]] = True
                else:
                    orig.set_car(car)
                    orig.call(ev[1])
                    port.logic(ev[2], car)
                    self.assertEqual(port.logic(99, {}), orig.car_out(), f'frame {frame} {ev[0]}')
                    check(f'frame {frame} {ev[0]}')
            if frame % 6 == 0:                      # the physics step, about 10 a second
                car.update(pending)
                pending.clear()
                orig.set_car(car)
                orig.call(STEP)
                port.logic(3, car)
                self.assertEqual(port.logic(99, {}), orig.car_out(), f'frame {frame} step')
                check(f'frame {frame} step')
            orig.regs(0, paula.intena)
            orig.set_car({k: car[k] for k in ('pos', 'cop_pos', 'cop_speed', 'speed')})
            orig.call(drv.VBLANK)
            port.logic(100, {k: car[k] for k in ('pos', 'cop_pos', 'cop_speed', 'speed')}, paula.intena)
            check(f'frame {frame} vertical blank')
            end = now + 1 / 60
            for t, bits in paula.due(end):
                now = t
                orig.regs(bits, paula.intena)
                orig.call(drv.AUDIO_INT, until=drv.AUDIO_INT_RTE)
                port.call(101, bits, paula.intena)
                check(f'frame {frame} audio interrupt {bits:#x}')
            now = end
        self.assertGreater(step, 600)
        self.assertGreaterEqual(starts, 10)
        period = {c: {v for a, v, _ in writes if a == 0xDFF0A6 + 16 * c} for c in range(4)}
        self.assertGreater(len(period[0]), 40)                  # the siren swept
        self.assertIn(0x18B, period[1])                         # the gear change squeal
        self.assertGreater(len(period[3]), 30)                  # the engine followed the rpm
        dma0 = sum(1 for a, v, _ in writes if a == 0xDFF096 and v & 0x8001 == 0x8001)
        self.assertGreaterEqual(dma0, 6)                        # radar, bumps, siren, crash


if __name__ == '__main__':
    unittest.main()
