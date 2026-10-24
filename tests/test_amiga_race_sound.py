"""The Amiga race sound driver in C (amiga/race_sound.c) against duel's own 68000 code.

Both run the same script of plays, stops, volume and period changes and ramps, with the vertical blank
server every frame and the audio interrupts a Paula timing model takes from the original's register
writes. Every custom chip write must be the same, in the same order.

Needs the unpacked Amiga game in runs/amiga and build/td2diff.dll; skipped without them.
"""
import ctypes
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'analysis/tools/python'), str(ROOT / 'tools/amiga'), str(ROOT / 'tests')]
AMIGA = ROOT / 'runs/amiga'
DLL = ROOT / 'build/td2diff.dll'

import hunk  # noqa: E402

A4 = 0x2957E
INIT, PLAY, PLAY_RAW, STOP, BUSY, SET, RAMP = 0x11F96, 0x120CC, 0x12072, 0x1218A, 0x121EA, 0x12202, 0x12250
VBLANK, AUDIO_INT, AUDIO_INT_RTE = 0x1231C, 0x1226E, 0x1231A
STUBS_TO_RTS = (0x21730, 0x218E0)   # the siren sweep the server calls first; the OS call in INIT
STOP_AT = 0x0FFF0
SAMPLES = {'Squeal': 0x40000, 'crash': 0x44000, 'siren': 0x4C000}


class Original:
    def __init__(self, stubs=STUBS_TO_RTS):
        import unicorn
        from unicorn import m68k_const as m
        self.m = m
        mem, _ = hunk.load((AMIGA / 'duel').read_bytes())
        mem = bytearray(mem) + bytearray(0x80000 - len(mem))
        for stub in stubs:
            mem[stub:stub + 2] = b'\x4e\x75'
        for name, at in SAMPLES.items():
            data = (AMIGA / 'sfx' / name).read_bytes()
            mem[at:at + len(data)] = data
        uc = unicorn.Uc(unicorn.UC_ARCH_M68K, unicorn.UC_MODE_BIG_ENDIAN)
        uc.ctl_set_cpu_model(m.UC_CPU_M68K_M68000)
        uc.mem_map(0, 0x80000)
        uc.mem_write(0, bytes(mem))
        uc.mem_map(0xDFF000, 0x1000)
        self.log = []

        def on_write(uc_, access, addr, size, value, data):
            if size == 4:
                self.log += [(addr, (value >> 16) & 0xFFFF, 2), (addr + 2, value & 0xFFFF, 2)]
            else:
                self.log.append((addr, value & 0xFFFF, size))
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write, begin=0xDFF000, end=0xDFFFFF)
        self.uc = uc

    def wr(self, addr, value, size):
        self.uc.mem_write(addr, (value & ((1 << 8 * size) - 1)).to_bytes(size, 'big'))

    def rd(self, addr, size):
        return int.from_bytes(self.uc.mem_read(addr, size), 'big')

    def call(self, pc, args=b'', until=STOP_AT):
        uc, m = self.uc, self.m
        sp = 0x7FF00
        uc.mem_write(sp, struct.pack('>I', STOP_AT) + args)
        uc.reg_write(m.UC_M68K_REG_SR, 0x2700)
        uc.reg_write(m.UC_M68K_REG_A7, sp)
        uc.reg_write(m.UC_M68K_REG_A4, A4)
        uc.emu_start(pc, until, count=1_000_000)
        return uc.reg_read(m.UC_M68K_REG_D0) & 0xFFFF

    def regs(self, intreqr, intenar):
        self.uc.mem_write(0xDFF01C, struct.pack('>HH', intenar, intreqr))

    def take_log(self):
        log, self.log = self.log, []
        return log


class Port:
    def __init__(self):
        self.dll = ctypes.CDLL(str(DLL))
        self.dll.dh_race_call.restype = ctypes.c_uint32
        self.dll.dh_race_call.argtypes = [ctypes.c_int] + [ctypes.c_uint32] * 6
        self.dll.dh_amiga_mem.restype = ctypes.c_void_p
        mem = (ctypes.c_uint8 * 0x80000).from_address(self.dll.dh_amiga_mem())
        for name, at in SAMPLES.items():
            data = (AMIGA / 'sfx' / name).read_bytes()
            mem[at:at + len(data)] = data
        self.n = 8192
        self.a = (ctypes.c_uint32 * self.n)()
        self.v = (ctypes.c_uint16 * self.n)()
        self.s = (ctypes.c_uint16 * self.n)()
        self.take_log()

    def call(self, cmd, *args):
        args = list(args) + [0] * (6 - len(args))
        return self.dll.dh_race_call(cmd, *args) & 0xFFFF

    def take_log(self):
        n = self.dll.dh_song_log(self.a, self.v, self.s, self.n)
        return [(self.a[i], self.v[i], self.s[i]) for i in range(n)]


class Paula:
    """When the audio interrupts come (as in test_amiga_song), and INTENA as the writes leave it."""

    def __init__(self):
        self.len = [0] * 4
        self.per = [0x7C] * 4
        self.on = [False] * 4
        self.next = [None] * 4
        self.intena = 0

    def feed(self, log, now):
        for addr, value, size in log:
            if 0xDFF0A0 <= addr < 0xDFF0E0:
                ch, r = divmod(addr - 0xDFF0A0, 16)
                if r == 4:
                    self.len[ch] = value or 0x10000
                elif r == 6:
                    self.per[ch] = max(value, 124)
            elif addr == 0xDFF096:
                for ch in range(4):
                    if value & (1 << ch):
                        if value & 0x8000 and not self.on[ch]:
                            self.on[ch], self.next[ch] = True, now
                        elif not value & 0x8000:
                            self.on[ch], self.next[ch] = False, None
            elif addr == 0xDFF09A:
                if value & 0x8000:
                    self.intena |= value & 0x7FFF
                else:
                    self.intena &= ~value & 0x7FFF

    def due(self, until):
        out = []
        while True:
            pending = [(t, c) for c, t in enumerate(self.next) if t is not None and t < until]
            if not pending:
                return out
            t, _ = min(pending)
            bits = 0
            for c in range(4):
                if self.next[c] is not None and abs(self.next[c] - t) < 1e-9:
                    bits |= 0x80 << c
                    self.next[c] = t + self.len[c] * 2 * self.per[c] / 3579545
            out.append((t, bits))


def w(*words):
    return b''.join(struct.pack('>H', x & 0xFFFF) for x in words)


def l(x):
    return struct.pack('>I', x & 0xFFFFFFFF)


@unittest.skipUnless((AMIGA / 'duel').exists() and DLL.exists(), 'needs runs/amiga and build/td2diff.dll')
class RaceSoundTest(unittest.TestCase):
    def test_driver_matches_the_original(self):
        orig, port, paula = Original(), Port(), Paula()
        squeal, crash, siren = SAMPLES['Squeal'], SAMPLES['crash'], SAMPLES['siren']
        squeal_len = struct.unpack('>I', (AMIGA / 'sfx/Squeal').read_bytes()[:4])[0]
        # frame -> list of (C command and arguments, original address and stack arguments)
        script = {
            0: [((0,), (INIT, b''))],
            2: [((2, crash, 3, 64), (PLAY_RAW, l(crash) + w(3, 64)))],
            5: [((1, squeal + 6, squeal_len, 1, 0x166, 0, 0xFFFF),
                 (PLAY, l(squeal + 6) + l(squeal_len) + w(1, 0x166, 0, 0xFFFF)))],
            6: [((6, 1, 63, 0x7000), (RAMP, w(1, 63) + l(0x7000)))],
            30: [((5, 1, 300, 0xFFFF), (SET, w(1, 300, -1))), ((5, 1, 0xFFFF, 20), (SET, w(1, -1, 20)))],
            40: [((2, siren, 2, 64), (PLAY_RAW, l(siren) + w(2, 64)))],
            45: [((4, 2), (BUSY, w(2)))],
            50: [((3, 1), (STOP, w(1)))],
            51: [((1, squeal + 6, squeal_len, 1, 0x200, 40, 2),
                  (PLAY, l(squeal + 6) + l(squeal_len) + w(1, 0x200, 40, 2)))],
            60: [((1, squeal + 6, squeal_len, 6, 0x180, 30, 1),
                  (PLAY, l(squeal + 6) + l(squeal_len) + w(6, 0x180, 30, 1)))],
            70: [((6, 1, 0, 0x20000), (RAMP, w(1, 0) + l(0x20000)))],
            100: [((2, crash, 0, 50), (PLAY_RAW, l(crash) + w(0, 50)))],
            120: [((3, 0), (STOP, w(0)))],
        }
        now, step = 0.0, 0
        starts = interrupts = 0

        def check(what):
            nonlocal step, starts
            lo, lp = orig.take_log(), port.take_log()
            self.assertEqual(lp, lo, f'register writes differ at step {step} ({what})')
            starts += sum(1 for a, v, s in lo if a == 0xDFF096 and v & 0x8000)
            paula.feed(lo, now)
            step += 1

        for frame in range(200):
            for (cargs, (pc, stack)) in script.get(frame, []):
                ro = orig.call(pc, stack)
                rp = port.call(*cargs)
                if cargs[0] == 4:
                    self.assertEqual(rp, ro & 0xFFFF)
                check(f'frame {frame} command {cargs[0]}')
            orig.regs(0, paula.intena)
            orig.call(VBLANK)
            port.call(100, paula.intena)
            check(f'frame {frame} vertical blank')
            end = now + 1 / 50
            for t, bits in paula.due(end):
                now = t
                orig.regs(bits, paula.intena)
                orig.call(AUDIO_INT, until=AUDIO_INT_RTE)
                port.call(101, bits, paula.intena)
                interrupts += 1
                check(f'frame {frame} audio interrupt {bits:#x}')
            now = end
        self.assertGreater(step, 220)
        self.assertGreaterEqual(starts, 6)          # samples really started
        self.assertGreater(interrupts, 20)


if __name__ == '__main__':
    unittest.main()
