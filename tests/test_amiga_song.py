"""The Amiga music and effect player in C (amiga/song.c) against the original 68000 code in sfx/song.

Both play the same script: the commands of the player's entry point, CIA timer ticks (SongInt) and the
audio interrupts (SongIntHandler) a small Paula timing model derives from the original's own register
writes. Every custom chip and CIA write must be the same, in the same order.

Needs the unpacked Amiga game in runs/amiga and build/td2diff.dll; skipped without them.
"""
import ctypes
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'analysis/tools/python'), str(ROOT / 'tools/amiga')]
SONG = ROOT / 'runs/amiga/sfx/song'
DLL = ROOT / 'build/td2diff.dll'

import hunk  # noqa: E402

ENTRY, SONG_INT, SONG_INT_HANDLER, HANDLER_RTE = 0x10018, 0x102BE, 0x10860, 0x108C4
STOP = 0x0FFF0
CLOCK = 3579545          # Paula, NTSC (the player's own effect periods use this clock)
ECLOCK = 715909          # CIA


class Original:
    """sfx/song under Unicorn; custom chips and CIAs as plain memory with a write log."""

    def __init__(self, blob):
        import unicorn
        from unicorn import m68k_const as m
        self.u, self.m = unicorn, m
        self.mem, self.sections = hunk.load(blob)
        uc = unicorn.Uc(unicorn.UC_ARCH_M68K, unicorn.UC_MODE_BIG_ENDIAN)
        uc.ctl_set_cpu_model(m.UC_CPU_M68K_M68000)
        uc.mem_map(0, 0x80000)
        uc.mem_write(0, bytes(self.mem))
        uc.mem_map(0xBF0000, 0x10000)
        uc.mem_map(0xDFF000, 0x1000)
        self.log = []

        def on_write(uc_, access, addr, size, value, data):
            if addr >= 0xBF0000:
                self.log.append((addr, value & 0xFFFF if size > 1 else value & 0xFF, min(size, 2)))
                if size == 4:                       # a long write is two word cycles
                    self.log[-1] = (addr, (value >> 16) & 0xFFFF, 2)
                    self.log.append((addr + 2, value & 0xFFFF, 2))
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write, begin=0xBF0000, end=0xDFFFFF)
        self.uc = uc

    def run(self, pc, regs=(), until=STOP):
        uc, m = self.uc, self.m
        sp = 0x7FF00
        uc.mem_write(sp, struct.pack('>I', STOP))
        uc.reg_write(m.UC_M68K_REG_SR, 0x2700)      # first: changing S swaps A7
        uc.reg_write(m.UC_M68K_REG_A7, sp)
        for reg, v in regs:
            uc.reg_write(reg, v)
        uc.emu_start(pc, until, count=2_000_000)
        return uc.reg_read(m.UC_M68K_REG_D0) & 0xFFFFFFFF

    def call(self, cmd, a0=0, d1=0, d2=0, d3=0, d4=0):
        m = self.m
        if cmd == 100:
            return self.run(SONG_INT)
        if cmd == 101:
            self.uc.mem_write(0xDFF01E, struct.pack('>H', d1))
            return self.run(SONG_INT_HANDLER, until=HANDLER_RTE)   # Unicorn cannot run the RTE
        return self.run(ENTRY, [(m.UC_M68K_REG_D0, cmd), (m.UC_M68K_REG_A0, a0), (m.UC_M68K_REG_D1, d1),
                                (m.UC_M68K_REG_D2, d2), (m.UC_M68K_REG_D3, d3), (m.UC_M68K_REG_D4, d4)])

    def take_log(self):
        log, self.log = self.log, []
        return log


class Port:
    def __init__(self, blob):
        self.dll = ctypes.CDLL(str(DLL))
        self.dll.dh_song_call.restype = ctypes.c_uint32
        self.dll.dh_song_call.argtypes = [ctypes.c_int, ctypes.c_uint32] + [ctypes.c_uint16] * 4
        err = ctypes.create_string_buffer(256)
        if not self.dll.dh_song_load(blob, len(blob), err, 256):
            raise RuntimeError(err.value.decode())
        self.n = 8192
        self.a = (ctypes.c_uint32 * self.n)()
        self.v = (ctypes.c_uint16 * self.n)()
        self.s = (ctypes.c_uint16 * self.n)()

    def call(self, cmd, a0=0, d1=0, d2=0, d3=0, d4=0):
        return self.dll.dh_song_call(cmd, a0, d1, d2, d3, d4)

    def take_log(self):
        n = self.dll.dh_song_log(self.a, self.v, self.s, self.n)
        return [(self.a[i], self.v[i], self.s[i]) for i in range(n)]


class Paula:
    """When the audio interrupts come: a channel raises one when DMA starts it (it has latched LC and
    LEN) and at the start of every further block, LEN words at PER clocks per byte later."""

    def __init__(self):
        self.reg = [{'len': 0, 'per': 0x7C} for _ in range(4)]
        self.on = [False] * 4
        self.next = [None] * 4                      # time of the channel's next block start
        self.latch = 0xFFFF
        self.lo = self.hi = 0xFF

    def feed(self, log, now):
        for addr, value, size in log:
            if 0xDFF0A0 <= addr < 0xDFF0E0:
                ch, r = divmod(addr - 0xDFF0A0, 16)
                if r == 4:
                    self.reg[ch]['len'] = value or 0x10000
                elif r == 6:
                    self.reg[ch]['per'] = max(value, 124)
            elif addr == 0xDFF096:
                for ch in range(4):
                    if value & (1 << ch):
                        if value & 0x8000 and not self.on[ch]:
                            self.on[ch] = True
                            self.next[ch] = now
                        elif not value & 0x8000:
                            self.on[ch] = False
                            self.next[ch] = None
            elif addr == 0xBFE401:
                self.lo = value
            elif addr == 0xBFE501:
                self.hi = value
            elif addr == 0xBFEE01 and value & 0x10:
                self.latch = self.hi << 8 | self.lo

    def tick_seconds(self):
        return (self.latch + 1) / ECLOCK

    def due(self, until):
        """Interrupts before until, as (time, INTREQR bits), and moves each channel on a block."""
        out = []
        while True:
            pending = [(t, ch) for ch, t in enumerate(self.next) if t is not None and t < until]
            if not pending:
                return out
            t, ch = min(pending)
            bits = 0
            for c in range(4):
                if self.next[c] is not None and abs(self.next[c] - t) < 1e-9:
                    bits |= 0x80 << c
                    r = self.reg[c]
                    self.next[c] = t + r['len'] * 2 * r['per'] / CLOCK
            out.append((t, bits))


@unittest.skipUnless(SONG.exists() and DLL.exists(), 'needs runs/amiga and build/td2diff.dll')
class SongTest(unittest.TestCase):
    def play(self, script_ticks, events=None):
        blob = SONG.read_bytes()
        orig, port = Original(blob), Port(blob)
        paula = Paula()
        now = 0.0
        steps = 0

        def step(cmd, *args):
            nonlocal steps
            ro = orig.call(cmd, *args)
            rp = port.call(cmd, *args)
            lo, lp = orig.take_log(), port.take_log()
            self.assertEqual(lp, lo, f'register writes differ at step {steps} (command {cmd})')
            if cmd in (5, 9):
                self.assertEqual(rp & 0xFFFF, ro & 0xFFFF, f'result differs at step {steps}')
            paula.feed(lo, now)
            steps += 1
            return ro

        step(1)                                     # read the instruments
        step(2)                                     # the title song
        for tick in range(script_ticks):
            for c in (events or {}).get(tick, []):
                step(*c)
            step(100)
            end = now + paula.tick_seconds()
            for t, bits in paula.due(end):
                now = t
                step(101, 0, bits)
            now = end
        return steps

    def test_title_song_plays_the_same(self):
        steps = self.play(6000)                     # about two minutes at the song's tempo
        self.assertGreater(steps, 6000)

    def test_fade_pause_and_effects(self):
        mem, secs = hunk.load(SONG.read_bytes())
        voice = struct.unpack_from('>I', mem, 0x10F72 + 4)[0]          # an instrument's 8SVX as an effect
        form = struct.unpack_from('>I', mem, voice + 0x0A)[0]
        events = {
            300: [(7, form, 2, 40, 3, 0x80)],       # effect on channel 2, three repeats, music at half
            400: [(12, 0, 2, 8000, 50)],            # adjust its rate and volume
            420: [(9, 0, 2)],
            500: [(8, 0, 2)],
            700: [(10,)], 760: [(11,)],             # pause, resume
            900: [(7, form, 1, 64, 0xFFFF, 0x40)],  # a looping effect, then stop it
            1000: [(8, 0, 1)],
            1200: [(6, 0, 2)],                      # fade out
        }
        self.play(2000, events)


if __name__ == '__main__':
    unittest.main()
