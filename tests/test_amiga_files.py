"""The Amiga file readers against the Amiga game's own code, run under Unicorn.

Needs the unpacked Amiga game in runs/amiga (a copy of the user's archive); skipped without it.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'analysis/tools/python'), str(ROOT / 'tools/amiga')]
AMIGA = ROOT / 'runs/amiga'

import hunk  # noqa: E402
import rpck  # noqa: E402

UNPACK = 0x1E518          # duel's Rpck unpacker: (packed, packed length, destination)
RETURN = 0x0FFF0          # a stop address for the routine's rts


def run_68k(mem, entry, args, out_addr, out_len):
    import unicorn
    from unicorn import m68k_const as m
    uc = unicorn.Uc(unicorn.UC_ARCH_M68K, unicorn.UC_MODE_BIG_ENDIAN)
    uc.ctl_set_cpu_model(m.UC_CPU_M68K_M68000)
    size = (len(mem) + 0xFFFF) & ~0xFFFF
    uc.mem_map(0, size + 0x100000)
    uc.mem_write(0, bytes(mem))
    sp = size + 0xF0000
    stack = struct.pack('>I', RETURN) + b''.join(struct.pack('>I', a) for a in args)
    uc.mem_write(sp, stack)
    uc.reg_write(m.UC_M68K_REG_A7, sp)
    uc.emu_start(entry, RETURN, count=50_000_000)
    return bytes(uc.mem_read(out_addr, out_len))


@unittest.skipUnless((AMIGA / 'duel').exists(), 'no Amiga game in runs/amiga')
class RpckTest(unittest.TestCase):
    def test_every_packed_file_unpacks_as_the_game_does(self):
        mem, _ = hunk.load((AMIGA / 'duel').read_bytes())
        files = [p for p in sorted(AMIGA.rglob('*')) if p.is_file() and p.read_bytes()[:4] == rpck.MAGIC]
        self.assertGreater(len(files), 100)
        base = (len(mem) + 0xFFFF) & ~0xFFFF
        for p in files:
            data = p.read_bytes()
            size = struct.unpack_from('>I', data, 4)[0]
            src, dst = base, base + 0x40000
            work = bytearray(mem) + bytearray(dst + size + 16 - len(mem))
            work[src:src + len(data) - 8] = data[8:]
            got = run_68k(work, UNPACK, [src, len(data) - 8, dst], dst, size)
            self.assertEqual(rpck.read(data), got, p.relative_to(AMIGA))


if __name__ == '__main__':
    unittest.main()
