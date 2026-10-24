"""Amiga HUNK load files: parse the sections and relocations, and lay them out in one memory image.

Usage: python tools/amiga/hunk.py runs/amiga/duel [image.bin]   (prints the sections; writes the laid-out
memory, from address 0, for Ghidra)
"""
import struct
import sys

HUNK_UNIT, HUNK_NAME, HUNK_CODE, HUNK_DATA, HUNK_BSS = 0x3E7, 0x3E8, 0x3E9, 0x3EA, 0x3EB
HUNK_RELOC32, HUNK_RELOC16, HUNK_RELOC8, HUNK_EXT, HUNK_SYMBOL = 0x3EC, 0x3ED, 0x3EE, 0x3EF, 0x3F0
HUNK_DEBUG, HUNK_END, HUNK_HEADER, HUNK_DREL32, HUNK_RELOC32SHORT = 0x3F1, 0x3F2, 0x3F3, 0x3F7, 0x3FC
HUNK_OVERLAY, HUNK_BREAK = 0x3F5, 0x3F6
KINDS = {HUNK_CODE: 'code', HUNK_DATA: 'data', HUNK_BSS: 'bss'}


class Section:
    def __init__(self, index, kind, size, memflags):
        self.index = index
        self.kind = kind
        self.size = size          # bytes in memory
        self.memflags = memflags  # 0 any, 1 chip, 2 fast
        self.data = b''
        self.relocs = {}          # target section -> list of offsets in this section
        self.symbols = []         # (name, offset)
        self.base = 0

    def __repr__(self):
        mem = ('any', 'chip', 'fast', 'ext')[self.memflags]
        nrel = sum(len(v) for v in self.relocs.values())
        return f'#{self.index} {self.kind:4} {self.size:6d} bytes ({len(self.data)} in file), {mem} memory, {nrel} relocations'


def parse(blob):
    pos = 0

    def long():
        nonlocal pos
        v = struct.unpack_from('>I', blob, pos)[0]
        pos += 4
        return v

    def word():
        nonlocal pos
        v = struct.unpack_from('>H', blob, pos)[0]
        pos += 2
        return v

    if long() != HUNK_HEADER:
        raise ValueError('not a HUNK load file')
    while long():                     # resident library names, none in practice
        pass
    count, first, last = long(), long(), long()
    sections = []
    for i in range(last - first + 1):
        v = long()
        flags = v >> 30
        if flags == 3:
            long()
        sections.append(Section(first + i, None, (v & 0x3FFFFFFF) * 4, flags))
    current = None
    index = 0
    while pos + 4 <= len(blob):
        kind = long() & 0x3FFFFFFF
        if kind in (HUNK_CODE, HUNK_DATA):
            n = long() & 0x3FFFFFFF
            current = sections[index]
            current.kind = KINDS[kind]
            current.data = blob[pos:pos + n * 4]
            pos += n * 4
        elif kind == HUNK_BSS:
            long()
            current = sections[index]
            current.kind = 'bss'
        elif kind == HUNK_RELOC32:
            while True:
                n = long()
                if not n:
                    break
                target = long()
                current.relocs.setdefault(target, []).extend(long() for _ in range(n))
        elif kind in (HUNK_RELOC32SHORT, HUNK_DREL32):
            while True:
                n = word()
                if not n:
                    break
                target = word()
                current.relocs.setdefault(target, []).extend(word() for _ in range(n))
            if pos & 2:
                pos += 2
        elif kind == HUNK_SYMBOL:
            while True:
                n = long()
                if not n:
                    break
                name = blob[pos:pos + n * 4].rstrip(b'\0').decode('latin-1')
                pos += n * 4
                current.symbols.append((name, long()))
        elif kind == HUNK_DEBUG:
            pos += long() * 4
        elif kind == HUNK_NAME:
            pos += long() * 4
        elif kind == HUNK_END:
            index += 1
        elif kind in (HUNK_OVERLAY, HUNK_BREAK):
            # An overlay table follows the root hunks; the overlay nodes are load files of their own,
            # at the offsets the table gives (see overlays()).
            break
        else:
            raise ValueError(f'unknown hunk {kind:#x} at {pos - 4:#x}')
    return sections


def load(blob, base=0x10000, align=0x10):
    """Lays the sections out from base, applies the relocations, returns (memory bytes, sections).
    The memory starts at address 0 so addresses index it directly."""
    sections = parse(blob)
    addr = base
    for s in sections:
        s.base = addr
        addr = (addr + s.size + 8 + align - 1) & ~(align - 1)
    mem = bytearray(addr)
    for s in sections:
        mem[s.base:s.base + len(s.data)] = s.data
    for s in sections:
        for target, offsets in s.relocs.items():
            for off in offsets:
                a = s.base + off
                v = struct.unpack_from('>I', mem, a)[0]
                struct.pack_into('>I', mem, a, (v + sections[target].base) & 0xFFFFFFFF)
    return mem, sections


if __name__ == '__main__':
    blob = open(sys.argv[1], 'rb').read()
    mem, sections = load(blob)
    for s in sections:
        print(f'{s.base:06x}', s)
        for name, off in s.symbols[:20]:
            print(f'    {name} {s.base + off:06x}')
    if len(sys.argv) > 2:
        open(sys.argv[2], 'wb').write(mem)
