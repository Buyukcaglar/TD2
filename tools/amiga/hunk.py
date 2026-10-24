"""Amiga HUNK load files: parse the sections and relocations, and lay them out in one memory image.

Usage: python tools/amiga/hunk.py runs/amiga/duel [image.bin]   (prints the sections; writes the laid-out
memory, from address 0, with the overlay nodes, for Ghidra)

Overlays. duel's root is followed by HUNK_OVERLAY: a table that gives, for each overlay node, the file
offset of a load file of its own (HUNK_HEADER, its hunks, HUNK_BREAK). duel has one node, one code hunk
without relocations: it reaches the root A4-relative, and the root calls it through the overlay
manager's stubs (bsr.w to the manager, then a word with the node and a word with the offset in it).
load(..., overlays=True) lays the nodes out after the root from OVERLAY_BASE.
"""
import struct
import sys

HUNK_UNIT, HUNK_NAME, HUNK_CODE, HUNK_DATA, HUNK_BSS = 0x3E7, 0x3E8, 0x3E9, 0x3EA, 0x3EB
HUNK_RELOC32, HUNK_RELOC16, HUNK_RELOC8, HUNK_EXT, HUNK_SYMBOL = 0x3EC, 0x3ED, 0x3EE, 0x3EF, 0x3F0
HUNK_DEBUG, HUNK_END, HUNK_HEADER, HUNK_DREL32, HUNK_RELOC32SHORT = 0x3F1, 0x3F2, 0x3F3, 0x3F7, 0x3FC
HUNK_OVERLAY, HUNK_BREAK = 0x3F5, 0x3F6
KINDS = {HUNK_CODE: 'code', HUNK_DATA: 'data', HUNK_BSS: 'bss'}
OVERLAY_BASE = 0x2A000


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


def parse(blob, start=0):
    pos = start

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
    parse.overlay_at = None
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
            # The root (or a node) ends here; for the root, overlays() reads the table.
            parse.overlay_at = pos - 4 if kind == HUNK_OVERLAY else None
            break
        else:
            raise ValueError(f'unknown hunk {kind:#x} at {pos - 4:#x}')
    return sections


def overlays(blob):
    """The overlay nodes' sections, from the HUNK_OVERLAY table after the root: (node number, sections)."""
    parse(blob)
    at = parse.overlay_at
    if at is None:
        return []
    size = struct.unpack_from('>I', blob, at + 4)[0]
    table = struct.unpack_from(f'>{size + 1}I', blob, at + 8)
    # duel's table (Lattice's layout) is 1, the node's file offset, and three longs the manager
    # uses; the nodes are found by the longs that point at a HUNK_HEADER.
    nodes = []
    for offset in table:
        if 0 < offset < len(blob) - 4 and struct.unpack_from('>I', blob, offset)[0] == HUNK_HEADER:
            nodes.append((len(nodes) + 1, parse(blob, offset)))
    return nodes


def load(blob, base=0x10000, align=0x10, overlays_too=False):
    """Lays the sections out from base, applies the relocations, returns (memory bytes, sections).
    The memory starts at address 0 so addresses index it directly. With overlays_too, the overlay
    nodes' sections follow from OVERLAY_BASE (numbered after the root's)."""
    sections = parse(blob)
    addr = base
    for s in sections:
        s.base = addr
        addr = (addr + s.size + 8 + align - 1) & ~(align - 1)
    if overlays_too:
        root = len(sections)
        addr = max(addr, OVERLAY_BASE)
        for _, node in overlays(blob):
            for s in node:
                s.base = addr
                addr = (addr + s.size + 8 + align - 1) & ~(align - 1)
                # a node's relocations name hunks by the header's numbers, which count on from the root
                sections.append(s)
        assert all(s.index >= root for s in sections[root:])
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
    mem, sections = load(blob, overlays_too=True)
    for s in sections:
        print(f'{s.base:06x}', s)
        for name, off in s.symbols[:20]:
            print(f'    {name} {s.base + off:06x}')
    if len(sys.argv) > 2:
        open(sys.argv[2], 'wb').write(mem)
