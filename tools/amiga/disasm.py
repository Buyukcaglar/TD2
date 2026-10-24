"""Disassembles part of an Amiga load file with Capstone's 68000 mode.

Usage: python tools/amiga/disasm.py runs/amiga/duel 1e600 1e700   (addresses as hunk.load lays them out)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import capstone  # noqa: E402
import hunk  # noqa: E402


def disassemble(mem, start, end):
    md = capstone.Cs(capstone.CS_ARCH_M68K, capstone.CS_MODE_BIG_ENDIAN | capstone.CS_MODE_M68K_000)
    pc = start
    while pc < end:
        got = False
        for insn in md.disasm(bytes(mem[pc:end]), pc):
            yield insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str
            pc = insn.address + insn.size
            got = True
        if pc < end:
            yield pc, mem[pc:pc + 2].hex(), 'dc.w', f'${mem[pc] << 8 | mem[pc + 1]:04x}'
            pc += 2
        elif not got:
            break


if __name__ == '__main__':
    mem, sections = hunk.load(open(sys.argv[1], 'rb').read())
    start, end = int(sys.argv[2], 16), int(sys.argv[3], 16)
    labels = {s.base + off: name for s in sections for name, off in s.symbols}
    for addr, raw, mn, ops in disassemble(mem, start, end):
        if addr in labels:
            print(f'{labels[addr]}:')
        for a, name in labels.items():                 # name the symbols an operand refers to
            ops = ops.replace(f'${a:x}', f'{name}')
        print(f'{addr:06x}  {raw:<20} {mn:8} {ops}')
