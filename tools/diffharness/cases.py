"""Test cases for the differential harness: which original function, which port adapter, and how
to randomise its inputs. Inputs are the DS globals the function reads, its register arguments and,
for the unpackers, real packed game files placed in the heap the way unpack_file does it."""
from __future__ import annotations

import os
import random
from pathlib import Path

from .harness import (DGROUP, HEAP_BOTTOM, HEAP_TOP, MEM, ROOT, Case, Harness, Spec, default_regs, lin,
                      load_symbols)

S = load_symbols()
GAME_DIRS = [ROOT / 'runs/game', ROOT / 'analysis/inputs/dos']


def ds_put(mem: bytearray, name_or_off, value: int, size: int = 1):
    off = S[name_or_off] if isinstance(name_or_off, str) else name_or_off
    a = lin(DGROUP, off)
    mem[a:a + size] = (value & ((1 << 8 * size) - 1)).to_bytes(size, 'little')


def ds_put_bytes(mem: bytearray, name: str, data: bytes):
    a = lin(DGROUP, S[name])
    mem[a:a + len(data)] = data


def edgy16(rng: random.Random, edges=(0, 1, 0x7FFF, 0x8000, 0xFFFF)) -> int:
    """A random word, with a bias towards boundary values."""
    return rng.choice(edges) if rng.random() < 0.15 else rng.randrange(0x10000)


def edgy8(rng: random.Random) -> int:
    return rng.choice((0, 1, 0x7F, 0x80, 0xFF)) if rng.random() < 0.2 else rng.randrange(0x100)


def gear(rng: random.Random) -> int:
    return rng.choice((0, 0, 1, 2, 3, 4, 5, rng.randrange(256)))


def forever(make):
    def cases(rng, base):
        while True:
            mem = bytearray(base)
            regs = default_regs(rng)
            label = make(rng, mem, regs)
            yield Case(mem, regs, label=label or '')
    return cases


# ---------------------------------------------------------------------------------------------- simulation

def _rand8(rng, mem, regs):
    ds_put(mem, 'DS_rand8_idx', edgy16(rng), 2)
    ds_put_bytes(mem, 'DS_rand8_tab', bytes(edgy8(rng) for _ in range(256)))


def _curve_sum(rng, mem, regs):
    ds_put_bytes(mem, 'DS_curve_ring', bytes(edgy8(rng) for _ in range(8)))
    ds_put(mem, 'DS_speed', edgy16(rng), 2)


def _free_rev(rng, mem, regs):
    ds_put(mem, 'DS_gear', gear(rng))
    ds_put(mem, 'DS_throttle', edgy8(rng))
    ds_put(mem, 'DS_rpm', rng.choice((rng.randrange(700, 1300), edgy16(rng))), 2)


def _engine_state(rng, mem):
    ds_put(mem, 'DS_gear', gear(rng))
    ds_put(mem, 'DS_gear_ratio', edgy16(rng), 2)
    ds_put(mem, 'DS_speed', edgy16(rng), 2)
    ds_put(mem, 'DS_rpm', edgy16(rng), 2)


def _drag_apply(rng, mem, regs):
    _engine_state(rng, mem)
    ds_put(mem, 'DS_throttle', rng.choice((0xFF, edgy8(rng), edgy8(rng))))
    regs['dx'] = rng.choice((0, edgy16(rng), rng.randrange(0x200)))


def _brake(rng, mem, regs):
    _engine_state(rng, mem)
    regs['dx'] = rng.choice((0x640, 0x320, 0x190, edgy16(rng)))


def _update_rpm(rng, mem, regs):
    _engine_state(rng, mem)


def _overrev_check(rng, mem, regs):
    redline = rng.randrange(4000, 8000)
    ds_put(mem, 'DS_car_rpm_redline', rng.choice((redline, edgy16(rng))), 2)
    ds_put(mem, 'DS_car_rpm_max', rng.choice((redline + rng.randrange(0, 1500), edgy16(rng))), 2)
    ds_put(mem, 'DS_rpm', rng.choice((redline + rng.randrange(-200, 1800), edgy16(rng))), 2)
    ds_put(mem, 'DS_overrev_ticks', rng.choice((0x1D, 0x1E, 0, rng.randrange(0x20), edgy8(rng))))
    ds_put(mem, 'DS_run_state', 0)


# ---------------------------------------------------------------------------------------------- unpackers

def game_dir() -> Path:
    for d in GAME_DIRS:
        if (d / 'TD2EGA.EXE').exists():
            return d
    raise FileNotFoundError('no game files: run run.ps1 once to create runs/game')


def packed_files(kind: int) -> list[Path]:
    """Game files whose first unpack pass is RLE (kind 1) or Huffman (kind 2), per FORMATS.md."""
    out = []
    for name in sorted(os.listdir(game_dir())):
        p = game_dir() / name
        head = p.read_bytes()[:8]
        if len(head) < 8 or p.suffix.upper() not in ('.PES', '.PCS', '.DAT'):
            continue
        t = head[0]
        first = head[4] if t & 0x80 else t
        if (t in (1, 2) or t == 0x82) and first == kind:
            out.append(p)
        elif kind == 1 and t == 0x82:
            out.append(p)          # second pass is RLE: the harness runs the Huffman pass first
    return out


def each_file(rng: random.Random, files: list[Path]):
    """Every file once in random order, then again in a new order, forever."""
    while True:
        order = files[:]
        rng.shuffle(order)
        yield from order


def paras(n: int) -> int:
    return (n >> 4) + (n & 15 != 0)


def place_packed(rng: random.Random, mem: bytearray, data: bytes) -> tuple[int, int, int]:
    """Lays out a packed file as unpack_file does: a block of total paragraphs at blk_seg, the file
    loaded at its top. The block starts out full of random bytes. Returns (blk_seg, total, in_seg)."""
    total = paras(int.from_bytes(data[1:4], 'little')) + 1
    room = HEAP_TOP - HEAP_BOTTOM - total
    blk = HEAP_BOTTOM + rng.randrange(max(1, room))
    mem[blk * 16:(blk + total) * 16] = rng.randbytes(total * 16)
    in_seg = blk + total - paras(len(data))
    mem[in_seg * 16:in_seg * 16 + len(data)] = data
    return blk, total, in_seg


def _huff_cases(rng, base):
    for f in each_file(rng, packed_files(2)):
        data = f.read_bytes()
        mem = bytearray(base)
        blk, total, in_seg = place_packed(rng, mem, data)
        in_off = 4 if data[0] & 0x80 else 0
        yield Case(mem, default_regs(rng), [in_off, in_seg, 0, blk, total], f.name)


def _rle_cases(harness_holder):
    def cases(rng, base):
        for f in each_file(rng, packed_files(1)):
            data = f.read_bytes()
            mem = bytearray(base)
            blk, total, in_seg = place_packed(rng, mem, data)
            if data[0] == 0x82:
                # First pass: the original Huffman decoder, then the move-up that unpack_file does.
                h = harness_holder[0]
                first = Case(mem, default_regs(rng), [4, in_seg, 0, blk, total])
                orig, _, _ = h.call(HUFF, first)
                if orig.error:
                    raise RuntimeError(f'{f.name}: Huffman pass failed: {orig.error}')
                size = orig.regs['dx'] << 16 | orig.regs['ax']
                n = paras(size)
                nseg = blk + total - n
                mem = bytearray(orig.mem)
                mem[nseg * 16:(nseg + n) * 16] = mem[blk * 16:(blk + n) * 16]
                in_seg, in_off = nseg, 0
                label = f.name + ' (pass 2)'
            else:
                in_off, label = 0, f.name
            yield Case(mem, default_regs(rng), [in_off, in_seg, 0, blk, total], label)
    return cases


# ---------------------------------------------------------------------------------------------- the list

HARNESS: list = [None]      # the running Harness, for cases that need the original to prepare inputs

# The RLE cases use HUFF to run the first pass of 0x82 files.
HUFF = Spec('huff_decode', '06c9:7c16', True, ['ax', 'dx'], _huff_cases,
            'Huffman pass of every packed PES/PCS/DAT file, random heap placement')

SPECS = [
    Spec('rand8', '06c9:780e', True, ['ax'], forever(_rand8), 'random ring cursor and table'),
    Spec('curve_sum', '06c9:448a', False, [], forever(_curve_sum), 'random curve ring and speed'),
    Spec('free_rev', '06c9:4588', False, [], forever(_free_rev), 'gear, throttle, rpm'),
    Spec('drag_apply', '06c9:45bf', False, [], forever(_drag_apply), 'force in DX, throttle FFh path to brake'),
    Spec('brake', '06c9:45fc', False, [], forever(_brake), 'amount in DX, then update_rpm'),
    Spec('update_rpm', '06c9:4612', False, ['cx', 'dx'], forever(_update_rpm), 'CX old rpm, DX new rpm'),
    Spec('overrev_check', '06c9:4639', False, [], forever(_overrev_check), 'redline counter, blown engine'),
    Spec('rle_decode', '06c9:6b02', True, ['ax', 'dx'], _rle_cases(HARNESS),
         'EC_ PCS files directly, other files after their original Huffman pass'),
    HUFF,
]


def bind(harness: Harness):
    HARNESS[0] = harness
