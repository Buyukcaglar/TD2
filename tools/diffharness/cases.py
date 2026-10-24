"""Test cases for the differential harness: which original function, which port adapter, and how
to randomise its inputs. Inputs are the DS globals the function reads, its register arguments and,
for the unpackers, real packed game files placed in the heap the way unpack_file does it."""
from __future__ import annotations

import os
import random
import re
from pathlib import Path

from .harness import (DGROUP, HEAP_BOTTOM, HEAP_TOP, MEM, ROOT, Case, Harness, Spec, default_regs, lin,
                      load_symbols)

S = load_symbols()


def _sim_aliases():
    """Names the port's sim.h defines on top of symbols.h, e.g. DS_region_flags = DS_start_flags."""
    text = (ROOT / 'port/td2/td2port/src/game/sim.h').read_text()
    for name, base, plus in re.findall(r'^#define\s+(DS_\w+)\s+\(?(DS_\w+)(?:\s*\+\s*(\d+))?\)?', text, re.M):
        if base in S and name not in S:
            S[name] = S[base] + int(plus or 0)


_sim_aliases()
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


def load_car(rng: random.Random, mem: bytearray):
    """A real car record: 0x34F bytes of a car .BIN at DS:23A6, as the stage loader copies it."""
    cars = [p for p in sorted(game_dir().glob('*.BIN')) if p.stat().st_size >= 0x34F and not p.stem.endswith('O')]
    ds_put_bytes(mem, 'DS_car', rng.choice(cars).read_bytes()[:0x34F])


def stale_bp(rng: random.Random) -> int:
    """BP values the sim leaves behind: ring slots, short zone lengths, rpm, road pointers."""
    return rng.choice((rng.randrange(0x14), rng.randrange(0x80), 0x13, 0x14,
                       rng.randrange(800, 8000), 0x3B33 + rng.randrange(4000), rng.randrange(0x10000)))


# ---------------------------------------------------------------------------------------------- road edges and roadside

def _roadside_hit(rng, mem, regs):
    rc = edgy16(rng)
    ds_put(mem, 'DS_ring_counter', rc, 2)
    slot = rc & 0x7F
    t = rng.choice((rng.randrange(0x80, 0x100), rng.randrange(0x50), rng.randrange(0x1E, 0x50),
                    rng.randrange(0x50, 0x80), rng.randrange(0x50, 0x80)))
    ds_put(mem, S['DS_roadside_type'] + slot, t)
    side = rng.choice((rng.randrange(-7, 8), edgy8(rng) - 256 if rng.random() < 0.1 else 3))
    ds_put(mem, S['DS_roadside_side'] + slot, side & 0xFF)
    if t < 0x50:
        ds_put(mem, S['DS_scenery_sprites'] + 4 * t, rng.choice((0, 0, rng.randrange(1, 0x10000))), 2)
    sgn = rng.choice((0, HEAP_BOTTOM + 0x100))
    ds_put(mem, 'DS_sgn_seg', sgn, 2)
    if sgn:
        a = sgn * 16
        mem[a:a + 0x10000] = rng.randbytes(0x10000)
        if rng.random() < 0.2:                           # no such sign
            q = (t - 0x1E) & 0xFF
            ix = ((q % 5) << 8 | q // 5) * 2 & 0xFFFF
            mem[a + ix:a + ix + 2] = b'\0\0'
    flags = edgy8(rng)
    ds_put(mem, 'DS_region_flags', flags)
    ds_put(mem, 'DS_median', rng.choice((0, 1)))
    x = side * 50 if side < 128 else 0
    x = x + 500 if x >= 0 else x - 500
    left = x - rng.randrange(-200, 400)
    ds_put(mem, 'DS_car_left', left, 2)
    ds_put(mem, 'DS_car_right', left + 0xB4, 2)
    ds_put(mem, 'DS_run_state', 0)
    ds_put(mem, 'DS_speed', edgy16(rng), 2)
    ds_put(mem, 'DS_gear', gear(rng))
    regs['bp'] = stale_bp(rng)


def _obj_place_roadside(rng, mem, regs):
    ds_put(mem, 'DS_ring_counter', edgy16(rng), 2)
    regs['bx'] = rng.randrange(0x1C, 0x30) * 2
    regs['bp'] = stale_bp(rng)


def _road_edges(rng, mem, regs):
    load_car(rng, mem)
    flags = rng.choice((0, 0, 1, edgy8(rng)))            # 0 / 1: plain road, the right-side zone path
    ds_put(mem, 'DS_region_flags', flags)
    right = rng.random() < 0.8
    edge = (400 if flags & 0x80 else 900 if flags & 1 else 500) * (1 if right else -1)
    centre = edge + rng.randrange(-300, 300)
    ds_put(mem, 'DS_car_centre', centre, 2)
    ds_put(mem, 'DS_car_left', centre - 0x5A, 2)
    ds_put(mem, 'DS_car_right', centre + 0x5A, 2)
    unit = rng.randrange(2000)
    ds_put(mem, 'DS_player_pos', 0x3B33 + unit, 2)
    zones, at = [], max(1, unit - rng.randrange(300))
    for _ in range(rng.randrange(0, 5)):
        length = rng.choice((rng.randrange(1, 0x14), rng.randrange(1, 400)))
        zones.append((at, at + length, rng.randrange(-100, 100), rng.randrange(-100, 100)))
        at += length + rng.randrange(0, 100)
    data = b''.join(v.to_bytes(2, 'little', signed=v < 0) for z in zones for v in z) + bytes(8)
    ds_put_bytes(mem, 'DS_right_zones', data)
    ds_put(mem, 'DS_speed', edgy16(rng), 2)
    ds_put(mem, 'DS_gear', gear(rng))
    ds_put(mem, 'DS_gear_ratio', edgy16(rng), 2)
    ds_put(mem, 'DS_run_state', 0)
    regs['bp'] = stale_bp(rng)


def _decode_controls(rng, mem, regs):
    load_car(rng, mem)
    neutral_tap = rng.random() < 0.4
    for name in ('DS_knob_anim', 'DS_fire_held', 'DS_shift_latch', 'DS_gearbox_timer', 'DS_engine_damage',
                 'DS_steer_in', 'DS_throttle', 'DS_grind_timer'):
        ds_put(mem, name, rng.choice((0, 0, 1, edgy8(rng))))
    ds_put(mem, 'DS_input', rng.randrange(0x40))         # joystick directions and fire
    ds_put(mem, 'DS_gear', rng.randrange(0, 7))
    ds_put(mem, 'DS_finished', rng.choice((0, 0, 0, 1)))
    ds_put(mem, 'DS_auto_trans', rng.choice((0, 1)))
    ds_put(mem, 'DS_gate_mode', rng.choice((0, 1)))
    ds_put(mem, 'DS_clock_started', rng.choice((0, 1)))
    ds_put(mem, 'DS_demo_mode', rng.choice((0, 0, 1)), 2)
    ds_put(mem, 'DS_rpm', rng.choice((rng.randrange(800, 8000), edgy16(rng))), 2)
    ds_put(mem, 'DS_speed', edgy16(rng), 2)
    ds_put(mem, 'DS_idle_ticks', edgy16(rng), 2)
    for name in ('DS_knob_x', 'DS_knob_y', 'DS_knob_target_x', 'DS_knob_target_y'):
        ds_put(mem, name, rng.randrange(-40, 40), 2)
    ds_put(mem, 'DS_run_state', 0)
    ds_put(mem, 'DS_gear_ratio', rng.choice((edgy16(rng), rng.randrange(0x4000, 0x10000))), 2)
    regs['bp'] = stale_bp(rng)
    regs['cx'] = rng.choice((rng.randrange(800, 8000), rng.randrange(0x30, 0x70), 0xFA0, edgy16(rng)))
    if neutral_tap:                                      # fire released in neutral without a shift
        ds_put(mem, 'DS_gear', 0)
        ds_put(mem, 'DS_knob_anim', 0)
        ds_put(mem, 'DS_fire_held', rng.choice((1, 1, edgy8(rng) or 1)))
        ds_put(mem, 'DS_input', rng.randrange(0x10))
        ds_put(mem, 'DS_engine_damage', rng.choice((0, 0, edgy8(rng))))
        ds_put(mem, 'DS_grind_timer', 0)


def _sound_tick(rng, mem, regs):
    for name in ('DS_rpm', 'DS_rpm_display', 'DS_siren_pitch', 'DS_clock_seconds', 'DS_tick_count10'):
        ds_put(mem, name, edgy16(rng), 2)
    for name in ('DS_sound_frame', 'DS_siren_on', 'DS_siren_dir', 'DS_radar_beep', 'DS_grind_timer',
                 'DS_skidding'):
        ds_put(mem, name, rng.choice((0, 0, 1, edgy8(rng))))
    ds_put(mem, 'DS_div_100hz', rng.choice((1, 1, rng.randrange(256))))


# ---------------------------------------------------------------------------------------------- traffic

DAT_BASE, DAT_SIZE = 0x346A, 0x1E5E          # a stage .DAT unpacks to an image of DS:346A..52C7
ROAD0 = 0x3B51
_stages: dict = {}


def stage_image(name: str) -> bytes:
    """A stage .DAT unpacked by the original's own Huffman and RLE passes (cached)."""
    if name not in _stages:
        h, rng = HARNESS[0], random.Random(name)
        data = (game_dir() / name).read_bytes()
        mem = bytearray(h.base)
        blk, total, in_seg = place_packed(rng, mem, data)
        orig, _, _ = h.call(HUFF, Case(mem, default_regs(rng), [4, in_seg, 0, blk, total]))
        n = paras(orig.regs['dx'] << 16 | orig.regs['ax'])
        nseg = blk + total - n
        mem = bytearray(orig.mem)
        mem[nseg * 16:(nseg + n) * 16] = mem[blk * 16:(blk + n) * 16]
        rle = next(sp for sp in SPECS if sp.name == 'rle_decode')
        orig, _, _ = h.call(rle, Case(mem, default_regs(rng), [0, nseg, 0, blk, total]))
        if orig.error:
            raise RuntimeError(f'{name}: {orig.error}')
        _stages[name] = orig.mem[blk * 16:blk * 16 + DAT_SIZE]
    return _stages[name]


def load_stage(rng: random.Random, mem: bytearray) -> tuple[int, int, int]:
    """A real stage with its traffic lists set up as at the start of a stage (prepare_traffic_lists
    without the random drops, sim_stage_start's stage end). Returns (units, n_onc8, n_same8)."""
    name = rng.choice(sorted(p.name for p in game_dir().glob('*.DAT') if p.read_bytes()[:1] == b'\x82'))
    a = lin(DGROUP, DAT_BASE)
    mem[a:a + DAT_SIZE] = stage_image(name)
    units = int.from_bytes(mem[lin(DGROUP, S['DS_dat_road_units']):][:2], 'little')
    counts = []
    for base, oncoming in ((S['DS_oncoming'], True), (S['DS_same_dir'], False)):
        si = 0
        while mem[lin(DGROUP, base + si)] != 0 and si < 0x190:
            e = lin(DGROUP, base + si)
            raw = int.from_bytes(mem[e + 2:e + 4], 'little')
            mem[e + 2:e + 4] = (raw * units // 1000 + ROAD0).to_bytes(2, 'little')
            if not oncoming:
                mem[e] = (mem[e] + 4) & 0xFF
            mem[e + 6:e + 8] = (0xFF38 if oncoming else 0xC8).to_bytes(2, 'little')
            si += 8
        counts.append(si)
    ds_put(mem, 'DS_oncoming_count8', counts[0], 2)
    ds_put(mem, 'DS_same_count8', counts[1], 2)
    end = lin(DGROUP, S['DS_stage_end'])
    mem[end:end + 2] = ((int.from_bytes(mem[end:end + 2], 'little') + 0x3B33) & 0xFFFF).to_bytes(2, 'little')
    return units, counts[0], counts[1]


def road_pos(rng, units):
    return ROAD0 + rng.randrange(units)


def _traffic_state(rng, mem, scatter: bool):
    """Stage, lists, drivers. scatter moves the cars to random places, as after a while of driving."""
    units, n_onc, n_same = load_stage(rng, mem)
    if scatter:
        for base, n in ((S['DS_oncoming'], n_onc), (S['DS_same_dir'], n_same)):
            for si in range(0, n, 8):
                ds_put(mem, base + si + 2, road_pos(rng, units), 2)
                ds_put(mem, base + si + 4, rng.randrange(0x10000), 2)
                ds_put(mem, base + si + 6, rng.randrange(-700, 700), 2)
    for drv in ('player', 'opp', 'cop'):
        ds_put(mem, f'DS_{drv}_sub', rng.randrange(0x10000), 2)
        ds_put(mem, f'DS_{drv}_pos', road_pos(rng, units), 2)
    ds_put(mem, 'DS_cop_pos', rng.choice((0, road_pos(rng, units))), 2)
    ds_put(mem, 'DS_car_centre', rng.randrange(-700, 700), 2)
    ds_put(mem, 'DS_opp_x', rng.randrange(-700, 700), 2)
    ds_put(mem, 'DS_cop_x', rng.randrange(-700, 700), 2)
    for name, n in (('DS_onc_next', n_onc), ('DS_same_next', n_same), ('DS_opp_onc_next', n_onc),
                    ('DS_opp_same_next', n_same), ('DS_cop_onc_next', n_onc), ('DS_cop_same_next', n_same)):
        ds_put(mem, name, 8 * rng.randrange(n // 8), 2)
    ds_put(mem, 'DS_opp_enabled', rng.choice((0, 1, 1)))
    ds_put(mem, 'DS_cop_active', rng.choice((0, 0, 1)))
    ds_put(mem, 'DS_cop_state', rng.choice((0, 0, 1, 7, 8, rng.randrange(9))))
    ds_put(mem, 'DS_traffic_speed', rng.choice((0x60, 0x80, 0xA0, rng.randrange(0x200))), 2)
    ds_put(mem, 'DS_median', rng.choice((0, 1)))
    for name in ('DS_opp_pass_mode', 'DS_cop_force_meet', 'DS_opp_crash_timer'):
        ds_put(mem, name, rng.choice((0, 0, 1, edgy8(rng))))
    for name in ('DS_speed', 'DS_opp_speed', 'DS_cop_speed'):
        ds_put(mem, name, edgy16(rng), 2)
    for name in ('DS_rel_player_opp', 'DS_rel_player_cop', 'DS_rel_opp_cop'):
        ds_put(mem, name, rng.choice((0xFFFF, 0, 1, edgy16(rng))), 2)
    ds_put(mem, 'DS_run_state', 0)
    return units, n_onc, n_same


def _traffic(rng, mem, regs):
    _traffic_state(rng, mem, rng.random() < 0.7)
    # Often put the next car right at a driver, so meetings, crashes and police starts happen.
    for drv, x_name, lists in (('player', 'DS_car_centre', (('DS_onc_next', 'DS_oncoming'), ('DS_same_next', 'DS_same_dir'))),
                               ('opp', 'DS_opp_x', (('DS_opp_onc_next', 'DS_oncoming'), ('DS_opp_same_next', 'DS_same_dir')))):
        for next_name, base_name in lists:
            if rng.random() < 0.5:
                continue
            e = S[base_name] + int.from_bytes(mem[lin(DGROUP, S[next_name]):][:2], 'little')
            pos = int.from_bytes(mem[lin(DGROUP, S[f'DS_{drv}_pos']):][:2], 'little')
            ds_put(mem, e + 2, pos - rng.randrange(0, 5), 2)
            ds_put(mem, e + 4, rng.randrange(0x10000), 2)
            x = int.from_bytes(mem[lin(DGROUP, S[x_name]):][:2], 'little', signed=True)
            ds_put(mem, e + 6, x + rng.randrange(-250, 250), 2)
            if drv == 'player' and base_name == 'DS_oncoming' and rng.random() < 0.5:
                ds_put(mem, e, 4)                         # a police car
                ds_put(mem, 'DS_cop_pos', 0, 2)
                ds_put(mem, 'DS_speed', rng.randrange(0x3000, 0x8000), 2)


def _pass_collisions(rng, mem, regs):
    _, _, n_same = _traffic_state(rng, mem, True)
    regs['cx'] = n_same                                  # what traffic() leaves (see the traffic case)


def _traffic_resync(rng, mem, regs):
    _traffic_state(rng, mem, rng.random() < 0.7)


def _nearest_ahead(rng, mem, regs):
    units, n_onc, n_same = _traffic_state(rng, mem, rng.random() < 0.7)
    oncoming = rng.random() < 0.5
    regs['si'] = S['DS_oncoming'] if oncoming else S['DS_same_dir']
    regs['cx'] = n_onc if oncoming else n_same
    regs['ax'] = rng.randrange(0x10000)
    regs['dx'] = road_pos(rng, units)                   # DI stays random: the original never sets it


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
    Spec('roadside_hit', '06c9:4c85', False, ['bp'], forever(_roadside_hit),
         'scenery and billboards, stale BP (crash test)'),
    Spec('obj_place_roadside', '06c9:499a', False, ['bp'], forever(_obj_place_roadside),
         'objects 1Ch..2Fh, BP = ring slot'),
    Spec('road_edges', '06c9:4b9a', False, ['bp'], forever(_road_edges), 'walls, drop-offs, right-side zones'),
    Spec('decode_controls', '06c9:4281', False, ['bp'], forever(_decode_controls),
         'real car records, joystick, gears, fire tapped in neutral; BP = rpm'),
    Spec('sound_tick', '06c9:412c', False, ['cx'], forever(_sound_tick), 'engine, siren, grind tones; CX = rpm'),
    Spec('traffic', '06c9:4d3f', False, ['cx'], forever(_traffic),
         'real stage traffic; CX left for pass_collisions = same_count8'),
    Spec('pass_collisions', '06c9:595f', False, [], forever(_pass_collisions),
         'player, opponent and police passing each other'),
    Spec('traffic_resync', '06c9:5ada', True, [], forever(_traffic_resync), 'lists cleared around the drivers'),
    Spec('nearest_ahead', '06c9:5c30', False, ['si'], forever(_nearest_ahead),
         'real stage traffic, DI random (never used)'),
    Spec('rle_decode', '06c9:6b02', True, ['ax', 'dx'], _rle_cases(HARNESS),
         'EC_ PCS files directly, other files after their original Huffman pass'),
    HUFF,
]


def bind(harness: Harness):
    HARNESS[0] = harness
