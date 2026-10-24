"""Representative actual Kylofon C versus admitted original instructions.

The candidate C API has fixed DGROUP and host C frames. This comparison admits
disjoint original SS scratch only; it never transfers raw GPR/FLAGS/alias proof
from our separate recovery bus APIs. Inputs are synthetic and no game runs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))
sys.path.insert(0, str(ROOT / 'tools'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from validation.twenty_bit_bus import map_twenty_bit_ram

IMAGE_SHA = '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
MZ_SHA = '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2'
LOAD, DS, CS = 0x1000, 0x278f, 0x16c9
SIZE = 0x100000
RANGES = [(0x780e, 0x782b), (0x5d83, 0x5d9e), (0x6a17, 0x6a30),
          (0x448a, 0x44a6), (0x45bf, 0x4639), (0x5dfb, 0x5e1c),
          (0xba3c, 0xbac7), (0x6b02, 0x6d18), (0x7030, 0x7083)]
FAR = {0x780e, 0x5d83, 0x5d8d, 0x6a17, 0x6a28, 0x5dfb, 0xba3c, 0x6b02}


def require(test, message):
    if not test:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_word(data, address, value):
    data[address & 0xfffff] = value & 255
    data[(address + 1) & 0xfffff] = (value >> 8) & 255


def put(data, offset, value, width=2, segment=DS):
    address = segment * 16 + offset
    for i in range(width):
        data[(address + i) & 0xfffff] = (value >> (8 * i)) & 255


class Native:
    def __init__(self, path):
        self.path = path.resolve()
        require(self.path.is_relative_to(ROOT / 'analysis'), 'Use a private analysis library')
        self.dll = C.CDLL(str(self.path))
        self.memory = self.dll.td2r03_memory
        self.memory.argtypes = []
        self.memory.restype = C.POINTER(C.c_uint8)
        self.memory_size = self.dll.td2r03_memory_size
        self.memory_size.argtypes = []
        self.memory_size.restype = C.c_uint32
        self.size = self.memory_size()
        require(SIZE <= self.size <= 0x200000, 'Unexpected native memory extent')
        self.call = self.dll.td2r03_call
        self.call.argtypes = [C.c_uint32] * 5
        self.call.restype = C.c_uint32
        self.error = self.dll.td2r03_error
        self.error.argtypes = []
        self.error.restype = C.c_int
        self.message = self.dll.td2r03_error_message
        self.message.argtypes = []
        self.message.restype = C.c_char_p
        self.pointer = self.memory()

    def run(self, data, entry, params, repeat):
        C.memmove(self.pointer, bytes(data), len(data))
        if self.size > SIZE:
            C.memset(C.addressof(self.pointer.contents) + SIZE, 0xa5, self.size - SIZE)
        value = 0
        for _ in range(repeat):
            value = self.call(entry, *(list(params) + [0] * (4 - len(params))))
            error = self.error()
            require(not error, 'Native trapped: ' + str(self.message()))
        return value, C.string_at(self.pointer, SIZE)


def fixtures():
    rng = random.Random(0x4b594c4f)
    edges = [0, 1, 2, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff]
    # Each fixture is an original instruction contract, not a Python replica of C.
    for cursor in edges + list(range(256)):
        for repeat in ([1, 17] if cursor in edges else [1]):
            yield dict(family='byte_ring', entry=0x780e, params=(), cursor=cursor,
                       selected_byte=rng.randrange(256), repeat=repeat)
    for value, other in itertools.product(edges, [0, 0xffff, 0x4567]):
        yield dict(family='literal_reader', entry=0x5d83, params=(), low=value, bios=other)
        for arg in edges:
            yield dict(family='literal_subtract', entry=0x5d8d, params=(arg,), low=value, bios=other)
    for index in range(128):
        ptr = rng.randrange(1 << 32)
        yield dict(family='input_vector_set', entry=0x6a17, params=(ptr,), ss_same=index & 1)
        yield dict(family='input_vector_get', entry=0x6a28, params=(), vector=ptr, ss_same=index & 1)
    for index in range(320):
        yield dict(family='simulation_curve', entry=0x448a, params=(), ring=[rng.randrange(256) for _ in range(8)],
                   speed=(edges[index % len(edges)] if index < 90 else rng.randrange(65536)), ss_same=index & 1)
    for speed, force, throttle in itertools.product(edges, edges, [0, 0xff]):
        yield dict(family='simulation_drag', entry=0x45bf, params=(force,), speed=speed,
                   throttle=throttle, drag=rng.randrange(256), ss_same=(speed + force) & 1)
    for speed, ratio, enabled in itertools.product(edges, edges, [0, 1, 0xff]):
        yield dict(family='simulation_rpm', entry=0x4612, params=(), speed=speed,
                   ratio=ratio, enabled=enabled, ss_same=(speed + ratio) & 1)
    for index in range(128):
        yield dict(family='graphics_clip', entry=0x5dfb, params=tuple(rng.randrange(65536) for _ in range(4)), ss_same=index & 1)
    for index in range(384):
        x = edges[index % len(edges)] if index < 144 else rng.randrange(65536)
        y = (0, 1, 199, 0x7fff, 0x8000, 0xffff)[index % 6]
        yield dict(family='graphics_ram_plot', entry=0xba3c, params=(x, y, index & 255),
                   row=rng.randrange(65536), mask=(0x80 >> (x & 7)), wrap=index % 5 == 0,
                   missing=index % 7 == 0, ss_same=index & 1)
    # Bounded run-only profile: header copied through SS, 1..11 escape bytes,
    # ec high bit skips the first sequence stage. Malformed/full-loop domains stay open.
    for index in range(192):
        nesc = (1, 3, 11)[index % 3]
        markers = list(range(0xe0, 0xe0 + nesc))
        value = (index * 37) & 0x7f
        count = (0, 1, 2, 3, 127, 255, 256, 513)[index % 8]
        if index % 4 == 0:
            body = bytes([value, (value + 1) & 0x7f, (value + 2) & 0x7f])
        elif nesc >= 3 and index % 4 == 1:
            body = bytes([markers[2], count & 255, count >> 8, value])
        elif nesc >= 4 and index % 4 == 2:
            rank = 4 + index % (nesc - 3)
            body = bytes([markers[rank - 1], value])
        else:
            body = bytes([markers[0], count & 255, value])
        yield dict(family='codec_run_stage', entry=0x6b02, params=((0x8000 << 16) | 0x120, 0x60001234, 0x400),
                   body=list(body), nesc=nesc, markers=markers, ss_same=1)
    # Excluded original SS alias witnesses: first vector store changes the second
    # forwarded stack argument. A host argument API deliberately cannot inherit it.
    for ptr in [0x1234abcd, 0xabcd1234, 0x0001ffff, 0xffff0001]:
        yield dict(family='excluded_ss_alias', entry=0x6a17, params=(ptr,), ss_same=1, sp=0x64d6, excluded=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--build-record', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--probe', type=int, default=0)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists() and output.is_relative_to(ROOT / 'docs/recovery/evidence'), 'Fresh public evidence path required')
    image_path = ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin'
    mz_path = ROOT / 'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe'
    image, mz = image_path.read_bytes(), mz_path.read_bytes()
    require(hashlib.sha256(image).hexdigest() == IMAGE_SHA and hashlib.sha256(mz).hexdigest() == MZ_SHA, 'Original image identity')
    count, table = struct.unpack_from('<H', mz, 6)[0], struct.unpack_from('<H', mz, 24)[0]
    relocations = [struct.unpack_from('<H', mz, table + i * 4)[0] + 16 * struct.unpack_from('<H', mz, table + i * 4 + 2)[0] for i in range(count)]
    relocated = bytearray(image)
    for at in relocations:
        struct.pack_into('<H', relocated, at, (struct.unpack_from('<H', relocated, at)[0] + LOAD) & 65535)
    base = bytearray(b'\xa5' * SIZE)
    base[LOAD * 16:LOAD * 16 + len(relocated)] = relocated
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    fence = {CS * 16 + ins.address for begin, end in RANGES for ins in decoder.disasm(image[0x6c90 + begin:0x6c90 + end], begin)}
    cpu = Uc(UC_ARCH_X86, UC_MODE_16)
    backing = map_twenty_bit_ram(cpu)
    active = {}
    def code(u, address, size, unused):
        if address == active['sentinel']:
            active['returned'] = True
            u.emu_stop()
            return
        require(address in fence, f'Original escaped instruction fence: {address:x}')
        active['instructions'] += 1
        active['sites'].add(address - CS * 16)
    def interrupt(*unused):
        raise RuntimeError('No interrupts/devices are admitted in this representative profile')
    cpu.hook_add(UC_HOOK_CODE, code)
    cpu.hook_add(UC_HOOK_INTR, interrupt)
    native = Native(args.library)
    baseline = Native(args.baseline) if args.baseline else None
    totals, mismatches, baseline_mismatches, excluded = Counter(), Counter(), Counter(), Counter()
    witnesses, sites = [], set()
    begin_time = time.monotonic()
    error = None
    instructions = 0
    case_hash = hashlib.sha256()
    try:
        for case_index, case in enumerate(fixtures()):
            if args.probe and case_index >= args.probe:
                break
            data = bytearray(base)
            family, entry, params = case['family'], case['entry'], case['params']
            ss, sp = (DS if case.get('ss_same') else 0x9000), case.get('sp', 0xe000)
            repeat = case.get('repeat', 1)
            if family == 'byte_ring':
                put(data, 0x66e6, case['cursor'])
                for i in range(256):
                    put(data, 0x66e8 + i, (i * 37 + case_index) & 255, 1)
                put(data, 0x66e8 + ((case['cursor'] - 1) & 255), case['selected_byte'], 1)
            elif family.startswith('literal_'):
                write_word(data, 0x86c, case['low'])
                write_word(data, 0x46c, case['bios'])
            elif family == 'input_vector_get':
                put(data, 0x64dc, case['vector'], 4)
            elif family == 'simulation_curve':
                for i, value in enumerate(case['ring']):
                    put(data, 0x335d + i, value, 1)
                put(data, 0x52ce, case['speed'])
            elif family == 'simulation_drag':
                put(data, 0x52ce, case['speed'])
                put(data, 0x336c, case['throttle'], 1)
                put(data, 0x324a + (case['speed'] >> 10), case['drag'], 1)
                put(data, 0x2f56, 0, 1)
            elif family == 'simulation_rpm':
                put(data, 0x52ce, case['speed'])
                put(data, 0x3328, case['ratio'])
                put(data, 0x2f56, case['enabled'], 1)
            elif family == 'graphics_ram_plot':
                x, y, colour = params
                rowtab = 0xb26b
                put(data, 0xaf44, rowtab, segment=CS)
                row_address = (rowtab + ((y << 1) & 65535)) & 65535
                put(data, row_address, case['row'], segment=CS)
                planes = [0xffff if case['wrap'] else 0x7000, 0 if case['missing'] else 0x7100, 0x7200, 0x7300]
                for i, plane in enumerate(planes):
                    put(data, 0xaf3c + i * 2, plane, segment=CS)
                put(data, 0x68ce + (x & 7), case['mask'], 1)
            elif family == 'codec_run_stage':
                body = bytes(case['body'])
                raw = b'\x01' + (0x100).to_bytes(3, 'little') + len(body).to_bytes(4, 'little') + bytes([0x80 | case['nesc']]) + bytes(case['markers']) + body
                start = 0x80120
                data[start:start + max(len(raw), 20)] = raw.ljust(max(len(raw), 20), b'\x7f')
            # Original call-frame bytes are synthetic input, not native C stack.
            frame_words = [0x100, 0xc000] if entry in FAR else [0xf000]
            original_params = list(params)
            if entry == 0x6a17:
                original_params = [params[0] & 65535, params[0] >> 16]
            elif entry == 0x6b02:
                original_params = [0x120, 0x8000, 0x1234, 0x6000, 0x400]
            elif entry in {0x448a, 0x45bf, 0x4612}:
                original_params = []
            for i, word in enumerate(frame_words + original_params):
                write_word(data, ss * 16 + ((sp + i * 2) & 65535), word)
            expected = None
            for iteration in range(repeat):
                cpu.mem_write(0, bytes(data if iteration == 0 else expected))
                for reg, value in [(UC_X86_REG_CS, CS), (UC_X86_REG_IP, entry), (UC_X86_REG_DS, DS),
                                   (UC_X86_REG_ES, 0x6789), (UC_X86_REG_SS, ss), (UC_X86_REG_SP, sp),
                                   (UC_X86_REG_AX, 0xbeef), (UC_X86_REG_BX, 0x1234), (UC_X86_REG_CX, 0x3456),
                                   (UC_X86_REG_DX, params[0] if entry == 0x45bf else 0xabcd),
                                   (UC_X86_REG_BP, 0x5678), (UC_X86_REG_SI, 0x4567), (UC_X86_REG_DI, 0x789a),
                                   (UC_X86_REG_EFLAGS, 0x603)]:
                    cpu.reg_write(reg, value)
                active.update(sentinel=0xc0100 if entry in FAR else CS * 16 + 0xf000, returned=False, instructions=0, sites=set())
                cpu.emu_start(CS * 16 + entry, 0, count=2000000)
                require(active['returned'], f'Original instruction budget exhausted: {family}/{case_index}')
                require(cpu.reg_read(UC_X86_REG_SP) == sp + (4 if entry in FAR else 2), 'Original return/frame')
                expected = bytearray(cpu.mem_read(0, SIZE))
                instructions += active['instructions']
                sites.update(active['sites'])
            expected_value = None
            if entry in {0x780e, 0x5d83, 0x5d8d}:
                expected_value = cpu.reg_read(UC_X86_REG_AX)
            elif entry in {0x6a28, 0x6b02}:
                expected_value = cpu.reg_read(UC_X86_REG_AX) | (cpu.reg_read(UC_X86_REG_DX) << 16)
            # Exclude only actual original frame/local scratch. Overlapping live
            # vector bytes are separately compared for the excluded-alias witness.
            scratch_start, scratch_end = ss * 16 + sp - 0x300, ss * 16 + sp + 2 * len(frame_words + original_params)
            def compare_one(engine):
                value, actual = engine.run(data, entry, params, repeat)
                good = (actual[:scratch_start] == expected[:scratch_start] and actual[scratch_end:] == expected[scratch_end:])
                if case.get('excluded'):
                    at = DS * 16 + 0x64dc
                    good = good and actual[at:at + 4] == expected[at:at + 4]
                if expected_value is not None:
                    good = good and value == expected_value
                return good, value, actual
            good, value, actual = compare_one(native)
            original_case = json.dumps(case, sort_keys=True, separators=(',', ':')).encode()
            case_hash.update(original_case + b'\n')
            totals[family] += 1
            if case.get('excluded'):
                excluded['mismatch' if not good else 'match'] += 1
            elif not good:
                mismatches[family] += 1
            baseline_good, baseline_value, baseline_actual = None, None, None
            if baseline:
                baseline_good, baseline_value, baseline_actual = compare_one(baseline)
                if not baseline_good:
                    baseline_mismatches[family] += 1
            if (not good or baseline_good is False) and len([w for w in witnesses if w['family'] == family]) < 8:
                differences = [at for at in range(SIZE) if not scratch_start <= at < scratch_end and actual[at] != expected[at]]
                baseline_differences = ([at for at in range(SIZE) if not scratch_start <= at < scratch_end and baseline_actual[at] != expected[at]] if baseline_actual else [])
                vector_at = DS * 16 + 0x64dc
                witnesses.append({'case': case_index, 'family': family, 'entry': f'06C9:{entry:04X}',
                                  'fixture_sha256': hashlib.sha256(original_case).hexdigest(),
                                  'expected_scalar': expected_value, 'candidate_scalar': value,
                                  'baseline_scalar': baseline_value, 'candidate_matches': good,
                                  'baseline_matches': baseline_good, 'excluded_profile': bool(case.get('excluded')),
                                  'differing_physical_addresses': differences[:16],
                                  'baseline_differing_physical_addresses': baseline_differences[:16],
                                  'expected_live_vector': int.from_bytes(expected[vector_at:vector_at + 4], 'little') if case.get('excluded') else None,
                                  'candidate_live_vector': int.from_bytes(actual[vector_at:vector_at + 4], 'little') if case.get('excluded') else None,
                                  'expected_bus_sha256': hashlib.sha256(expected).hexdigest(),
                                  'candidate_bus_sha256': hashlib.sha256(actual).hexdigest()})
            if (case_index + 1) % 256 == 0:
                print(json.dumps({'cases': case_index + 1, 'candidate_mismatches': dict(mismatches)}), flush=True)
        if not args.probe:
            expected_counts = Counter(case['family'] for case in fixtures())
            require(totals == expected_counts, 'Complete deterministic fixture family coverage')
            require(excluded['mismatch'] == 4, 'Four excluded live-SS argument aliases must remain explicit witnesses')
            if baseline:
                require(baseline_mismatches['literal_reader'] > 0 and baseline_mismatches['literal_subtract'] > 0,
                        'Baseline wrong-address discriminators must execute')
                require(baseline_mismatches['graphics_ram_plot'] > 0, 'Baseline high physical wrap discriminators must execute')
    except Exception as exc:
        error = repr(exc)
    record = {'schema': 1, 'date': '2026-10-22', 'result': 'pass' if not error and not mismatches else 'fail',
              'scope': 'Representative actual candidate C versus original instructions, synthetic disjoint native caller profile; no game/DOS/device/session/fidelity acceptance',
              'error': error, 'vectors': sum(v for k, v in totals.items() if k != 'excluded_ss_alias'),
              'vectors_by_family': dict(totals), 'candidate_mismatches': dict(mismatches),
              'baseline_mismatches': dict(baseline_mismatches), 'excluded_ss_alias': dict(excluded),
              'witnesses': witnesses, 'original_instructions_executed': instructions,
              'original_instruction_sites_exercised': len(sites),
              'original_sites': [f'06C9:{ip:04X}' for ip in sorted(sites)],
              'fixture_stream_sha256': case_hash.hexdigest(), 'image_sha256': IMAGE_SHA,
              'normalized_mz_sha256': MZ_SHA, 'relocations': len(relocations), 'load_segment': LOAD,
              'validator_sha256': digest(Path(__file__)), 'library': str(native.path.relative_to(ROOT)),
              'library_sha256': digest(native.path), 'baseline_library_sha256': digest(baseline.path) if baseline else None,
              'build_record': {'path': str(args.build_record.relative_to(ROOT)), 'sha256': digest(args.build_record)} if args.build_record else None,
              'dependencies': [{'path': 'tools/validation/twenty_bit_bus.py', 'sha256': digest(ROOT / 'tools/validation/twenty_bit_bus.py')}],
              'elapsed_seconds': round(time.monotonic() - begin_time, 3), 'probe_limit': args.probe,
              'limits': ['Only selected entrypoints/fixtures; no inherited whole-core or previous raw-bus receipt credit.',
                         'C API scalar/state observations; GPR/FLAGS and original scratch stores are not native ABI promises.',
                         'Original SS scratch aperture SP-0300 through caller frame is excluded; four explicit live-argument aliases are reported outside admission.',
                         'Run-only codec ec high-bit and1..11escapes with disjoint bounded source/output; no supplied resources, ec0/fullLOOP or sequence-stage acceptance.',
                         'Graphics plot selects RAM planar branch; no EGA device/latch/register/pixel output acceptance.',
                         '20bit shared RAM mapping is an explicit serialized analysis bus profile, not observed hardware/A20 timing.',
                         'No actual keyboard BIOS, IRQ delivery/nesting, input event history, audio or supported historical caller reachability proof.']}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(record, indent=2) + '\n').encode())
    print(json.dumps({k: record[k] for k in ['result', 'error', 'vectors', 'vectors_by_family', 'candidate_mismatches', 'baseline_mismatches', 'excluded_ss_alias', 'original_instructions_executed', 'elapsed_seconds']}, indent=2))
    return 0 if record['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
