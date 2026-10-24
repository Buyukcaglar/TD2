"""Compare callback word updates and publication order with614C/6180.

Synthetic opaque code addresses; no callback executes, no real IRQ is delivered.
The fatal-report call is fenced before entry, preserving its partial prefix.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def require(value, message):
    if not value:
        raise RuntimeError(message)


class State(ctypes.Structure):
    _fields_ = [('word', ctypes.c_uint16 * 12)]


class Write(ctypes.Structure):
    _fields_ = [('word_index', ctypes.c_uint16), ('value', ctypes.c_uint16)]


class Result(ctypes.Structure):
    _fields_ = [('status', ctypes.c_uint16), ('slot', ctypes.c_uint16),
                ('write_count', ctypes.c_uint16), ('enables_interrupts', ctypes.c_uint16),
                ('writes', Write * 10)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    library, output = args.library.resolve(), args.output.resolve()
    require(library.is_relative_to(ROOT / 'analysis') and not output.exists() and output.is_relative_to(ROOT / 'docs/recovery/evidence'), 'Private library/fresh evidence required')
    image = (ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    image_sha = hashlib.sha256(image).hexdigest()
    require(image_sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    functions = []
    dll = ctypes.CDLL(str(library))
    for name in ['td2ega_callback_add', 'td2ega_callback_remove']:
        fn = getattr(dll, name)
        fn.argtypes = [ctypes.POINTER(State), ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(Result)]
        fn.restype = None
        functions.append(fn)
    rng = random.Random(0x614c6180)
    fixtures = []
    for mask in range(32):
        words = sum(([0x100 + slot, 0x200 + slot if mask & (1 << slot) else 0] for slot in range(5)), []) + [0xaaaa, 0xbbbb]
        for target in range(6):
            pair = words[target*2:target*2+2] if target < 5 else [0xcccc, 0xdddd]
            fixtures.append((words, pair))
    fixtures += [([0]*12, [0, 0]), ([0x1234, 0x5678]*6, [0x1234, 0x5678]),
                 ([0xffff]*12, [0xffff, 0xffff]), ([0xffff]*12, [0, 0])]
    for _ in range(256):
        words = [rng.randrange(65536) for _ in range(12)]
        for slot in range(5):
            if rng.randrange(3) == 0:
                words[slot*2 + 1] = 0
        pair = words[(slot := rng.randrange(5))*2:slot*2+2] if rng.randrange(2) else [rng.randrange(65536), rng.randrange(65536)]
        fixtures.append((words, pair))
    total = instructions_total = fatal = found = 0
    ds, ss, sp = 0x5000, 0x7000, 0x8000
    base = ds*16 + 0x5f12
    spans = []
    for load in [0x1000, 0x2345]:
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x100000)
        cs = load + 0x6c9
        code = image[0x6c90+0x614c:0x6c90+0x61bf]
        uc.mem_write(cs*16 + 0x614c, code)
        starts = {cs*16 + i.address for i in Cs(CS_ARCH_X86, CS_MODE_16).disasm(code, 0x614c)}
        active = {'writes': [], 'count': 0, 'fatal': False}

        def fetch(u, address, size, _):
            require(address in starts, 'Callback helper escaped instruction fence')
            if address == cs*16 + 0x6164:
                active['fatal'] = True
                u.emu_stop()
                return
            active['count'] += 1

        def write(u, access, address, size, value, _):
            if ss*16 + sp - 16 <= address and address + size <= ss*16 + sp + 8:
                return
            require(base <= address and address + size <= base + 24 and size == 2 and (address-base)%2 == 0, 'Unexpected callback writer')
            active['writes'].append(((address-base)//2, value & 65535, (u.reg_read(UC_X86_REG_EFLAGS)>>9)&1))

        def interrupt(*_):
            raise RuntimeError('Unexpected service/IRQ')

        uc.hook_add(UC_HOOK_CODE, fetch)
        uc.hook_add(UC_HOOK_MEM_WRITE, write)
        uc.hook_add(UC_HOOK_INTR, interrupt)
        for operation, entry in enumerate([0x614c, 0x6180]):
            for initial_if in [0, 1]:
                for initial_df in [0, 1]:
                    for words, pair in fixtures:
                        packed = struct.pack('<12H', *words)
                        guard = b'\xa5'*8
                        uc.mem_write(base-8, guard + packed + guard)
                        uc.mem_write(ss*16 + sp - 16, guard*2 + struct.pack('<4H', 0x100, 0x8000, *pair))
                        preserved = [(UC_X86_REG_DS, ds), (UC_X86_REG_SS, ss), (UC_X86_REG_ES, 0x6789),
                                     (UC_X86_REG_BP, 0x5678), (UC_X86_REG_SI, 0x4567), (UC_X86_REG_DI, 0x3456)]
                        for register, value in preserved + [(UC_X86_REG_CS, cs), (UC_X86_REG_IP, entry),
                              (UC_X86_REG_SP, sp), (UC_X86_REG_AX, 0xbeef), (UC_X86_REG_DX, 0xabcd),
                              (UC_X86_REG_EFLAGS, 3 | (initial_if << 9) | (initial_df << 10))]:
                            uc.reg_write(register, value)
                        active.update(writes=[], count=0, fatal=False)
                        uc.emu_start(cs*16 + entry, 0x80100, count=256)
                        native = State.from_buffer_copy(packed)
                        result = Result()
                        functions[operation](ctypes.byref(native), *pair, ctypes.byref(result))
                        expected = bytes(uc.mem_read(base, 24))
                        require(bytes(native) == expected, 'C/original callback state')
                        require(bytes(uc.mem_read(base-8, 40)) == guard + expected + guard, 'State guard')
                        writes = [(w.word_index, w.value) for w in result.writes[:result.write_count]]
                        require(writes == [(i, value) for i, value, _ in active['writes']], 'Ordered publication/write mismatch')
                        require(result.status == int(active['fatal']), 'Fatal-prefix status')
                        slot = next((i for i in range(5) if (words[2*i+1] == 0 if operation == 0 else words[2*i:2*i+2] == pair)), 5)
                        require(result.slot == slot and result.enables_interrupts == int(operation == 1 and slot < 5), 'Result slot/interrupt policy')
                        require(all(flag == (initial_if if operation == 0 else 0) for _, _, flag in active['writes']), 'Original write masking policy')
                        require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1 == (1 if operation == 1 and slot < 5 else initial_if), 'Final interrupt flag')
                        require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1 == initial_df, 'DF preservation')
                        if active['fatal']:
                            require(operation == 0 and uc.reg_read(UC_X86_REG_CS) == cs and uc.reg_read(UC_X86_REG_IP) == 0x6164 and uc.reg_read(UC_X86_REG_SP) == sp-4, 'Fatal-prefix fence/frame')
                            require(uc.reg_read(UC_X86_REG_AX) == 0x5fe8 and not active['writes'], 'Fatal prefix AX/state')
                            fatal += 1
                        else:
                            require(uc.reg_read(UC_X86_REG_CS) == 0x8000 and uc.reg_read(UC_X86_REG_IP) == 0x100 and uc.reg_read(UC_X86_REG_SP) == sp+4, 'Far-return frame')
                            require(all(uc.reg_read(reg) == value for reg, value in preserved), 'Preserved registers')
                            expected_ax = pair[1] if operation == 0 else words[9] if slot < 4 else pair[0]
                            require(uc.reg_read(UC_X86_REG_AX) == expected_ax, 'AX effect')
                            require(uc.reg_read(UC_X86_REG_DX) == (0xabcd if operation == 0 else pair[1]), 'DX effect')
                            require(uc.reg_read(UC_X86_REG_BX) == 0x5f12 + (slot*4 if operation == 0 else 16 if slot < 5 else 20), 'BX effect')
                            require(uc.reg_read(UC_X86_REG_CX) == (5-slot if operation == 0 else 0), 'CX effect')
                            found += int(operation == 1 and slot < 5)
                        total += 1
                        instructions_total += active['count']
        spans.append({'load_segment': load, 'module_offset': 0x6c90+0x614c, 'length': len(code), 'unrelocated_sha256': hashlib.sha256(code).hexdigest()})
    diagnostics = 0
    for function in functions:
        result = Result()
        function(None, 0, 0, ctypes.byref(result))
        require(result.status == 2 and result.write_count == 0, 'Native argument diagnostic')
        function(None, 0, 0, None)
        diagnostics += 2
    result = {'schema': 1, 'result': 'pass', 'function_ids': ['FN-EGA-000150', 'FN-EGA-000151'],
              'source_sha256': hashlib.sha256((ROOT / 'src/recovered/td2ega_timer_callbacks.c').read_bytes()).hexdigest(),
              'validator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'image_sha256': image_sha,
              'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(), 'vectors': total,
              'native_only_diagnostics': diagnostics, 'original_instructions_executed': instructions_total,
              'fatal_prefix_cases': fatal, 'remove_match_cases': found, 'original_spans': spans,
              'limits': 'Only isolated five-slot callback metadata, opaque synthetic addresses and ordered writes. Add is unmasked; matchedremove masks writes then unconditionallySTI. Actualcallbacks, asynchronousIRQ/nesting, fulltimer/audio/device behavior, caller lifetimes and game/session acceptance remainopen.'}
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
