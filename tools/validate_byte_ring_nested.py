"""Fence one synthetic nested invocation at each byte-ring boundary.

This is a preserved-register nested-call model, not delivery of a hardware IRQ
or proof that every modelled boundary occurs on an admitted game execution.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def require(test, message):
    if not test:
        raise RuntimeError(message)


class State(ctypes.Structure):
    _fields_ = [('cursor', ctypes.c_uint16), ('bytes', ctypes.c_uint8 * 256)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    output, library = args.output.resolve(), args.library.resolve()
    require(not output.exists() and output.is_relative_to(ROOT / 'docs/recovery/evidence') and library.is_relative_to(ROOT / 'analysis'), 'Fresh evidence/private DLL required')
    image = (ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    image_sha = hashlib.sha256(image).hexdigest()
    require(image_sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    code = image[0x6c90+0x780e:0x6c90+0x782b]
    ips = [i.address for i in Cs(CS_ARCH_X86, CS_MODE_16).disasm(code, 0x780e)]
    require(len(ips) == 11, 'Unexpected helper boundaries')
    dll = ctypes.CDLL(str(library))
    step = dll.td2ega_byte_ring_step
    step.argtypes = [ctypes.POINTER(State)]
    step.restype = ctypes.c_uint16
    registers = [UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
                 UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_SP,
                 UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_DS, UC_X86_REG_ES,
                 UC_X86_REG_SS, UC_X86_REG_EFLAGS]
    counts = {f'{ip:04X}': 0 for ip in ips}
    mismatches = {f'{ip:04X}': 0 for ip in ips}
    total = instructions = 0
    witness = None
    ds, ss, sp = 0x5000, 0x7000, 0x8000
    state_at = ds*16 + 0x66e6
    for load in [0x1000, 0x2345]:
        cs = load + 0x6c9
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x100000)
        uc.mem_write(cs*16 + 0x780e, code)
        starts = {cs*16 + ip for ip in ips}
        active = {'stop': None, 'count': 0}

        def fetch(u, address, size, _):
            require(address in starts, 'Nested helper escaped instruction fence')
            if active['stop'] == address:
                u.emu_stop()
            else:
                active['count'] += 1

        def write(u, access, address, size, value, _):
            require(state_at <= address and address+size <= state_at+258 or
                    ss*16+sp-0x120 <= address and address+size <= ss*16+sp+4, 'Unexpected nested writer')

        def interrupt(*_):
            raise RuntimeError('Unexpected actual interrupt/service')

        uc.hook_add(UC_HOOK_CODE, fetch)
        uc.hook_add(UC_HOOK_MEM_WRITE, write)
        uc.hook_add(UC_HOOK_INTR, interrupt)
        for cursor in [0, 1, 2, 255, 256, 257, 0xfffe, 0xffff]:
            for phase in range(256):
                table = bytes((i*73 + phase) & 255 for i in range(256))
                packed = struct.pack('<H', cursor) + table
                for boundary in ips:
                    uc.mem_write(state_at-8, b'\xa5'*8 + packed + b'\xa5'*8)
                    uc.mem_write(ss*16+sp-0x120, b'\xa5'*0x124)
                    uc.mem_write(ss*16+sp, struct.pack('<HH', 0x100, 0x8000))
                    initial = [0xbeef, 0x1234, 0x2345, 0x3456, 0x4567, 0x5678, 0x6789,
                               sp, cs, 0x780e, ds, 0x6000, ss, 0x202]
                    for reg, value in zip(registers, initial):
                        uc.reg_write(reg, value)
                    active.update(stop=cs*16+boundary, count=0)
                    uc.emu_start(cs*16+0x780e, 0x80100, count=32)
                    require(uc.reg_read(UC_X86_REG_CS) == cs and uc.reg_read(UC_X86_REG_IP) == boundary, 'Outer pause boundary')
                    saved = [uc.reg_read(reg) for reg in registers]
                    nested_sp = sp-0x100
                    uc.mem_write(ss*16+nested_sp, struct.pack('<HH', 0x100, 0x8000))
                    uc.reg_write(UC_X86_REG_SP, nested_sp)
                    active['stop'] = None
                    uc.emu_start(cs*16+0x780e, 0x80100, count=32)
                    require(uc.reg_read(UC_X86_REG_CS) == 0x8000 and uc.reg_read(UC_X86_REG_IP) == 0x100 and uc.reg_read(UC_X86_REG_SP) == nested_sp+4, 'Nested far return')
                    inner_ax = uc.reg_read(UC_X86_REG_AX)
                    for reg, value in zip(registers, saved):
                        uc.reg_write(reg, value)
                    uc.emu_start(cs*16+boundary, 0x80100, count=32)
                    require(uc.reg_read(UC_X86_REG_CS) == 0x8000 and uc.reg_read(UC_X86_REG_IP) == 0x100 and uc.reg_read(UC_X86_REG_SP) == sp+4, 'Resumed far return')
                    outer_ax = uc.reg_read(UC_X86_REG_AX)
                    actual = bytes(uc.mem_read(state_at, 258))
                    reference = State.from_buffer_copy(packed)
                    if boundary <= 0x780f:
                        expected_inner, expected_outer = step(ctypes.byref(reference)), step(ctypes.byref(reference))
                    elif boundary == 0x7813:
                        reference.cursor = (reference.cursor-1)&65535
                        expected_inner = step(ctypes.byref(reference))
                        index = reference.cursor & 255
                        old = reference.bytes[index]
                        reference.bytes[index] = ((old << 1) | (old < 128)) & 255
                        expected_outer = reference.bytes[index]
                    else:
                        expected_outer, expected_inner = step(ctypes.byref(reference)), step(ctypes.byref(reference))
                    require(actual == bytes(reference) and (inner_ax, outer_ax) == (expected_inner, expected_outer), 'Nested original/reference state/results')
                    require(bytes(uc.mem_read(state_at-8, 274)) == b'\xa5'*8+actual+b'\xa5'*8, 'State guard')
                    require(all(uc.reg_read(reg) == value for reg, value in zip(registers, initial) if reg not in [UC_X86_REG_AX, UC_X86_REG_SP, UC_X86_REG_CS, UC_X86_REG_IP, UC_X86_REG_EFLAGS]), 'Outer restored registers')
                    serial = State.from_buffer_copy(packed)
                    step(ctypes.byref(serial)); step(ctypes.byref(serial))
                    different = actual != bytes(serial)
                    require(not different or boundary == 0x7813, 'Unexpected nonserial boundary')
                    if different and witness is None:
                        witness = {'load_segment': load, 'initial_cursor': cursor, 'phase': phase,
                                   'pause_before': '06C9:7813', 'final_cursor': reference.cursor,
                                   'inner_ax': inner_ax, 'outer_ax': outer_ax,
                                   'changed_indexes': [i for i in range(256) if actual[2+i] != table[i]],
                                   'serial_changed_indexes': [i for i in range(256) if serial.bytes[i] != table[i]]}
                    key = f'{boundary:04X}'
                    counts[key] += 1
                    mismatches[key] += different
                    instructions += active['count']
                    total += 1
    require(witness is not None and mismatches['7813'] > 0, 'Missing nonserial witness')
    result = {'schema': 1, 'result': 'pass', 'image_sha256': image_sha,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'native_source_sha256': hashlib.sha256((ROOT/'src/recovered/td2ega_byte_ring.c').read_bytes()).hexdigest(),
              'vectors': total, 'original_instructions_executed': instructions, 'boundary_cases': counts,
              'state_mismatches_against_two_serial_calls': mismatches, 'nonserial_witness': witness,
              'conclusion': 'Nested call after outerDEC butbeforeMOVSI makesbothinvocations updatetheinnerselectedbyte; outerselectedindex isskipped, cursorstilldecrements twice. Other testedboundaries matchserialfinalstate underpreservedregister nesting. AtomicCstep alone cannotrepresent thismodelledinterleaving.',
              'limits': 'Synthetic one-level preserved-register nestedcall model only. No realIRQ delivery, actualcallbackguard feasibility, timing/rate, supportedgame schedule, wholefunctionreentrancy orcore/fidelity acceptance. Existing byte-ring C remainsunchanged andmodelsserialized invocations.'}
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
