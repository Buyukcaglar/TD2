"""Fence main's retry return through its actual self-modifying helper.

Synthetic helper AX and INT11 responses only. Stop before the external word
reader; no filesystem, real firmware, timer, or game session is exercised.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


def require(test, message):
    if not test:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output.resolve()
    require(not output.exists() and output.is_relative_to(ROOT / 'docs/recovery/evidence'), 'Fresh evidence output required')
    image_path = ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin'
    image = image_path.read_bytes()
    image_sha = hashlib.sha256(image).hexdigest()
    require(image_sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    mz = (ROOT / 'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest() == '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2', 'Unadmitted MZ')
    count, table = struct.unpack_from('<H', mz, 6)[0], struct.unpack_from('<H', mz, 24)[0]
    relocs = [struct.unpack_from('<H', mz, table + 4*i)[0] + 16*struct.unpack_from('<H', mz, table + 4*i + 2)[0] for i in range(count)]
    rows = []
    main_sites = {0x9d2, 0x9d5, 0x9d8, 0x9fb, 0x9fc, 0x9ff, 0xa04}
    for load in [0x1000, 0x2345]:
        for helper_ax in [0, 1, 2, 3, 4, 0xffff, 0x101]:
            for first in range(4):
                for second in range(4):
                    relocated = bytearray(image)
                    for offset in relocs:
                        struct.pack_into('<H', relocated, offset, (struct.unpack_from('<H', relocated, offset)[0] + load) & 65535)
                    uc = Uc(UC_ARCH_X86, UC_MODE_16)
                    uc.mem_map(0, 0x100000)
                    uc.mem_write(load * 16, bytes(relocated))
                    group = load + 0x178f
                    stack = group * 16
                    sp = 0xe000
                    uc.mem_write(stack + sp - 0x100, b'\xa5' * 0x108)
                    preserved = [(UC_X86_REG_DS, group), (UC_X86_REG_SS, group), (UC_X86_REG_ES, 0x4444),
                                 (UC_X86_REG_BP, 0xd000), (UC_X86_REG_SI, 0x2222), (UC_X86_REG_DI, 0x3333)]
                    for register, value in preserved + [(UC_X86_REG_CS, load), (UC_X86_REG_IP, 0x9d2),
                            (UC_X86_REG_SP, sp), (UC_X86_REG_AX, helper_ax), (UC_X86_REG_EFLAGS, 0x202)]:
                        uc.reg_write(register, value)
                    instructions = [0]
                    queries = [0]
                    visited = []
                    allowed = {0x10, 0x11, 0x12, 0x13, stack + 0x5656, stack + 0x5657, stack + 0x5658,
                               stack + 0x7c, stack + 0x7d}
                    allowed.update(load*16 + 0x6c90 + off for off in [0x1bf7, 0x424a, 0x4275, 0x42ad])
                    allowed.update(load*16 + 0x13a80 + off for off in [0x24, 0x2a, 0x2b, 0x2c, 0x2d, 0xbb, 0x154, 0x3da])

                    def code(u, address, size, _):
                        cs, ip = u.reg_read(UC_X86_REG_CS), u.reg_read(UC_X86_REG_IP)
                        if cs == load and ip == 0xa07:
                            u.emu_stop()
                            return
                        require((cs == load and ip in main_sites) or
                                (cs == load + 0x13a8 and (0x2e <= ip < 0x1ad or 0x3d3 <= ip < 0x3f8)), 'Instruction escaped retry/helper fence')
                        if cs == load:
                            visited.append(ip)
                        instructions[0] += 1

                    def write(u, access, address, size, value, _):
                        require(stack + sp - 0x100 <= address and address + size <= stack + sp + 8 or
                                all(address + n in allowed for n in range(size)), 'Unexpected retry/helper write')

                    def interrupt(u, number, _):
                        require(number == 0x11 and queries[0] < 2, 'Unexpected service')
                        u.reg_write(UC_X86_REG_AX, ([first, second][queries[0]] << 6) | 0x211)
                        queries[0] += 1

                    uc.hook_add(UC_HOOK_CODE, code)
                    uc.hook_add(UC_HOOK_MEM_WRITE, write)
                    uc.hook_add(UC_HOOK_INTR, interrupt)
                    uc.emu_start(load * 16 + 0x9d2, 0xfffff, count=4096)
                    require(uc.reg_read(UC_X86_REG_CS) == load and uc.reg_read(UC_X86_REG_IP) == 0xa07 and
                            uc.reg_read(UC_X86_REG_SP) == sp + 4, 'Retry stop/frame')
                    require(all(uc.reg_read(reg) == value for reg, value in preserved), 'Retry preserved registers')
                    require(visited == sorted(main_sites), 'Retry branch did not follow unconditional 09D8 jump')
                    selected = (helper_ax - 1) & 65535
                    admitted_first = (selected & 255) <= first
                    admitted = admitted_first and (selected & 255) <= second
                    result = 0 if admitted else selected
                    require(struct.unpack('<H', bytes(uc.mem_read(stack + 0x5657, 2)))[0] == selected, 'Selected word')
                    require(struct.unpack('<H', bytes(uc.mem_read(stack + 0x7c, 2)))[0] == result and
                            uc.reg_read(UC_X86_REG_AX) == result, 'Caller result')
                    controls = [uc.mem_read(load*16 + 0x6c90 + offset, 1)[0] for offset in [0x1bf7, 0x424a, 0x4275, 0x42ad]]
                    require(controls == [0xcb if admitted else 0xf8] + ([0x75]*3 if admitted_first else [0x76, 0x76, 0x77]), 'Caller patch state')
                    require(struct.unpack('<HH', bytes(uc.mem_read(0x10, 4))) == (sp - 10, 0x201), 'Actual far-call stack bookmark')
                    rows.append({'load_segment': load, 'synthetic_helper_ax': helper_ax, 'selected_word': selected,
                                 'first_equipment_index': first, 'second_equipment_index': second, 'result_word': result,
                                 'control_bytes': controls, 'instructions': instructions[0], 'queries': queries[0]})
    require(hashlib.sha256(image_path.read_bytes()).hexdigest() == image_sha, 'Original derived image changed')
    result = {'schema': 1, 'result': 'pass', 'image_sha256': image_sha,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'vectors': len(rows),
              'original_instructions_executed': sum(row['instructions'] for row in rows), 'cases': rows,
              'conclusion': '09D8 unconditionally reaches DEC AX and stores helper-return-minus-one at DS5657 before actual002E. Helper AX1 (and0101 by low-byte comparison) admits both synthetic equipment queries and installs CB/75/75/75; DS007C receives0. AX0 wraps selected word toFFFF and rejects all tested query indexes.',
              'limits': 'Actual0477 helper/file success, main history and later state-machine execution are not exercised. Synthetic AX/INT11, isolated loaded copies, DF0. Stops before5D83; no timer semantics, DOS session, complete state-machine or fidelity acceptance.'}
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    main()
