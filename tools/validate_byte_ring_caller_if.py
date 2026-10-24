"""Execute4A34..4A46, actual7977 and780E to inspect the caller's IF.

No45FC, complete simulation callback, timer delivery or real media executes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


def require(test, message):
    if not test:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output.resolve()
    require(not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'), 'Fresh evidence required')
    image = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    require(sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    mz = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest() == '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2', 'Unadmitted MZ')
    n, t = struct.unpack_from('<H', mz, 6)[0], struct.unpack_from('<H', mz, 24)[0]
    relocs = [struct.unpack_from('<H', mz, t+4*i)[0] + 16*struct.unpack_from('<H', mz, t+4*i+2)[0] for i in range(n)]
    rows = []
    sites = {0x4a34, 0x4a37, 0x4a38, 0x4a39, 0x4a3e, 0x4a41}
    for load in [0x1000, 0x2345]:
        relocated = bytearray(image)
        for r in relocs:
            struct.pack_into('<H', relocated, r, (struct.unpack_from('<H', relocated, r)[0]+load)&65535)
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x100000)
        uc.mem_write(load*16, bytes(relocated))
        cs, ds, ss, sp = load+0x6c9, 0x5000, 0x7000, 0x8000
        active = {'ifs': [], 'count': 0}

        def code(u, address, size, _):
            ip = u.reg_read(UC_X86_REG_IP)
            require(u.reg_read(UC_X86_REG_CS) == cs, 'Slice changed CS')
            if ip == 0x4a46:
                u.emu_stop()
                return
            require(ip in sites or 0x7977 <= ip < 0x798f or 0x780e <= ip < 0x782b, 'Escaped caller/helper slice')
            if ip in [0x780e, 0x780f, 0x7813, 0x781b, 0x7823]:
                active['ifs'].append((u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
            active['count'] += 1

        def write(u, access, address, size, value, _):
            require(ss*16+sp-16 <= address and address+size <= ss*16+sp or
                    ds*16+0x66e6 <= address and address+size <= ds*16+0x67e8 or
                    address in [ds*16+0x5eee, ds*16+0x5ef0, ds*16+0x5efc], 'Unexpected slice write')

        def interrupt(*_):
            raise RuntimeError('Unexpected service/IRQ')

        uc.hook_add(UC_HOOK_CODE, code)
        uc.hook_add(UC_HOOK_MEM_WRITE, write)
        uc.hook_add(UC_HOOK_INTR, interrupt)
        for initial_if in [0, 1]:
            for initial_df in [0, 1]:
                for cursor in [0, 1, 255, 256, 0xffff]:
                    for phase in [0, 127, 128, 255]:
                        table = bytes((i*73+phase)&255 for i in range(256))
                        uc.mem_write(ds*16+0x66e6, struct.pack('<H', cursor)+table)
                        uc.mem_write(ds*16+0x5eee, b'\xa5'*16)
                        uc.mem_write(ss*16+sp-16, b'\xa5'*16)
                        for reg, value in [(UC_X86_REG_CS, cs), (UC_X86_REG_IP, 0x4a34), (UC_X86_REG_DS, ds),
                            (UC_X86_REG_SS, ss), (UC_X86_REG_SP, sp), (UC_X86_REG_BP, 0x1111),
                            (UC_X86_REG_SI, 0x2222), (UC_X86_REG_EFLAGS, 3|(initial_if<<9)|(initial_df<<10))]:
                            uc.reg_write(reg, value)
                        active.update(ifs=[], count=0)
                        uc.emu_start(cs*16+0x4a34, 0xfffff, count=128)
                        require(uc.reg_read(UC_X86_REG_IP) == 0x4a46 and uc.reg_read(UC_X86_REG_SP) == sp, 'Slice stop/frame')
                        require(active['ifs'] == [1]*5, 'Byte-ring executes with IF enabled after7977')
                        require(uc.reg_read(UC_X86_REG_BP) == 0x1111 and uc.reg_read(UC_X86_REG_SI) == 0x2222 and uc.reg_read(UC_X86_REG_DS) == ds, 'Preserved registers')
                        require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1 == initial_df, 'DF unchanged')
                        expected_cursor = (cursor-1)&65535
                        old = table[expected_cursor&255]
                        expected = ((old<<1)|(old<128))&255
                        require(uc.reg_read(UC_X86_REG_AX) == expected and struct.unpack('<H', bytes(uc.mem_read(ds*16+0x66e6, 2)))[0] == expected_cursor, 'Sample result/cursor')
                        require(struct.unpack('<HH', bytes(uc.mem_read(ds*16+0x5eee, 4))) == (ds, 0x5494) and uc.mem_read(ds*16+0x5efc, 1)[0] == 1, '7977 source publication')
                        rows.append({'load_segment': load, 'initial_if': initial_if, 'initial_df': initial_df,
                                     'cursor': cursor, 'phase': phase, 'sample_if': active['ifs'], 'ax': expected,
                                     'instructions': active['count']})
    result = {'schema': 1, 'result': 'pass', 'image_sha256': sha,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'vectors': len(rows), 'original_instructions_executed': sum(r['instructions'] for r in rows),
              'cases': rows, 'conclusion': 'Actual4A39 call7977 executesSTI;4A41 byte-ring call anditscursor/load/store instructions executeIF1 regardlessincomingIF. NoCLI existsbetweenSTIandthatcall. A callback-entryCLI alone doesnotestablishexclusion for thissamplerpath.',
              'limits': 'Isolated slice beginsafter45FC; earlierpathguards, actualIRQdelivery/latency/PICmask, complete403Bcallbackfeasibility, game schedule andfidelity remainunverified. No timerfrequencyassigned.'}
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    main()
