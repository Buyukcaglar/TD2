"""Compare6AA2 to native raw-loader control with synthetic DOS services.

No real file is opened; only synthetic bytes are copied into private RAM.
Fatal cases stop before16A7:0002, retaining partial reads and open handles.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def require(test, message):
    if not test:
        raise RuntimeError(message)


class Request(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint16) for name in ['operation', 'handle', 'segment', 'offset', 'count']]


class Response(ctypes.Structure):
    _fields_ = [('ax', ctypes.c_uint16), ('carry', ctypes.c_uint16)]


class Result(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint16) for name in ['status', 'failed_operation', 'return_offset', 'return_segment',
                'handle', 'handle_valid', 'next_segment', 'last_read_segment']] + [('successful_reads', ctypes.c_uint32)]


Service = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(Request), ctypes.POINTER(Response))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    library, output = args.library.resolve(), args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'), 'Private library/fresh evidence required')
    image = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    require(sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    mz = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest() == '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2', 'Unadmitted MZ')
    n, table = struct.unpack_from('<H', mz, 6)[0], struct.unpack_from('<H', mz, 24)[0]
    relocs = [struct.unpack_from('<H', mz, table+4*i)[0] + 16*struct.unpack_from('<H', mz, table+4*i+2)[0] for i in range(n)]
    dll = ctypes.CDLL(str(library))
    native = dll.td2ega_raw_load
    native.argtypes = [Service, ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
                       ctypes.c_uint16, ctypes.c_uint32, ctypes.POINTER(Result)]
    native.restype = None
    rows = []
    for load in [0x1000, 0x2345]:
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x110000)
        cs, ds, ss, sp = load+0x6c9, 0x5000, 0x7000, 0x8000
        first, length = 0x6c90+0x6aa2, 96
        code = bytearray(image[first:first+length])
        for r in relocs:
            if first <= r < first+length:
                struct.pack_into('<H', code, r-first, (struct.unpack_from('<H', code, r-first)[0]+load)&65535)
        uc.mem_write(cs*16+0x6aa2, bytes(code))
        starts = {cs*16+i.address for i in Cs(CS_ARCH_X86, CS_MODE_16).disasm(code, 0x6aa2)}
        active = {}

        def code_hook(u, address, size, _):
            require(address in starts, 'Raw loader escaped instruction fence')
            if address == cs*16+0x6afd:
                active['fatal'] = True
                u.emu_stop()
                return
            active['instructions'] += 1

        def write_hook(u, access, address, size, value, _):
            require(ss*16+sp-32 <= address and address+size <= ss*16+sp+10, 'Unexpected CPU raw-loader write')

        def service(model, op, handle, segment, offset, count, write_bytes):
            if op == 0:
                require((segment, offset) == (ds, 0x120), 'Open filename coordinates')
                model['events'].append([0, segment, offset])
                return (2, 1) if active['fail'] == 'open' else (active['handle'], 0)
            require(handle == active['handle'], 'Handle flow')
            if op == 1:
                index = model['reads']
                require(count == 0x4000 and segment == (active['segment']+0x400*index)&65535 and offset == active['offset'], 'Read coordinates/count')
                model['events'].append([1, handle, segment, offset, count])
                model['reads'] += 1
                if active['fail'] == index:
                    data = b'\xd7'*active['partial_error_bytes']
                    write_bytes(segment*16+offset, data)
                    return 5, 1
                position = model['position']
                data = active['file'][position:position+count]
                write_bytes(segment*16+offset, data)
                model['position'] += len(data)
                return len(data), 0
            require(op == 2, 'Unknown service operation')
            model['events'].append([2, handle, segment, offset])
            return (5, 1) if active['close_carry'] else (0, 0)

        def interrupt(u, number, _):
            require(number == 0x21, 'Unexpected IRQ/service')
            ah = (u.reg_read(UC_X86_REG_AX)>>8)&255
            require(ah in [0x3d, 0x3f, 0x3e], 'Unexpected DOS operation')
            op = {0x3d:0, 0x3f:1, 0x3e:2}[ah]
            if op == 0:
                require(u.reg_read(UC_X86_REG_AX)&255 == 0, 'Open mode')
            ax, carry = service(active['guest'], op, u.reg_read(UC_X86_REG_BX), u.reg_read(UC_X86_REG_DS),
                                u.reg_read(UC_X86_REG_DX), u.reg_read(UC_X86_REG_CX),
                                lambda at, data: u.mem_write(at, data) if data else None)
            u.reg_write(UC_X86_REG_AX, ax)
            u.reg_write(UC_X86_REG_EFLAGS, (u.reg_read(UC_X86_REG_EFLAGS)&~1)|carry)

        uc.hook_add(UC_HOOK_CODE, code_hook)
        uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
        uc.hook_add(UC_HOOK_INTR, interrupt)
        cases = [(size, None, 0) for size in [0,1,15,0x3fff,0x4000,0x4001,0x8000,0x8001,0xc000]]
        cases += [(0xc000, 'open', 0)] + [(0xc000, index, partial) for index in [0,1,2] for partial in [0,7]]
        for size, fail, partial in cases:
            file_bytes = bytes((i*37+13)&255 for i in range(size))
            for segment in [0x4000, 0x9000, 0xfc00]:
                for offset in [0, 1, 0xc000]:
                    # Full last physical block then zero-byte EOF at0000:0000:
                    # actual data stays below1MiB; only synthetic guard bytes
                    # above1MiB are mapped. No A20 behavior is inferred.
                    if segment == 0xfc00 and (size != 0x4000 or fail is not None or offset != 0):
                        continue
                    for handle in [0, 0xffff]:
                        for close_carry in [0, 1]:
                            pool_start = segment*16+offset-8
                            pool_length = 0x10010
                            baseline = b'\xa5'*pool_length
                            uc.mem_write(pool_start, baseline)
                            uc.mem_write(ss*16+sp-32, b'\xa5'*32+struct.pack('<5H', 0x100, 0x8000, 0x120, offset, segment))
                            active.update(file=file_bytes, fail=fail, partial_error_bytes=partial, segment=segment, offset=offset,
                                          handle=handle, close_carry=close_carry, instructions=0, fatal=False,
                                          guest={'events':[], 'reads':0, 'position':0})
                            preserved = [(UC_X86_REG_DS, ds), (UC_X86_REG_SS, ss), (UC_X86_REG_ES, 0x6789),
                                         (UC_X86_REG_BP, 0x5678), (UC_X86_REG_SI, 0x4567), (UC_X86_REG_DI, 0x3456)]
                            for reg, value in preserved + [(UC_X86_REG_CS,cs), (UC_X86_REG_IP,0x6aa2), (UC_X86_REG_SP,sp),
                                (UC_X86_REG_EFLAGS,0x603), (UC_X86_REG_AX,0xbeef), (UC_X86_REG_BX,0xabcd)]:
                                uc.reg_write(reg, value)
                            uc.emu_start(cs*16+0x6aa2, 0x80100, count=1024)
                            memory = bytearray(baseline)
                            model = {'events':[], 'reads':0, 'position':0}
                            errors = []

                            def native_service(context, request_ptr, response_ptr):
                                try:
                                    request = request_ptr.contents
                                    def write_bytes(at, data):
                                        if not data:
                                            return
                                        require(pool_start <= at and at+len(data) <= pool_start+pool_length, 'Native memory fence')
                                        memory[at-pool_start:at-pool_start+len(data)] = data
                                    ax, carry = service(model, request.operation, request.handle, request.segment, request.offset, request.count, write_bytes)
                                    response_ptr.contents.ax, response_ptr.contents.carry = ax, carry
                                    return 1
                                except Exception as error:
                                    errors.append(str(error))
                                    return 0

                            callback = Service(native_service)
                            result = Result()
                            native(callback, None, ds, 0x120, offset, segment, 16, ctypes.byref(result))
                            require(not errors, 'Native service: '+str(errors))
                            require(model == active['guest'], 'Service/event order mismatch')
                            require(bytes(memory) == bytes(uc.mem_read(pool_start, pool_length)), 'Partial/full destination memory mismatch')
                            fatal = fail is not None
                            require(result.status == int(fatal) == int(active['fatal']), 'Fatal prefix/normal status')
                            successful = model['reads'] - int(isinstance(fail, int))
                            require(result.successful_reads == successful and result.next_segment == (segment+0x400*successful)&65535, 'Local segment/read count')
                            require(struct.unpack('<H', bytes(uc.mem_read(ss*16+sp-8,2)))[0] == result.next_segment, 'Original BP-6 local segment')
                            if fatal:
                                require(uc.reg_read(UC_X86_REG_CS) == cs and uc.reg_read(UC_X86_REG_IP) == 0x6afd and uc.reg_read(UC_X86_REG_SP) == sp-14, 'Fatal frame/fence')
                                require(uc.reg_read(UC_X86_REG_DS) == load+0x178f and uc.reg_read(UC_X86_REG_AX) == 0x64e0, 'Fatal reporting DS/message')
                                require(result.failed_operation == (0 if fail == 'open' else 1) and not any(e[0] == 2 for e in model['events']), 'Fatal no-close policy')
                            else:
                                require(uc.reg_read(UC_X86_REG_CS) == 0x8000 and uc.reg_read(UC_X86_REG_IP) == 0x100 and uc.reg_read(UC_X86_REG_SP) == sp+4, 'Normal far return/frame')
                                require(all(uc.reg_read(reg) == value for reg,value in preserved), 'Normal preserved registers/segments')
                                require(uc.reg_read(UC_X86_REG_AX) == result.return_offset == offset and uc.reg_read(UC_X86_REG_DX) == result.return_segment == segment, 'Returned original far data coordinates')
                            require(result.handle_valid == int(fail != 'open') and (not result.handle_valid or result.handle == handle), 'Handle validity')
                            rows.append({'load_segment':load,'file_size':size,'fail':fail,'error_written_bytes':partial,
                                         'destination_segment':segment,'destination_offset':offset,'handle':handle,
                                         'close_carry':close_carry,'status':result.status,'successful_reads':successful,
                                         'instructions':active['instructions']})
    diagnostics = 0
    for service_fn, budget in [(Service(), 16), (Service(lambda context, req, res:0), 16),
                               (Service(lambda context, req, res:1), 0)]:
        result = Result()
        native(service_fn, None, 0, 0, 0, 0, budget, ctypes.byref(result))
        require(result.status == 2, 'Native service/budget diagnostic')
        diagnostics += 1
    native(Service(), None, 0, 0, 0, 0, 0, None)
    diagnostics += 1
    result = {'schema':1,'result':'pass','function_id':'FN-EGA-000168','image_sha256':sha,
              'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_raw_load.c').read_bytes()).hexdigest(),
              'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'vectors':len(rows),
              'native_only_diagnostics':diagnostics,'original_instructions_executed':sum(r['instructions'] for r in rows),
              'cases':rows,'limits':'Synthetic service profile preserves nonresponse DOS registers andusesordinarymappedbytepools; caller bounds/realDOS filesystem, fatalcleanup andcompleteplatform behavior remainopen. No suppliedfilebytesdecoded or game session. Nativeworkbudget/servicefault diagnostics areoutside original contract.'}
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cases'},indent=2))


if __name__ == '__main__':
    main()
