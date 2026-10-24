"""Compare actual26D8+89A2+916C bodies and their retained SS argument pools."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from validate_line_draw import Registers, StateRegisters, Request, Service, Result, require, values
from validate_draw_sequence import Service as ParentService, Result as ParentResult
from validate_sprite_draw import Result as SpriteResult
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86 import X86_OP_MEM, X86_REG_ES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(ROOT / 'docs/recovery/evidence') and not output.exists(), 'Fresh receipt')
    image = (ROOT / 'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    require(sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Image identity')
    mz = (ROOT / 'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest() == '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2', 'MZ identity')
    n, t = struct.unpack_from('<H', mz, 6)[0], struct.unpack_from('<H', mz, 24)[0]
    relocs = [struct.unpack_from('<H', mz, t+4*i)[0]+16*struct.unpack_from('<H', mz, t+4*i+2)[0] for i in range(n)]
    libraries = ['analysis/build/draw-sequence-repro/td2ega_draw_sequence.dll', 'analysis/build/rectangle-draw-repro/td2ega_rectangle_draw.dll', 'analysis/build/sprite-draw-repro-v2/td2ega_sprite_draw.dll']
    dlls = [C.CDLL(str(ROOT / p)) for p in libraries]
    fill, rectangle, sprite = dlls[0].td2ega_draw_sequence, dlls[1].td2ega_rectangle_draw, dlls[2].td2ega_sprite_draw
    common = [C.POINTER(C.c_uint8), C.c_uint32, C.c_uint16, C.c_uint16, C.c_uint16, C.c_uint16, C.POINTER(StateRegisters)]
    fill.argtypes = common+[ParentService, C.c_void_p, C.c_uint32, C.POINTER(ParentResult)]
    rectangle.argtypes = common+[Service, C.c_void_p, C.c_uint32, C.POINTER(Result)]
    sprite.argtypes = common+[Service, C.c_void_p, C.c_uint32, C.POINTER(SpriteResult)]
    for fn in [fill, rectangle, sprite]:
        fn.restype = None
    flow_path = 'analysis/flow/indirect-v8/direct-flow.json'
    graph = json.loads((ROOT / flow_path).read_text())
    entries = [0x26d8, 0x89a2, 0x916c, 0x82d0, 0x8336, 0x839c, 0xad22, 0xad8b, 0xadf4]
    functions = [f for f in graph['functions'] if f['entry'] in [f'06C9:{e:04X}' for e in entries]]
    require(len(functions) == len(entries), 'Entry fence')
    fence = {ip for f in functions for ip in f['instructions']}
    far_calls = {int(c['site'][5:], 16): (int(c['target'][5:], 16), int(c['site'][5:], 16)+c['size']) for f in functions for c in f['calls'] if c['kind'] == 'lcall'}
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    out_sites, reads, writes, reps = set(), {}, {}, set()
    rect_reads = {0x8b97, 0x8bd7, 0x8bfa, 0x8c1e, 0x8c44, 0x8c69}
    rect_writes = {0x8b9a, 0x8bda, 0x8bfd, 0x8c21, 0x8c47, 0x8c6c}
    for ip in fence:
        ins = next(md.disasm(image[0x6c90+ip:0x6c90+ip+15], ip, count=1))
        if ins.mnemonic == 'out':
            out_sites.add(ip)
        if ins.mnemonic.startswith('rep'):
            reps.add(ip)
        hardware = 0x9835 <= ip <= 0x9c2e or 0xad22 <= ip <= 0xae60
        if ip in rect_reads or hardware and ins.mnemonic == 'mov' and len(ins.operands) > 1 and ins.operands[1].type == X86_OP_MEM and ins.operands[1].mem.segment == X86_REG_ES:
            reads[ip] = True
        if ip in rect_writes:
            writes[ip] = 'al'
        elif hardware:
            if ins.mnemonic.endswith('movsb'):
                writes[ip] = 'source'
            elif ins.mnemonic.endswith('stosb'):
                writes[ip] = 'al'
            elif ins.operands and ins.operands[0].type == X86_OP_MEM and ins.operands[0].mem.segment == X86_REG_ES:
                writes[ip] = ins.op_str.split(',')[-1].strip()
    regs = [UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_DS, UC_X86_REG_ES]
    sp = 0xe000
    vectors = instructions = 0
    exercised = set()
    coverage = Counter()

    def far_event(site, target, ss, current, words, incoming):
        return ['far', site, target, ss, current, len(words), words, values(incoming.registers), incoming.bp, incoming.carry]

    def io_event(q):
        return ['bus', q.kind, q.site, q.stack_segment, q.stack_sp, q.port, q.value, q.address, values(q.incoming.registers), q.incoming.bp, q.incoming.carry]

    for load in [0x1000, 0x2345]:
        cs, ds = load+0x6c9, load+0x178f
        relocated = bytearray(image)
        for at in relocs:
            struct.pack_into('<H', relocated, at, (struct.unpack_from('<H', relocated, at)[0]+load)&65535)
        base = bytearray([0xa5])*0x100000
        base[load*16:load*16+len(relocated)] = relocated
        base[ds*16:ds*16+65536] = bytes(65536)
        u = Uc(UC_ARCH_X86, UC_MODE_16)
        u.mem_map(0, 0x100000)
        active = {}

        def read_regs():
            flags = u.reg_read(UC_X86_REG_EFLAGS)
            return StateRegisters(Registers(*[u.reg_read(r) for r in regs], (flags>>9)&1, (flags>>10)&1), u.reg_read(UC_X86_REG_BP), flags&1)

        def code(cpu, address, size, unused):
            ip = address-cs*16
            if active['expected'] is not None:
                site, target, ret = active['expected']
                require(ip == target, 'Far target')
                current = u.reg_read(UC_X86_REG_SP)
                require(bytes(u.mem_read(active['ss']*16+current, 4)) == struct.pack('<2H', ret, cs), 'Far frame')
                live = (sp-current-4)//2
                require(live == 5 if target == 0x89a2 else live in [16, 12, 8, 4], 'Prepared pools')
                words = list(struct.unpack('<'+'H'*live, u.mem_read(active['ss']*16+current+4, live*2)))
                active['events'].append(far_event(site, target, active['ss'], current, words, read_regs()))
                active['expected'] = None
            require(ip in fence, 'Composition escaped '+hex(address))
            active['instructions'] += 1
            active['sites'].add(ip)
            if ip in far_calls:
                target, ret = far_calls[ip]
                require(target in [0x89a2, 0x916c], 'Unexpected far child')
                active['expected'] = (ip, target, ret)
            if ip in out_sites | reads.keys() | writes.keys() and (ip not in reps or u.reg_read(UC_X86_REG_CX)):
                rr = read_regs()
                kind = 1 if ip in out_sites else 2 if ip in reads else 3
                physical = ((rr.registers.es<<4)+rr.registers.di)&0xfffff if kind != 1 else 0
                if kind == 2:
                    value = bytes(u.mem_read(physical, 1))[0]
                elif kind == 1:
                    value = rr.registers.ax&255
                elif writes[ip] == 'source':
                    value = bytes(u.mem_read(((rr.registers.ds<<4)+rr.registers.si)&0xfffff, 1))[0]
                else:
                    name = writes[ip]
                    whole = {'al': rr.registers.ax, 'ah': rr.registers.ax, 'cl': rr.registers.cx, 'dl': rr.registers.dx}[name]
                    value = (whole>>8)&255 if name == 'ah' else whole&255
                q = Request(kind, ip, cs, 0, active['ss'], u.reg_read(UC_X86_REG_SP), rr.registers.dx, value, (C.c_uint16*5)(), physical, rr)
                active['events'].append(io_event(q))

        def out_hook(cpu, port, size, value, unused):
            require(size == 1 and active['events'][-1][5:7] == [port, value], 'OUT event')
            active['outs'] += 1

        def interrupt(*unused):
            raise RuntimeError('Unexpected interrupt/fault in normal composition')

        u.hook_add(UC_HOOK_CODE, code)
        u.hook_add(UC_HOOK_INSN, out_hook, None, 1, 0, UC_X86_INS_OUT)
        u.hook_add(UC_HOOK_INTR, interrupt)
        cases = itertools.product([7, 157, 257, 511], range(4), range(4), [0, 4, 16], [2, 0x203, 0x402, 0x603], [0, 1])
        for position, plane, header, y, flags, same in cases:
            data = bytearray(base)
            ss = ds if same else 0x9000

            def pw(segment, offset, value):
                struct.pack_into('<H', data, ((segment<<4)+(offset&65535))&0xfffff, value&65535)

            def pb(segment, offset, value):
                data[((segment<<4)+(offset&65535))&0xfffff] = value&255

            planes = [0x5000, 0x6000, 0x7000, 0x8000] if plane == 0 else [0, 0x6000, 0, 0x8000] if plane == 1 else [0xa000, 0, 0, 0] if plane == 2 else [ds]*4
            for i, value in enumerate(planes):
                pw(cs, 0xaf3c+2*i, value)
            for at, value in {0xaf44: 0xb000, 0xaf46: 0, 0xaf48: 20, 0xaf4a: 0, 0xaf4c: 4, 0xaf4e: 32}.items():
                pw(cs, at, value)
            for row in range(-32, 65):
                pw(cs, 0xb000+2*row, 0x200+32*row)
            for i in range(8):
                pb(ds, 0x6838+i, 255>>i)
                pb(ds, 0x6840+i, (255<<(7-i))&255)
            for mask in range(16):
                index = (mask&-mask).bit_length()-1 if mask else 0
                pb(cs, 0x9144+mask, index)
                pb(cs, 0x9154+mask, 1<<index)
            for i in range(4):
                pb(cs, 0x9164+i, 255^(1<<i))
                pb(cs, 0x9168+i, 1<<i)
            for at, value in {0x2c2a: 8, 0x5350: 0x5a0f, 0x5344: position*2, 0x2f48: 0, 0x2b56: y, 0x27de: 0x1000, 0x27e0: 0x6000, 0x27e2: 0x1100, 0x27e4: 0x6000, 0x27e6: 0x1200, 0x27e8: 0x6000}.items():
                pw(ds, at, value)
            for offset in [0x1000, 0x1100, 0x1200]:
                for at, value in [(0, 4), (2, 3), (4, 0), (6, 0), (8, 0), (10, 0)]:
                    pw(0x6000, offset+at, value)
                packed = [[15, 0, 0, 0], [1, 2, 4, 8], [0x1f, 0x20, 0, 0], [15, 0, 0, 0x30]][header]
                for i, value in enumerate(packed):
                    pb(0x6000, offset+12+i, value)
                for i in range(128):
                    pb(0x6000, offset+16+i, i*37+offset//256)
            frame, guard = struct.pack('<H', 0x100), b'\xa5'*8
            data[ss*16+sp-128:ss*16+sp+10] = b'\xa5'*128+frame+guard
            incoming = StateRegisters(Registers(0xa55a, 0xb123, 0xc456, 0xd789, 0x3456, 0x2345, ds, 0x5432, (flags>>9)&1, (flags>>10)&1), 0x5678, flags&1)
            u.mem_write(0, bytes(data))
            for reg, value in list(zip(regs, values(incoming.registers)[:8]))+[(UC_X86_REG_BP, incoming.bp), (UC_X86_REG_SS, ss), (UC_X86_REG_SP, sp), (UC_X86_REG_CS, cs), (UC_X86_REG_IP, 0x26d8), (UC_X86_REG_EFLAGS, flags)]:
                u.reg_write(reg, value)
            active.update(ss=ss, expected=None, events=[], outs=0, instructions=0, sites=set())
            u.emu_start(cs*16+0x26d8, cs*16+0x100, count=1000000)
            label = f'{load:x}/{position}/{plane}/{header}/{y}/{flags:x}/{same}'
            require((u.reg_read(UC_X86_REG_CS), u.reg_read(UC_X86_REG_IP), u.reg_read(UC_X86_REG_SP)) == (cs, 0x100, sp+2), 'Original near return '+label)
            bus = (C.c_uint8*len(data)).from_buffer_copy(data)
            events, errors = [], []
            children = Counter()

            def bus_callback(ctx, memory, request, response):
                try:
                    q = request.contents
                    require(q.kind in [1, 2, 3], 'Byte adapter only')
                    events.append(io_event(q))
                    if q.kind == 2:
                        response.contents.value = bus[q.address]
                    elif q.kind == 3:
                        bus[q.address] = q.value
                    return 1
                except Exception as exc:
                    errors.append(str(exc))
                    return 0

            adapter = Service(bus_callback)

            def parent_callback(ctx, memory, request, response):
                try:
                    q = request.contents
                    require(q.kind == 1 and q.argument_count == (5 if q.offset == 0x89a2 else 4), 'Far child signature')
                    words = list(q.arguments)[:q.live_argument_count]
                    events.append(far_event(q.site, q.offset, q.stack_segment, q.stack_sp, words, q.incoming))
                    target, ret = far_calls[q.site]
                    require(target == q.offset, 'Native call target')
                    stack = struct.pack('<2H', ret, cs)+struct.pack('<'+'H'*len(words), *words)
                    C.memmove(C.byref(bus, q.stack_segment*16+q.stack_sp), stack, len(stack))
                    if q.offset == 0x89a2:
                        child = Result()
                        rectangle(memory, len(bus), load, q.stack_segment, q.stack_sp, 0, C.byref(q.incoming), adapter, None, 100000, C.byref(child))
                        children['rectangles'] += 1
                    elif q.offset == 0x916c:
                        child = SpriteResult()
                        sprite(memory, len(bus), load, q.stack_segment, q.stack_sp, 0, C.byref(q.incoming), adapter, None, 100000, C.byref(child))
                        children['sprites'] += 1
                        children['mask_calls'] += child.mask_calls
                        children['dispatches'] += child.dispatches
                        require((child.next_segment, child.next_ip) == (cs, ret), 'Sprite actual far-return words')
                    else:
                        raise RuntimeError('Unadmitted child')
                    require(child.status == 0 and child.current_sp == q.stack_sp+4, 'Child normal far return')
                    C.memmove(response, C.byref(child.returned), C.sizeof(StateRegisters))
                    return 1
                except Exception as exc:
                    errors.append(str(exc))
                    return 0

            parent = ParentService(parent_callback)
            result = ParentResult()
            fill(bus, len(bus), load, ss, sp, 0, C.byref(incoming), parent, None, 16, C.byref(result))
            require(not errors and result.status == 0 and result.current_sp == sp+2 and events == active['events'], 'Native chain/events '+label+str(errors))
            actual, expected = bytearray(u.mem_read(0, len(data))), bytearray(bus)
            actual[ss*16+sp-128:ss*16+sp] = expected[ss*16+sp-128:ss*16+sp]
            require(actual == expected, 'Full nonframe bus '+label)
            r = result.returned
            require([u.reg_read(reg) for reg in regs] == values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP) == r.bp, 'GPR/BP '+label)
            final_flags = u.reg_read(UC_X86_REG_EFLAGS)
            require((final_flags&1, (final_flags>>9)&1, (final_flags>>10)&1) == (r.carry, r.registers.interrupts_enabled, r.registers.direction), 'CF/IF/DF '+label)
            require(bytes(u.mem_read(ss*16+sp, 10)) == frame+guard, 'Root return/guard '+label)
            coverage.update(children)
            coverage['far_boundaries'] += sum(e[0] == 'far' for e in events)
            coverage['OUT_bytes'] += active['outs']
            coverage['device_reads'] += sum(e[0] == 'bus' and e[1] == 2 for e in events)
            coverage['device_writes'] += sum(e[0] == 'bus' and e[1] == 3 for e in events)
            vectors += 1
            instructions += active['instructions']
            exercised.update(active['sites'])
        print(json.dumps({'load': hex(load), 'vectors_completed': vectors}), flush=True)
    require(coverage['sprites'] == 4*vectors and coverage['rectangles'] == vectors and coverage['mask_calls'] > 0 and coverage['dispatches'] > 0, 'Actual chain coverage')
    dependencies = ['tools/validate_line_draw.py', 'tools/validate_draw_sequence.py', 'tools/validate_sprite_draw.py', 'tools/validate_state_loop.py']
    record = {'schema': 1, 'result': 'pass', 'vectors': vectors, 'image_sha256': sha, 'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'native_libraries': [{'path': p, 'sha256': hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in libraries], 'validator_dependencies': [{'path': p, 'sha256': hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in dependencies], 'flow_ledger': flow_path, 'flow_ledger_sha256': hashlib.sha256((ROOT/flow_path).read_bytes()).hexdigest(), 'entry_fence': [f'06C9:{e:04X}' for e in entries], 'instruction_sites_in_fence': len(fence), 'instruction_sites_exercised': len(exercised), 'original_instructions_executed': instructions, 'fixture_coverage': dict(coverage), 'limits': 'Actual26D8 near-return root,89A2 far child and all four916C far children with16/12/8/4 retained SS words, materialized far frames and actual near mask bodies; byte bus event/GPR/BP/CFIFDF/full nonframe bus comparison.128 private SS scratch bytes excluded because parent uses virtual argument pools; standalone sprite receipt separately compares full SS bus. Synthetic source packets, normal children only; budgets/faults remain separate helper contracts. No all-writer/caller/lifetime/exclusion/capacity, real EGA hardware, renderer, supplied-resource decode, DOS session, full state-machine/core/gameplay/fidelity acceptance. Scoped vectors separate from helper totals.'}
    output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k: record[k] for k in ['result', 'vectors', 'instruction_sites_in_fence', 'instruction_sites_exercised', 'original_instructions_executed', 'fixture_coverage']}, indent=2))


if __name__ == '__main__':
    main()
