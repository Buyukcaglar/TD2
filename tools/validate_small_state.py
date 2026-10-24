"""Compare finite state/read/copy helpers, preserving literal086C and raw returns."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['reads','writes']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();library=args.library.resolve();output=args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));fn=dll.td2ega_small_state
    fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None
    ids=[132,437,138,139,249,250,346,204,313,318,24,317,415,416]
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    records=[next(r for r in registry if r['id']==f'FN-EGA-{i:06d}') for i in ids]
    entries=[(r['entries'][0]['segment'],r['entries'][0]['segment_offset']) for r in records]
    graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text())
    wanted={f'{s:04X}:{o:04X}' for s,o in entries}
    fence={(int(f['entry'][:4],16),ip) for f in graph['functions'] if f['entry'] in wanted for ip in f['instructions']}
    regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
    vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536)
        u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP))
            require(pair in fence,'Small helper escaped '+str(pair))
            active['instructions']+=1;active['sites'].add(pair)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No OS/BIOS call in finite bodies')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry in range(14):
            first=[0,1,7,0x7fff,0x8000,0xffff]
            second=[0,1,0xff,0xffff]
            if entry in [12,13]:first=[0,0x681f,0x6820,0x6821,0x6822,0x6836,0xfff5,0xffff]
            if entry==6:second=list(range(256));first=[0,1,0x8000,0xffff]
            for a,b,same,flags in itertools.product(first,second,[0,1],[2,0x203,0x402,0x603]):
                data=bytearray(base);ss=ds if same else 0x9000;segment,ip=entries[entry];cs=load+segment;near=entry in [1,8]
                def put(seg,offset,v):struct.pack_into('<H',data,((seg<<4)+(offset&65535))&0xfffff,v&65535)
                put(0x40,0x46c,a);put(0x40,0x6c,a^0xffff)
                for offset,v in [(0x5e90,a),(0x5e92,b),(0x6d97,a),(0x6dd4,a),(0x6820,0x1234),(0x6822,0x5678)]:put(ds,offset,v)
                for i in range(24):data[ds*16+0x681f+i]=(i*37+a)&255
                # Reapply direct fields after patterned copy-source initialization.
                if entry==7:put(ds,0x6820,0x1234);put(ds,0x6822,0x5678)
                frame=struct.pack('<H',0x100) if near else struct.pack('<2H',0x100,0x1111)
                arguments=struct.pack('<2H',a,b);guard=b'\x5a\xa5'*4
                data[ss*16+sp-16:ss*16+sp+len(frame)+12]=b'\xa5'*16+frame+arguments+guard
                incoming=StateRegisters(Registers(a,0xb123,((a&255)<<8)|(b&255),b,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
                u.mem_write(0,bytes(data))
                for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
                active.update(writes=0,instructions=0,sites=set());end=cs*16+0x100 if near else 0x11210
                u.emu_start(cs*16+ip,end,count=10000)
                label=f'{load:x}/{entry}/{a:x}/{b:x}/{same}/{flags:x}'
                require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs if near else 0x1111,0x100,sp+len(frame)),'Original return '+label)
                bus=(C.c_uint8*len(data)).from_buffer_copy(data);result=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),C.byref(result))
                require(result.status==0 and result.current_sp==u.reg_read(UC_X86_REG_SP) and (result.next_segment,result.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Native return '+label)
                require(result.writes==active['writes'] and bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/frame/write count '+label)
                r=result.returned
                require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label)
                f=u.reg_read(UC_X86_REG_EFLAGS)
                require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CF/IF/DF '+label)
                require(bytes(u.mem_read(ss*16+sp,len(frame)+12))==frame+arguments+guard,'Root arguments/guard '+label)
                vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['bus_write_events']+=result.writes
            print(json.dumps({'load':hex(load),'entry':entry,'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised finite instruction sites '+str(fence-sites))
    record={'schema':1,'result':'pass','function_ids':[r['id'] for r in records],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_small_state.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Fourteen finite bodies, actualnestedC692 inC69C, fullbusincludingSSframe/GPR/BP/CFIFDF andnear/farreturns. Literal0040:046C physical086C distinguishedfromcanonical0040:006C; no timer/frequency/sourcewriter semantics assigned. RawDSownedcounter/arithmetic, nearoffsetselector, CLbytecount, orderedpairedstatewords/byteflag and22byteforwardcopy retained. Noallcaller/bounds/aliases/IRQexclusion/lifetime, realBIOS/DOS/session/render/audio/core/gameplay/fidelity acceptance. Nativeinvalidchecks separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))

if __name__=='__main__':main()
