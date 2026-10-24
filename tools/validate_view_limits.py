"""Compare2542/268A flag/owner limits, signed branches, aliases and returned CF."""
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
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('calls',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));finish=dll.td2ega_finish_limits;finish.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(Result)];finish.restype=None;limit=dll.td2ega_limit_value;limit.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(StateRegisters)];limit.restype=C.c_uint16
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:2542','06C9:268A']];require(len(fenced)==2,'Limitstagefences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000;group=bytes((i*37+11)&255 for i in range(65536));bounds=[0,1,5,6,79,80,0x7fff,0x8000,0xffff];selectors=[0,2,48,0x1c0,0x1d4,0x1d6,0xfffe,0xffff]
    cases=[('value',flags,v,p) for flags,v,p in itertools.product(range(256),bounds,range(6))]+[('finish',flags,v,p) for flags,v,p in itertools.product(range(256),bounds,range(4))]
    profiles=[(0,0,0,0,80),(2,4,0,1,79),(2,0,4,80,0),(0x8000,0x7fff,0xffff,0x8000,0xffff),(0x7fff,0x8000,0,0xffff,0x7fff),(0xffff,0xffff,0x8000,0x7fff,0x8000)]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=group;starts={cs*16+ip for f in fenced for ip in f['instructions']};active={}
        def code(cpu,address,size,_):
            require(address in starts,'Limitsescapedfence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address==cs*16+0x268a:active['calls']+=1
        def interrupt(*_):raise RuntimeError('Unexpectedinterrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for kind,flags,value,profile in cases:
            data=bytearray(base);ss=ds if vectors&1 else 0x9000
            def put(at,v):struct.pack_into('<H',data,ds*16+(at&65535),v&65535)
            if kind=='value':
                si,left,right,lower,upper=profiles[profile];put(0x2c6a,left);put(0x2c6c,right);put(0x2c66,lower);put(0x2c2c,upper)
            else:
                index=bounds.index(value);first=selectors[index%8];second=selectors[(index+2)%8];si=0x3456
                for selected,v in [(first,value),(second,value^0x7fff)]:put(selected+0x2a5e,v);put(selected+0x2ac2,(-v)&65535)
                put(0x2b26,value);put(0x2b56,value^0x8000);owner_pairs=[(0,0),(0,48),(48,0),(0x8000,0x7fff)];owner,other=owner_pairs[profile]
                fields={0x2c2e:value,0x2c68:value^0xffff,0x2c66:value,0x2c2c:bounds[(index+4)%len(bounds)],0x2c6e:0,0x2c70:48,0x2c2a:[0,17,0x8000,0xffff][profile],0x2c7e:value,0x2c78:profile&1,0x2c72:other,0x2c80:owner,0x2c6a:other,0x2c6c:owner,0x2c74:first,0x2c76:second,0x2c32:value^0x5a5a,0x2c34:value^0xa5a5,0x2c82:0xdead,0x2c84:0xbeef,0x2c86:0x1111,0x2c88:0x2222}
                for at,v in fields.items():put(at,v)
                data[ds*16+0x2c9a]=128 if profile&1 else 0;data[ds*16+0x2c9b]=128 if profile&2 else 0
            data[ds*16+0x2c98]=flags;frame=struct.pack('<H',0x100);data[ss*16+sp-2:ss*16+sp+6]=b'\xa5'*2+frame+b'\xa5'*4;u.mem_write(0,bytes(data));cpu_flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(value,0xb123,0xc456,0xd789,si,0x2345,ds,0x5432,(cpu_flags>>9)&1,(cpu_flags>>10)&1),0x5678,cpu_flags&1);entry=0x268a if kind=='value' else 0x2542
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_EFLAGS,cpu_flags)]:u.reg_write(reg,val)
            active.update(calls=0,instructions=0,sites=set());u.emu_start(cs*16+entry,cs*16+0x100,count=1024);label=f'{load:x}/{kind}/{flags:x}/{value:x}/{profile}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'OriginalplainnearRET '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data)
            if kind=='value':r=StateRegisters();require(limit(bus,len(bus),C.byref(incoming),C.byref(r))==0,'Nativereadonlystatus');require(active['calls']==1,'Standalonehelperentry')
            else:out=Result();finish(bus,len(bus),C.byref(incoming),C.byref(out));require(out.status==0 and out.calls==active['calls'],'Nativefinishcalls '+label);r=out.returned;coverage['actual_helper_calls']+=out.calls
            actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus)
            if kind=='finish':actual[ss*16+sp-2:ss*16+sp]=expected[ss*16+sp-2:ss*16+sp]
            require(actual==expected,'Fullbus/orderedaliasfields '+label);require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearframeguard '+label)
            if kind=='finish' and flags:
                require(all(0<=struct.unpack_from('<H',bus,ds*16+at)[0]<=80 for at in [0x2c66,0x2c2c]),'Finishedboundrange '+label)
                if flags&128:require(all(0<=struct.unpack_from('<H',bus,ds*16+at)[0]<=80 for at in [0x2c82,0x2c32,0x2c34,0x2c84]),'Fourfinishedvalueranges '+label)
            coverage[kind]+=1;coverage['same_DS_SS_'+str(ss==ds)]+=1;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
        print(json.dumps({'load_segment':hex(load),'vectors_completed':vectors}))
    require(len(sites)==len(starts),'Alllimitinstructionlocations '+str(sorted(address-cs*16 for address in starts if address-cs*16 not in sites)));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000091','FN-EGA-000092'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_view_limits.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete2542+actual268A/standalone268A, all256flagbytes, signedowner/limit/zero/highbit/wrapadjustments, currentDS selectors andorderedinput-outputaliases, returnedGPR/BP/CFIFDF/plainnearRET compared. Finishedbounds0..80 checked, 2C2Aownerwriter notnormalized. No actualcaller/producer/SS-DS/tablegeometry/resource/IRQ/renderer/core/game/fidelity; native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
