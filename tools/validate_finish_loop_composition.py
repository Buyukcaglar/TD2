"""Compare actual 1F71 and its complete eight-entry near/far body chain."""
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
from validate_loop_controls import Registers,StateRegisters,Request,Service,Result as RootResult,require,values
from validate_projection import Result as ProjectResult
from validate_record_interpolate import Result as InterpolateResult
from validate_view_limits import Result as LimitResult
from validate_near_clamp import Result as ClampResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();output=a.output.resolve();require(output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Fresh public receipt')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    libraries=['analysis/build/loop-controls-repro/td2ega_loop_controls.dll','analysis/build/projection-repro/td2ega_projection.dll','analysis/build/record-interpolate-repro/td2ega_record_interpolate.dll','analysis/build/view-limits-repro-v2/td2ega_view_limits.dll','analysis/build/near-clamp-repro/td2ega_near_clamp.dll'];dll=[C.CDLL(str(ROOT/x)) for x in libraries];root=dll[0].td2ega_loop_control;root.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(RootResult)];root.restype=None
    project=dll[1].td2ega_projection_step;project.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(ProjectResult)];project.restype=None
    interpolate=dll[2].td2ega_record_interpolate;interpolate.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(InterpolateResult)];interpolate.restype=None
    finish=dll[3].td2ega_finish_limits;finish.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(LimitResult)];finish.restype=None
    clamp=dll[4].td2ega_near_clamp;clamp.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(ClampResult)];clamp.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=['06C9:1F71','06C9:21C3','13A3:0038','06C9:2477','06C9:06C3','06C9:2542','06C9:268A','06C9:088E'];fenced=[f for f in graph['functions'] if f['entry'] in entries];require(len(fenced)==8,'Eight entry fence');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();forms=[(0x40,0x40),(0x48,0x48),(0x40,0x48),(0x48,0x40)];call_sites={0x1f7a:(0x21c3,0x1f7d),0x1f7d:(0x2477,0x1f80),0x1f80:(0x2542,0x1f83),0x1f89:(0x88e,0x1f8c)}
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={(load+int(f['entry'][:4],16))*16+ip for f in fenced for ip in f['instructions']}
        for flag,desc,same,flags,form in itertools.product([0,8,0x20,0x40,0x80,0x88,0xc0,0xff],[0,0x80],[0,1],[2,0x203,0x402,0x603],range(4)):
            ss=ds if same else 0x9000;data=bytearray(base);data[cs*16+0x71f],data[cs*16+0x735]=forms[form]
            def put(at,v):struct.pack_into('<H',data,ds*16+at,v&65535)
            for i in range(25):
                put(0x26f6+2*i,0);put(0x2728+2*i,0);put(0x275a+2*i,16);data[ds*16+0x3b80-i]=i|(128 if i&1 else 0)
            for i in range(128):put(0x347e+4*i,desc);put(0x3480+4*i,0)
            for i in range(129):put(0x5560+2*i,(i*257)&65535)
            for at,v in {0x2c26:0x3b80,0x700:0x3b33,0x2c2a:17,0x2c2c:80,0x2c2e:80,0x2c68:0,0x2c66:0,0x2c7e:0}.items():put(at,v)
            data[ds*16+0x2c97]=flag;data[ds*16+0x2c98]=flag;data[ds*16+0x37f6]=desc>>7
            for i in range(5*92):put(0x9c4+2*i,(i*7%150-30)&65535)
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+8]=b'\xa5'*64+frame+b'\xa5'*4
            u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x1f71),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            active={'instructions':0,'sites':set(),'events':[],'expected':None,'entries':Counter()}
            def read_regs():
                f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
            def event(q):return [q.kind,q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
            def code(cpu,address,size,_):
                if active['expected'] and address==cs*16+active['expected'][1]:
                    site,target,ret=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(current==sp-8 and bytes(u.mem_read(ss*16+current,2))==struct.pack('<H',ret),'Actual child near frame');q=Request(0,site,cs,target,0,0,ss,current,(C.c_uint16*10)(),read_regs());active['events'].append(event(q));active['expected']=None
                require(address in starts,'Composed body escaped fence '+hex(address));active['instructions']+=1;active['sites'].add(address-load*16)
                for f in fenced:
                    if address==(load+int(f['entry'][:4],16))*16+int(f['entry'][5:],16):active['entries'][f['entry']]+=1
                ip=address-cs*16
                if ip in call_sites:target,ret=call_sites[ip];active['expected']=(ip,target,ret)
            def interrupt(*_):raise RuntimeError('Unexpected original fault/interrupt in normal fixture')
            u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt);u.emu_start(cs*16+0x1f71,0x11210,count=200000);label=f'{load:x}/{flag:x}/{desc:x}/{same}/{flags:x}/{form}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original root RETF '+label)
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];children=Counter()
            def callback(ctx,m,q,r):
                try:
                    q=q.contents;events.append(event(q));require(q.kind==0 and q.argument_count==q.live_argument_count==0,'Expected near child only')
                    if q.offset==0x21c3:out=ProjectResult();project(m,len(bus),C.byref(q.incoming),4096,C.byref(out));children['lookups']+=out.lookups
                    elif q.offset==0x2477:out=InterpolateResult();interpolate(m,len(bus),load,q.stack_segment,q.stack_sp,C.byref(q.incoming),10000,C.byref(out));children['line_calls']+=out.helper_calls
                    elif q.offset==0x2542:out=LimitResult();finish(m,len(bus),C.byref(q.incoming),C.byref(out));children['limit_calls']+=out.calls
                    elif q.offset==0x88e:out=ClampResult();clamp(m,len(bus),C.byref(q.incoming),10000,C.byref(out));children['clamp_words']+=out.words
                    else:raise RuntimeError('Unexpected child')
                    require(out.status==0,'Child normal status '+hex(q.offset));C.memmove(r,C.byref(out.returned),C.sizeof(StateRegisters));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);out=RootResult();root(bus,len(bus),load,ss,sp,1,C.byref(incoming),cb,None,4,C.byref(out));require(not errors and out.status==0 and out.calls==4 and events==active['events'] and out.current_sp==sp+4 and out.return_bytes==4,'Native complete near chain '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonframe bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Returned registers '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'Root return/guard '+label);require(children['line_calls']==active['entries']['06C9:06C3'] and children['lookups']==active['entries']['13A3:0038'] and children['limit_calls']==active['entries']['06C9:268A'],'Actual nested body counts '+label)
            coverage.update(children);coverage['same_DS_SS_'+str(same)]+=1;coverage['initial_patch_form_'+str(form)]+=1;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
    deps=['tools/validate_loop_controls.py','tools/validate_projection.py','tools/validate_record_interpolate.py','tools/validate_view_limits.py','tools/validate_near_clamp.py','tools/validate_state_loop.py'];record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_libraries':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in libraries],'validator_dependencies':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in deps],'entry_fence':entries,'instruction_sites_in_fence':len(starts),'instruction_sites_exercised':len(sites),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual1F71+21C3/13A3:0038+2477/06C3+2542/268A+088E, four near body boundaries without ABI-value mocks. Synthetic zero-weight heights/width16/sentinel-empty list, boundednormal 2C2A/088E counts only. Equal/independent DS-SS views and four initial06C3 codeforms, freshCPU each fixture. Full nonframe bus/GPR/BP/CFIFDF/rootRETF4 compared. Entry fence not all-path coverage; no actual producer/resource-fed capacities/allwriters/SS-DS integration/IRQ exclusion/core/state/game/fidelity. Child fault/budget prefixes remain separate helper evidence. No hardware/OS services or DOS session.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
