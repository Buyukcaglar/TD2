"""Compare DOS3E wrapper plus actual shared near error mapper and root tail."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['services','error_calls','bus_writes']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
def state(cpu):
    flags=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in [UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]],(flags>>9)&1,(flags>>10)&1),cpu.reg_read(UC_X86_REG_BP),flags&1)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_close_handle;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());selected=[f for f in g['functions'] if f['entry'] in ['13A8:223E','13A8:094A']];fence={ip for f in selected for ip in f['instructions']};root_returns={0x92b,0x943};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Close wrapper escaped '+hex(address))
            if ip in root_returns or ip==0x973:active['return_kind']='near' if ip==0x973 else 'root';u.emu_stop();return
            if ip==0x2252 and active['limit']==0:active['prefix']=True;u.emu_stop();return
            if ip==0x939:active['error_calls']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(cpu,number,unused):
            require(number==0x21 and u.reg_read(UC_X86_REG_IP)==0x2254,'Only syntheticDOS3E boundary');r=state(u);require(r.registers.ax>>8==0x3e,'DOS3E request');active['requests'].append([number,0x2252,cs,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);returned=active['returned']
            for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
            if active['mutate']:
                u.mem_write(active['ss']*16+active['sp']-2,struct.pack('<H',0x1357));active['service_write_events']+=1
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        for handle,error,version,ds_mode,bp_mode,mutate,same,sp,flags,limit in itertools.product([0,19,20,0xffff],[0,1,0x13,0x20,0x21,0x22,0x8000,0xff01],[2,3],[0,1],[0,1],[0,1],[0,1],[20,0xe000,0x6da4,0x6d99],[2,0x603],[0,1]):
            data=bytearray(base);ss=ds if same else 0x9000;ret_ds=ds+0x100 if ds_mode else ds
            for segment in [ds,ret_ds]:
                data[segment*16+0x6d9d]=version;struct.pack_into('<H',data,segment*16+0x6da2,20)
                for k in range(20):data[segment*16+0x6dda+k]=(0x80+7*k)&255
            frame=struct.pack('<3H',0x1111,0x2222,handle);data[ss*16+sp-16:ss*16+sp+14]=b'\xa5'*16+frame+b'\xa5'*8;data[ss*16+0xd000:ss*16+0xd006]=struct.pack('<3H',0x7777,0x4444,0x5555);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);returned=StateRegisters(Registers(error,0xfff1 if mutate else 0xbada,0xcafe,0xd00d,0x1234,0x4321,ret_ds,0x2468,1-incoming.registers.interrupts_enabled,1-incoming.registers.direction),0xd000 if bp_mode else sp-2,int(error!=0));u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x223e),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(error_calls=0,limit=limit,ss=ss,sp=sp,returned=returned,mutate=mutate,service_write_events=0,writes=0,instructions=0,sites=set(),requests=[],executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0x223e,0,count=1000);label=f'{load:x}/{handle:x}/{error:x}/{version}/{ds_mode}/{bp_mode}/{mutate}/{same}/{sp:x}/{flags:x}/{limit}';require(active['prefix'] or active['return_kind'],'Outcome '+label);raw_near=False
            while active['return_kind']:
                kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;active['return_kind']=None
                if kind=='root':break
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))!=(cs,0x93c):raw_near=True;break
                u.emu_start(cs*16+0x93c,0,count=1000);require(active['return_kind']=='root','Root after mapper '+label)
            native_requests=[]
            @Service
            def callback(context,memory,request,out):
                q=request.contents;r=q.incoming;native_requests.append([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(r.registers),r.bp,r.carry]);out[0]=returned
                if mutate:at=ss*16+sp-2;memory[at]=0x57;memory[at+1]=0x13
                return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw_near else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.services==len(active['requests']) and out.error_calls==active['error_calls'] and out.bus_writes==active['writes'],'Status/count '+label);require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Whole bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix' if active['prefix'] else 'raw_near_return' if raw_near else 'root_far_return']+=1;coverage['raw_root_return']+=int(not active['prefix'] and not raw_near and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['syntheticDOSservices']+=out.services;coverage['actual_error_calls']+=out.error_calls;coverage['bus_write_events']+=out.bus_writes;coverage['service_write_events']+=active['service_write_events']
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['raw_near_return']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000310'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_close_handle.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual13A8:223E/shared0924-0939tails plus actual094Anearerror mapper, fullnestedSS/wholebus/GPR/BP/CFIFDF/actualrootfarreturn orrawchildnearreturn. Unsignedhandlelimit/rawinvalid0900error, successclearbyte6DA4+actualreturnedBX/DS. SyntheticDOS3Eservice fullreturnedregister/BP/DS/IFDF andbus mutations, SS/SP/CSpreserved, no realINTentry/return frames oractualDOS/fileoperations. NativebeforeINT/adapterdiagnostics separate. Caller/otherFLAGS/bounds/writers/lifetime/core/resourcefedP2/P3/device/session/game/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
