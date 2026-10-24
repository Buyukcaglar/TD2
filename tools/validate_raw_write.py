"""Compare raw create/write wrappers with synthetic DOS and error-call fences."""
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
from validate_small_platform import Registers,StateRegisters,Request,Service,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['services','write_requests','successful_writes','bus_writes','error_calls']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_raw_write;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:7866','06C9:7874'] for ip in f['instructions']};int_sites={0x7889,0x78c7,0x78ec};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter()
    def event(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
    def response(q,profile,error_plan,write_index,entry):
        rr=StateRegisters.from_buffer_copy(bytes(q.incoming));stage=0 if q.site==0x7889 else 1 if q.site==0x78c7 else 2;rr.carry=int(error_plan==1 and stage==0 or error_plan==2 and stage==1 and write_index==1 or error_plan==3 and stage==1 and write_index==2 or error_plan==4 and stage==2)
        if stage==0:rr.registers.ax=0xbeef if profile&1 else 0x1234
        elif stage==1:rr.registers.ax=[q.incoming.registers.cx,0,1,0xffff,7][profile]
        else:rr.registers.ax=0xdead
        mutations=[]
        if profile:
            rr.registers.ds=0x7100+stage*0x100;rr.registers.interrupts_enabled=profile&1;rr.registers.direction=(profile>>1)&1
        if profile==2:
            rr.registers.cx=0xa500+stage;rr.registers.dx=0xb600+stage;rr.registers.bx=0xc700+stage;rr.registers.si=0xd800+stage;rr.registers.di=0xe900+stage
        if profile==3:
            def at(offset):return ((q.stack_segment<<4)+((q.incoming.bp+offset)&65535))&0xfffff
            if stage==0:mutations +=[(at(6),struct.pack('<H',0x2900)),(at(-2),struct.pack('<H',0x7200))]
            if stage==1 and write_index==1 and rr.carry==0:mutations +=[(at(12),struct.pack('<2H',1,0)),(at(10),struct.pack('<H',0xfc00))]
        if profile==4 and stage==0:rr.bp=(rr.bp+32)&65535
        return rr,mutations
    for load in [0x1000,0x2345]:
        cs,ds,error_cs=load+0x6c9,load+0x178f,load+0x16a7;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def read_regs():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def code(cpu,address,size,unused):
            actual_cs,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if actual_cs==error_cs and ip==2:
                current=u.reg_read(UC_X86_REG_SP);words=struct.unpack('<4H',u.mem_read(active['ss']*16+current,8));require(words[:2]==(0x78e7,cs),'Error far frame');active['error_boundary']=True;active['error_words']=list(words);u.emu_stop();return
            require(actual_cs==cs and ip in fence,'Raw writer escaped '+hex(address))
            if ip in int_sites:
                if len(active['events'])==active['limit']:active['prefix']=True;u.emu_stop();return
                active['pending']=Request(0x21,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),read_regs())
            active['instructions']+=1;active['sites'].add(ip)
        def interrupt(cpu,vector,unused):
            q=active['pending'];require(vector==0x21 and q is not None,'DOS boundary');active['events'].append(event(q))
            if q.site==0x78c7:active['write_requests']+=1
            rr,mutations=response(q,active['profile'],active['error_plan'],active['write_requests'],active['entry'])
            if q.site==0x78c7 and rr.carry==0:active['successful_writes']+=1
            if q.site==0x78ec and active['error_plan']==1:active['stale_close']+=1
            for at,payload in mutations:u.mem_write(at,payload)
            for reg,v in zip(regs,values(rr.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,rr.bp);f=u.reg_read(UC_X86_REG_EFLAGS);u.reg_write(UC_X86_REG_EFLAGS,(f&~0x601)|rr.carry|(rr.registers.interrupts_enabled<<9)|(rr.registers.direction<<10));active['pending']=None
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_MEM_WRITE,written)
        cases=itertools.product(range(2),[0,1,0x3fff,0x4000,0x4001,0x7fff,0x10000,0xffffffff],range(5),range(5),[0,1],[2,0x203,0x402,0x603],[0,1,2,3,4,8])
        for entry,length,profile,error_plan,same,flags,limit in cases:
            data=bytearray(base);ss=ds if same else 0x9000;buffer_segment=0xfc00 if flags&1 else 0x6000;args_words=[0x2800,0x1000,buffer_segment,length&65535,length>>16];frame=struct.pack('<2H',0x100,0x1111);tail=struct.pack('<5H',*args_words)+b'\x5a\xa5'*4;data[ss*16+sp-32:ss*16+sp+4+len(tail)]=b'\xa5'*32+frame+tail;struct.pack_into('<H',data,ss*16+sp-10,0xabcd)
            # An explicit shadow frame admits returnedBP+32 without assuming DOS preservesBP.
            shadow=sp-2+32
            for offset,value in [(-10,entry),(-8,0xabcd),(-2,ds),(6,0x2800),(8,0x1000),(10,buffer_segment),(12,length&65535),(14,length>>16)]:struct.pack_into('<H',data,ss*16+shadow+offset,value)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7866 if entry==0 else 0x7874),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(ss=ss,limit=limit,profile=profile,error_plan=error_plan,entry=entry,prefix=False,error_boundary=False,error_words=None,pending=None,events=[],write_requests=0,successful_writes=0,stale_close=0,writes=0,instructions=0,sites=set());u.emu_start(cs*16+(0x7866 if entry==0 else 0x7874),0x11210,count=10000);label=f'{load:x}/{entry}/{length:x}/{profile}/{error_plan}/{same}/{flags:x}/{limit}';require(active['prefix'] or active['error_boundary'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original return/boundary '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];write_requests=0;successful_writes=0
            def callback(ctx,memory,request,returned):
                nonlocal write_requests,successful_writes
                try:
                    q=request.contents;events.append(event(q))
                    if q.site==0x78c7:write_requests+=1
                    rr,mutations=response(q,profile,error_plan,write_requests,entry)
                    if q.site==0x78c7 and rr.carry==0:successful_writes+=1
                    for at,payload in mutations:C.memmove(C.byref(bus,at),payload,len(payload))
                    C.memmove(returned,C.byref(rr),C.sizeof(StateRegisters));return 1
                except Exception as exc:errors.append(str(exc));return 0
            adapter=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),adapter,None,limit,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 1 if active['error_boundary'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.services==len(events) and events==active['events'] and out.write_requests==active['write_requests']==write_requests and out.successful_writes==active['successful_writes']==successful_writes and out.bus_writes==active['writes'] and out.error_calls==int(active['error_boundary']),'Native services/outcome '+label+str(errors));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus includingcallerlengths/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Farreturn/errorcalltarget '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['prefix' if active['prefix'] else 'error_call_boundaries' if active['error_boundary'] else 'far_returns']+=1;coverage['DOS_services']+=out.services;coverage['write_requests']+=out.write_requests;coverage['successful_writes']+=out.successful_writes;coverage['stale_create_failure_close_calls']+=active['stale_close'];coverage['bus_write_events']+=out.bus_writes
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised writer locations '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000192','FN-EGA-000193'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_raw_write.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_small_platform.py','tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Two rawcreate/write/close wrappers withsyntheticDOS3C/40/3E, fullreturnedDS/BP/CFIFDF andsharedbus includingcallerlength/source-segment/savedframes. LengthSUB/SBB beforewrite,400segmentadvance evenaftershortsuccess, stalehandleclose onoptionalcreatefailure andignoredcloseCF retained. Before-INTnativebudgetprefix separate; policy0errors stopatactual16A7:0002farcalleeentry afterpreparednearargs/farframe. ErrorcalleeFN348 contractpending, no body/no-return/normalhandler-return assumption admitted. SyntheticINT profile omitsrealinterruptframes/OS/files, noactualfile writes/resource decode/device/session/core/game/fidelity. Allactualproducer/caller/capacity/lifetime/IRQ/errorhandler integration andresource-fedP2/P3 remainopen; nativeinvalid/adapterchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
