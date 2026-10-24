"""Compare optional runtime far service and ordered saved-vector restores."""
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
from validate_runtime_message import Request as DOSRequest,Service as DOSService
from validate_finalizer_list import Request as CallbackRequest,Service as CallbackService
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['operations','services','callbacks','bus_writes']]+[('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_runtime_vectors;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='13A8:05E0')['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;base[0x90000]=base[0x94000]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def dos_response(r,profile,ss,qsp,sp,index):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if profile!=3:returned.registers.ax=0xa500+index;returned.registers.bx=0xbeef;returned.registers.cx=0xcafe;returned.registers.dx=0xd00d;returned.registers.si=0x1234;returned.registers.di=0x4321;returned.registers.ds=0x2468;returned.registers.es=0x3579;returned.bp=0x9999;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            else:returned.registers.ax=0;returned.carry=0
            if profile==1:mutations.append((ss*16+qsp,struct.pack('<H',ds+0x100 if index==0 else ds)))
            if profile==2:mutations.append((ss*16+sp,struct.pack('<H',0x5555)))
            return returned,mutations
        def callback_response(r,mode,ss,qsp):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if mode in [1,5]:returned.registers.ds=ds+0x100;returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.si=0x3456;returned.registers.di=0x4567;returned.registers.es=0x2468;returned.bp=0x8888;returned.carry^=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if mode==3:mutations.append((ss*16+qsp,struct.pack('<H',0x4444)))
            if mode==4:mutations.append((returned.registers.ds*16+0x6dc6,b'\0'))
            return returned,mutations
        def apply(returned,mutations):
            for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
            for at,value in mutations:u.mem_write(at,value)
            active['service_write_events']+=len(mutations)
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if segment==0x9000 and ip in [0,0x4000]:
                r=snapshot();active['callback_requests'].append([0x5e9,segment,ip,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);apply(*callback_response(r,active['mode'],active['ss'],u.reg_read(UC_X86_REG_SP)));active['return_kind']='callback';u.emu_stop();return
            require(segment==cs and ip in fence,'Runtime vectors escaped '+hex(address))
            if ip==0x60c:active['return_kind']='root';u.emu_stop();return
            if ip in [0x5e9,0x5f5,0x609]:
                if active['operations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['operations']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(cpu,number,unused):
            ip=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and ip in [0x5f5,0x609],'OnlyDOS25');r=snapshot();require(r.registers.ax>>8==0x25,'Setvectorrequest');index=len(active['dos_requests']);active['dos_requests'].append([number,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);apply(*dos_response(r,active['profile'],active['ss'],u.reg_read(UC_X86_REG_SP),active['sp'],index))
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        for mode,profile,same,sp,second,flags,limit in itertools.product(range(6),range(4),[0,1],[0xe000,0x6d8b,0x707a,0x6dc8,16],[0,1],[2,0x203,0x402,0x603],[0,1,2,3]):
            data=bytearray(base);ss=ds if same else 0x9000
            for segment in [ds,ds+0x100]:
                off=segment-ds;struct.pack_into('<2H',data,segment*16+0x7076,0 if mode==2 else 0x4000,0 if mode==0 else 0x9000);struct.pack_into('<2H',data,segment*16+0x6d89,0x1234+off,0x7000+off);struct.pack_into('<2H',data,segment*16+0x6dc8,0x5678+off,0x7100+off);data[segment*16+0x6dc6]=second if off==0 else 1-second;data[segment*16+0x6dc7]=0x23 if off==0 else 0x24
            # Root return only; preceding bytes retain deliberate table/save aliases.
            data[ss*16+sp:ss*16+sp+2]=struct.pack('<H',0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x5e0),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(mode=mode,profile=profile,ss=ss,sp=sp,limit=limit,operations=0,writes=0,instructions=0,sites=set(),dos_requests=[],callback_requests=[],service_write_events=0,executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0x5e0,0,count=1000);raw=False;root=False;synthetic_returns=0;label=f'{load:x}/{mode}/{profile}/{same}/{sp:x}/{second}/{flags:x}/{limit}'
            while active['return_kind']:
                kind=active['return_kind'];segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP);active['return_kind']=None;active['executing_return']=True;u.emu_start(segment*16+ip,0,count=1);active['executing_return']=False
                if kind=='root':sites.add(ip);active['instructions']+=1;root=True;break
                synthetic_returns+=1
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))!=(cs,0x5ed):raw=True;break
                u.emu_start(cs*16+0x5ed,0,count=1000)
            require(active['prefix'] or root or raw,'Outcome '+label);native_dos=[];native_callbacks=[]
            def mutate(memory,mutations):
                for at,value in mutations:
                    for k,b in enumerate(value):memory[at+k]=b
            @DOSService
            def dos(context,memory,q,out):
                request=q.contents;r=request.incoming;index=len(native_dos);native_dos.append([request.vector,request.site,request.segment,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned,mutations=dos_response(r,profile,ss,request.stack_sp,sp,index);out[0]=returned;mutate(memory,mutations);return 1
            @CallbackService
            def callback(context,memory,q,out):
                request=q.contents;r=request.incoming;native_callbacks.append([request.site,request.target_segment,request.target_ip,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned,mutations=callback_response(r,mode,ss,request.stack_sp);out[0]=returned;mutate(memory,mutations);return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),dos,callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.operations==active['operations'] and out.services==len(active['dos_requests']) and out.callbacks==len(active['callback_requests']) and out.bus_writes==active['writes'],'Status/count '+label);require(native_dos==active['dos_requests'] and native_callbacks==active['callback_requests'],'ServiceABI/postwriteLDS '+label+str((native_dos,active['dos_requests'])));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['budget_prefix' if active['prefix'] else 'raw_child_return' if raw else 'root_near_return']+=1;coverage['DOSservices']+=out.services;coverage['callbacks']+=out.callbacks;coverage['synthetic_callback_RETF_instructions']+=synthetic_returns;coverage['bus_write_events']+=out.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111);coverage['minimumSP16_cases']+=int(sp==16);coverage['stack_global_alias_cases']+=int(same and sp in [0x6d8b,0x707a,0x6dc8])
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['callbacks']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000262'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_vectors.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_runtime_message.py','tools/validate_finalizer_list.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual05E0optionalDS7076farcallback/savedDS/LDS6D89/DOS2500/restoredDSguard6DC6/AL6DC7/LDS6DC8/DOS25/rootnearRET. Fullbus/actualSSframes/GPR/BP/CFIFDF/serviceABI/actualcontrol, orderedpost-PUSHaliases andsavedDSmutations retained. SyntheticDOS/callback body/RETF andrealINT/vector/IRQ delivery separate. Nativebudget/adapter/rawchildreturns distinct. Actualcaller/saved-vectorwriters/targets/lifetime/exclusion/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
