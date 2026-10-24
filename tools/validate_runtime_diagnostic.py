"""Compare actual diagnostic/message chain, callback frames and raw checksum."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['operations','rows','services','callbacks','bus_writes']]+[('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_runtime_diagnostic;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());selected=[f for f in g['functions'] if f['entry'] in ['13A8:0620','13A8:066E','13A8:088C','13A8:08B7']];fence={ip for f in selected for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;base[0x90000]=base[0x94000]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def dos_response(r,profile):
            returned=StateRegisters.from_buffer_copy(bytes(r))
            if profile==0:returned.registers.ax=0;returned.carry=0
            if profile==1:returned.registers.ax=0xdead;returned.registers.bx=0xbeef;returned.registers.cx=0xcafe;returned.registers.dx=0xd00d;returned.registers.si=0x1234;returned.registers.di=0x4321;returned.registers.ds=ds+0x100;returned.registers.es=0x2468;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if profile==2:returned.bp=0xd000
            return returned
        def callback_response(r,mode,ss,qsp):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if mode==3:returned.registers.ds=ds+0x100;returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.si=0x3456;returned.registers.di=0x4567;returned.registers.es=0x2468;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if mode==4:mutations.append((ss*16+qsp,struct.pack('<H',0x4444)))
            if mode==5:mutations.append((ss*16+r.bp,struct.pack('<H',0x1357)))
            return returned,mutations
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if segment==0x9000 and ip in [0,0x4000]:
                r=snapshot();active['callback_requests'].append([0x633,segment,ip,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);returned,mutations=callback_response(r,active['mode'],active['ss'],u.reg_read(UC_X86_REG_SP))
                for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
                u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
                for at,value in mutations:u.mem_write(at,value)
                active['service_write_events']+=len(mutations);active['return_kind']='callback';u.emu_stop();return
            require(segment==cs and ip in fence,'Runtime diagnostic escaped '+hex(address))
            if ip in [0x643,0x693,0x8df]:active['return_kind']='message' if ip==0x8df else 'diagnostic' if ip==0x643 else 'checksum';u.emu_stop();return
            if ip in [0x677,0x899,0x633,0x8d9] or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX)!=0):
                if active['operations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['operations']+=1
                if ip==0x899:active['rows']+=1
                if ip==0x677:active['checksum_bytes']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(cpu,number,unused):
            require(number==0x21 and u.reg_read(UC_X86_REG_IP)==0x8db,'Only syntheticDOS40');r=snapshot();active['dos_requests'].append([number,0x8d9,cs,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);returned=dos_response(r,active['profile'])
            for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=list(itertools.product(range(2),range(5),range(6),[0,1],[0xe000,48],[2,0x603],[0,1,4,65,66,68,90,256],range(3)))
        cases +=[(1,0,0,same,0xe000,flags,66,0,last) for same,flags,last in itertools.product([0,1],[2,0x203,0x402,0x603],range(256))]
        for case in cases:
            entry,kind,mode,same,sp,flags,limit,profile=case[:8];last=case[8] if len(case)==9 else [0,0x55,0,0x42,0xff][kind];data=bytearray(base);ss=ds if same else 0x9000
            for segment in [ds,ds+0x100]:
                cursor=0x82c4
                for key,length in [(0xfc,2),(0xff,1),(1,3)]:struct.pack_into('<H',data,segment*16+cursor,key);cursor+=2;data[segment*16+cursor:segment*16+cursor+length+1]=b'A'*length+b'\0';cursor+=length+1
                struct.pack_into('<H',data,segment*16+cursor,0xffff);struct.pack_into('<2H',data,segment*16+0x6dcc,0 if mode==2 else 0x4000,0 if mode==0 else 0x9000)
            data[ds*16:ds*16+0x42]=bytes(0x42);data[ds*16+0x41]=last
            if len(case)==9 or kind in [0,1,4]:data[ds*16]=0x55^last
            if kind==3 and len(case)==8:data[ds*16:ds*16+0x42]=bytes(range(1,67))
            data[ss*16+sp-24:ss*16+sp+12]=b'\xa5'*24+struct.pack('<2H',0x1111,0x2222)+b'\xa5'*8;data[ss*16+0xd000:ss*16+0xd006]=struct.pack('<3H',0x7777,0x4444,0x5555);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));start=0x620 if entry==0 else 0x66e
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,start),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(entry=entry,mode=mode,profile=profile,ss=ss,limit=limit,writes=0,instructions=0,operations=0,rows=0,checksum_bytes=0,sites=set(),dos_requests=[],callback_requests=[],service_write_events=0,executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+start,0,count=100000);raw=False;root=False;synthetic_returns=0;label=f'{load:x}/{case}'
            while active['return_kind']:
                kind_ret=active['return_kind'];segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP);active['return_kind']=None;active['executing_return']=True;u.emu_start(segment*16+ip,0,count=1);active['executing_return']=False
                if kind_ret=='callback':synthetic_returns+=1
                else:sites.add(ip);active['instructions']+=1
                if kind_ret=='checksum' or (kind_ret=='diagnostic' and entry==0):root=True;break
                allowed={0x633:0x637} if False else ({0x637} if kind_ret=='callback' else {0x686} if kind_ret=='diagnostic' else {0x62c,0x640,0x68f})
                if u.reg_read(UC_X86_REG_CS)!=cs or u.reg_read(UC_X86_REG_IP) not in allowed:raw=True;break
                u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=100000)
            require(active['prefix'] or root or raw,'Outcome '+label);native_dos=[];native_callbacks=[]
            @DOSService
            def dos(context,memory,q,out):
                request=q.contents;r=request.incoming;native_dos.append([request.vector,request.site,request.segment,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);out[0]=dos_response(r,profile);return 1
            @CallbackService
            def callback(context,memory,q,out):
                request=q.contents;r=request.incoming;native_callbacks.append([request.site,request.target_segment,request.target_ip,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned,mutations=callback_response(r,mode,ss,request.stack_sp);out[0]=returned
                for at,value in mutations:
                    for k,b in enumerate(value):memory[at+k]=b
                return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),dos,callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.operations==active['operations'] and out.rows==active['rows'] and out.services==len(active['dos_requests']) and out.callbacks==len(active['callback_requests']) and out.bus_writes==active['writes'],'Status/count '+label+str((out.status,out.operations,out.rows,out.services,out.callbacks,out.bus_writes,active)));require(native_dos==active['dos_requests'] and native_callbacks==active['callback_requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/nestedSS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
            if len(case)==9:require(out.status==0 and r.registers.ax==last and out.services==0 and out.callbacks==0 and r.registers.direction==0,'Allbytevalidchecksum rawAX '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['budget_prefix' if active['prefix'] else 'raw_child_return' if raw else 'root_far_return']+=1;coverage['checksum_bytes']+=active['checksum_bytes'];coverage['DOSservices']+=out.services;coverage['callbacks']+=out.callbacks;coverage['synthetic_callback_RETF_instructions']+=synthetic_returns;coverage['bus_write_events']+=out.bus_writes;coverage['allbyte_validchecksum_cases']+=int(len(case)==9);coverage['minimumSP48_cases']+=int(sp==48)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['callbacks']>0 and coverage['allbyte_validchecksum_cases']==4096,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000264','FN-EGA-000266'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_diagnostic.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_runtime_message.py','tools/validate_finalizer_list.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual0620/066E+088C/08B7message bodies, 66byteXOR/CLD/rawvalidAXlastbyte/all256values, actualnestedSS/farframes/RETF2children/plainfarroots, optionalDS6DCC:6DCE callback. Fullbus/GPR/BP/CFIFDF/serviceABI/control. SyntheticDOS40andcallback bodies/RETF separated, returnedDS/BP/flags/SSmutations explicit. Nativeprefix/adapter/rawchildreturns separate. Actualcallbacktargets/writers/checksum-sourceownership/key/NUL/bounds/lifetime/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
