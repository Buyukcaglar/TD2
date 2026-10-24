"""Compare runtime lookup/actual nested output, raw DF and RETF2 cleanup."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['operations','rows','services','bus_writes']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_runtime_message;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());selected=[f for f in g['functions'] if f['entry'] in ['13A8:088C','13A8:08B7']];fence={ip for f in selected for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def respond(r,profile,ss,sp):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if profile==0:returned.registers.ax=0;returned.carry=0
            if profile==1:returned.registers.ax=0xdead;returned.registers.bx=0xbeef;returned.registers.cx=0xcafe;returned.registers.dx=0xd00d;returned.registers.si=0x1234;returned.registers.di=0x4321;returned.registers.ds=ds+0x100;returned.registers.es=0x2468;returned.bp=0xd000;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if profile==2:mutations=[(ss*16+sp-4,struct.pack('<H',0xbeef)),(ss*16+sp-2,struct.pack('<H',0x1357))]
            return returned,mutations
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Message escaped '+hex(address))
            if ip==0x8df or (ip==0x8b4 and active['entry']==0):active['return']=True;u.emu_stop();return
            if ip==0x899 or ip==0x8d9 or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX)!=0):
                if active['operations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['operations']+=1
                if ip==0x899:active['rows']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(cpu,number,unused):
            require(number==0x21 and u.reg_read(UC_X86_REG_IP)==0x8db,'OnlyDOS40boundary');r=snapshot();require(r.registers.ax==0x4000 and r.registers.bx==2,'Outputrequest');active['requests'].append([number,0x8d9,cs,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);returned,mutations=respond(r,active['profile'],active['ss'],active['sp'])
            for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
            for at,value in mutations:u.mem_write(at,value)
            active['service_write_events']+=len(mutations)
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=list(itertools.product(range(2),range(5),[0x10,0x20,0x30,0xffff,0xa5a5],[0,1],[0xe000,0x82c8],[2,0x203,0x402,0x603],[0,1,4,32,128],range(3)))
        cases +=[(1,4,0xa5a5,same,0xe000,flags,limit,0) for same,flags,limit in itertools.product([0,1],[2,0x203,0x402,0x603],[65536,65538])]
        for entry,kind,key,same,sp,flags,limit,profile in cases:
            data=bytearray(base);ss=ds if same else 0x9000
            if kind<3:
                cursor=0x82c4;lengths=[(0,1),(1,7),(17,0)][kind]
                for tag,length in zip([0x10,0x20],lengths):struct.pack_into('<H',data,ds*16+cursor,tag);cursor+=2;data[ds*16+cursor:ds*16+cursor+length+1]=bytes(0x41+k%26 for k in range(length))+b'\0';cursor+=length+1
                struct.pack_into('<H',data,ds*16+cursor,0xffff)
            elif kind==3:struct.pack_into('<H',data,ds*16+0x82c4,0xffff)
            # A reverse scan has no assumed valid reverse catalog; budgets retain raw paths.
            if flags&0x400 and kind<4:data[ds*16+0x82b0]=0
            frame=struct.pack('<3H',0x1111,0x2222,key);data[ss*16+sp-24:ss*16+sp+14]=b'\xa5'*24+frame+b'\xa5'*8;data[ss*16+0xd000:ss*16+0xd006]=struct.pack('<3H',0x7777,0x4444,0x5555);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));start=0x88c if entry==0 else 0x8b7
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,start),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(entry=entry,limit=limit,profile=profile,ss=ss,sp=sp,writes=0,instructions=0,operations=0,rows=0,sites=set(),requests=[],service_write_events=0,executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+start,0,count=500000);label=f'{load:x}/{entry}/{kind}/{key:x}/{same}/{sp:x}/{flags:x}/{limit}/{profile}';require(active['prefix'] or active['return'],'Outcome '+label)
            if active['return']:
                ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
            native_requests=[]
            @Service
            def callback(context,memory,q,out):
                request=q.contents;r=request.incoming;native_requests.append([request.vector,request.site,request.segment,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned,mutations=respond(r,profile,ss,sp);out[0]=returned
                for at,value in mutations:
                    for k,b in enumerate(value):memory[at+k]=b
                return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.operations==active['operations'] and out.rows==active['rows'] and out.services==len(active['requests']) and out.bus_writes==active['writes'],'Status/count '+label);require(native_requests==active['requests'],'DOSserviceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/nestedSS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix' if active['prefix'] else 'far_RETF2_returns']+=1;coverage['operations']+=out.operations;coverage['catalog_rows']+=out.rows;coverage['DOSservices']+=out.services;coverage['bus_write_events']+=out.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['reverseDF_fixtures']+=incoming.registers.direction;coverage['raw_root_returns']+=int(active['return'] and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['full_no_NUL_output_requests']+=sum(q[7]==65534 and q[-1]==1 for q in native_requests)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['DOSservices']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000269','FN-EGA-000270'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_message.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual088Crawcatalog lookup and08B7actualnestedlookup/outputscan/RETF2callee cleanup, incomingDF/word wrap, SSarguments/saves/farframes/fullbus/GPR/BP/CFIFDF/control. SyntheticDOS40 fullreturnedstate/DS/BP/IFDF/SSsave mutations, realINTframes/file/device effects unadmitted. Nativebefore-element/INT/adapterdiagnostics separate. Originalcatalog/message bytes external; caller/NUL/capacity/otherFLAGS/writers/lifetime/core/resourcefedP2/P3/device/session/game/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
