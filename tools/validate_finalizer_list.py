"""Compare reverse callback walk, actual far frames and bounded ABI services."""
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
    _fields_=[(n,C.c_uint16) for n in ['site','target_segment','target_ip','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['iterations','calls','bus_writes']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_finalizer_list;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='13A8:060D')['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;base[0x94000]=base[0x95000]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def response(r,mode):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[];qsp=u.reg_read(UC_X86_REG_SP)
            if mode==1:returned.registers.ds=ds+0x100
            if mode==2:returned.registers.si=returned.registers.di
            if mode==3:returned.registers.di=(returned.registers.di+4)&65535
            if mode==4:mutations.append((active['ss']*16+qsp,struct.pack('<H',0x4444)))
            if mode==5:mutations.append((returned.registers.ds*16+((returned.registers.di-4)&65535),bytes(4)))
            if mode==6:mutations.append((active['ss']*16+active['sp'],struct.pack('<H',0x5555)))
            if mode==7:returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.es=0x2468;returned.bp=0x9999;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            return returned,mutations
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if segment==0x9000 and ip in [0x4000,0x5000]:
                r=snapshot();active['requests'].append([0x61b,segment,ip,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);returned,mutations=response(r,active['mode'])
                for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
                u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
                for at,data in mutations:u.mem_write(at,data)
                active['callback']=True;u.emu_stop();return
            require(segment==cs and ip in fence,'Finalizer escaped '+hex(address))
            if ip==0x61f:active['root_return']=True;u.emu_stop();return
            if ip==0x611:
                if active['iterations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['iterations']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No INT in list walker or synthetic callback')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=list(itertools.product([0,1,2,4],[0,1,2],range(8),[0,1],[2,0x203,0x402,0x603],[0,1,2,8]))
        cases +=[(-1,0,2,same,flags,limit) for same,flags,limit in itertools.product([0,1],[2,0x203,0x402,0x603],[0,1,2,8])]
        cases +=[(-2,2,mode,same,flags,limit) for mode,same,flags,limit in itertools.product([0,1,2,4,5,6,7],[0,1],[2,0x203,0x402,0x603],[0,1,2,8])]
        for count,pattern,mode,same,flags,limit in cases:
            data=bytearray(base);ss=ds if same else 0x9000;sp=0xe000;si,di=(0,2) if count==-1 else (sp-4,sp) if count==-2 else (0x1200,0x1200+count*4)
            for segment in [ds,ds+0x100]:
                for k in range(4):
                    off=0x1200+4*k;target=(0,0) if pattern==0 or (pattern==1 and k%2==0) else (0x4000 if k%2==0 else 0x5000,0x9000);data[segment*16+off:segment*16+off+4]=struct.pack('<2H',*target)
            if count==-1:
                data[ds*16+0xfffe:ds*16+0x10002]=struct.pack('<2H',0x4000,0x9000);data[ds*16:ds*16+2]=struct.pack('<H',0x7777)
            if count==-2:
                for segment in [ds,ds+0x100]:data[segment*16+sp-4:segment*16+sp]=struct.pack('<2H',0x4000,0x9000)
            data[ss*16+sp:ss*16+sp+2]=struct.pack('<H',0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,si,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x60d),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(ss=ss,sp=sp,mode=mode,limit=limit,iterations=0,writes=0,instructions=0,sites=set(),requests=[],executing_return=False,prefix=False,callback=False,root_return=False);u.emu_start(cs*16+0x60d,0,count=10000);raw=False;synthetic_returns=0;label=f'{load:x}/{count}/{pattern}/{mode}/{same}/{flags:x}/{limit}'
            while active['callback']:
                segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP);active['executing_return']=True;u.emu_start(segment*16+ip,0,count=1);active['executing_return']=False;active['callback']=False;synthetic_returns+=1
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))!=(cs,0x61d):raw=True;break
                u.emu_start(cs*16+0x61d,0,count=10000)
            require(active['prefix'] or active['root_return'] or raw,'Outcome '+label)
            if active['root_return']:
                sites.add(0x61f);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0x61f,0,count=1);active['executing_return']=False
            native_requests=[]
            @Service
            def callback(context,memory,q,out):
                request=q.contents;r=request.incoming;native_requests.append([request.site,request.target_segment,request.target_ip,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
                # Same pure service response, using native request SP for frame writes.
                if mode==1:returned.registers.ds=ds+0x100
                if mode==2:returned.registers.si=returned.registers.di
                if mode==3:returned.registers.di=(returned.registers.di+4)&65535
                if mode==4:mutations.append((ss*16+request.stack_sp,struct.pack('<H',0x4444)))
                if mode==5:mutations.append((returned.registers.ds*16+((returned.registers.di-4)&65535),bytes(4)))
                if mode==6:mutations.append((ss*16+sp,struct.pack('<H',0x5555)))
                if mode==7:returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.es=0x2468;returned.bp=0x9999;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
                for at,value in mutations:
                    for k,b in enumerate(value):memory[at+k]=b
                out[0]=returned;return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.iterations==active['iterations'] and out.calls==len(active['requests']) and out.bus_writes==active['writes'],'Status/count '+label);require(native_requests==active['requests'],'Far operand/serviceABI '+label+str((native_requests,active['requests'])));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/nestedSS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['budget_prefix' if active['prefix'] else 'raw_child_return' if raw else 'root_near_return']+=1;coverage['iterations']+=out.iterations;coverage['callbacks']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['synthetic_RETF_instructions']+=synthetic_returns;coverage['far_operand_boundary_fixtures']+=int(count==-1)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['raw_child_return']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000263'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_finalizer_list.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual13A8:060D reverse list/unsignedguard/wordOR/indirectfarCALL/rootnearRET with actualnestedSSframes/fullbus/GPR/BP/CFIFDF/control. Syntheticcallback fullreturnedABI/DS/position/flags/busmutations andRETF separatefromoriginalinstructioncount/calleebodies. Boundaryfaroperand physical4byteview distinctfromtwo separatelywrappedwordORreads. Nativebefore-record/adapter/rawchildreturn outcomes separate. Actualcallbacktargets/allwriters/callerbounds/lifetime/exclusion/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
