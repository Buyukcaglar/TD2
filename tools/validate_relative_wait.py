"""Compare relative raw wait plus actual CLI/read/STI far reader and SS targets."""
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
    _fields_=[(n,C.c_uint16) for n in ['site','segment','offset','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['reads','bus_writes']]+[('returned',StateRegisters)]
Observer=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_relative_wait;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Observer,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:C6C5','06C9:C692'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def changes(mode,initial,index,r,ss,qsp,readword):
            low,high=initial;mutations=[]
            if index!=0:
                target_low=readword(ss,(r.bp-4)&65535);target_high=readword(ss,(r.bp-2)&65535)
                if mode in [1,4,5,6] or (mode in [2,3] and index>=2):low,high=target_low,target_high
                if mode==2 and index==1:low,high=(target_low-1)&65535,(target_high+1)&65535
                if mode==3 and index==1:low,high=(target_low+1)&65535,(target_high-1)&65535
                if mode==7:total=((initial[1]<<16)|initial[0])+index*0x10001;low,high=total&65535,(total>>16)&65535
            mutations.extend([(r.registers.ds*16+0x5e90,struct.pack('<H',low)),(r.registers.ds*16+0x5e92,struct.pack('<H',high))])
            if mode==4 and index==0:mutations.extend([(ss*16+((r.bp+6)&65535),struct.pack('<H',0xffff)),(ss*16+((r.bp+8)&65535),struct.pack('<H',1))])
            if mode==5 and index==1:mutations.append((ss*16+qsp,struct.pack('<H',0x4444)))
            if mode==6 and index==0:mutations.append((ss*16+r.bp,struct.pack('<H',0x1357)))
            return mutations
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Relativewait escaped '+hex(address))
            if ip in [0xc69b,0xc6ee]:active['return_kind']='child' if ip==0xc69b else 'root';u.emu_stop();return
            if ip in [0xc6cb,0xc6dc]:
                if active['reads']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['reads']+=1;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
            if ip==0xc692 and active['mode']!=8:
                r=snapshot();qsp=u.reg_read(UC_X86_REG_SP);active['requests'].append([active['site'],cs,0xc692,active['ss'],qsp,*values(r.registers),r.bp,r.carry])
                def readword(s,o):return struct.unpack('<H',u.mem_read(s*16+o,2))[0]
                mutations=changes(active['mode'],active['initial'],len(active['requests'])-1,r,active['ss'],qsp,readword)
                for at,value in mutations:u.mem_write(at,value)
                active['observer_write_events']+=len(mutations)
            if ip in [0xc693,0xc696]:require((u.reg_read(UC_X86_REG_EFLAGS)&0x200)==0,'OriginalCLIcritical read');active['critical_word_reads']+=1
            if ip==0xc6e6:
                bp=u.reg_read(UC_X86_REG_BP);ss=active['ss'];target_low=struct.unpack('<H',u.mem_read(ss*16+bp-4,2))[0];target_high=struct.unpack('<H',u.mem_read(ss*16+bp-2,2))[0]
                if u.reg_read(UC_X86_REG_DX)>target_high and u.reg_read(UC_X86_REG_AX)<target_low:active['and_discriminator']=True
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform INT in relative wait/counter body')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        pairs=[(0,0),(0xffff,0),(0,0xffff),(0xffff,0xffff),(0x7fff,0x8000),(0x8000,0x7fff)];offsets=[(0,0),(1,0),(0xffff,0),(0,1),(0xffff,0xffff),(0,0x8000)];cases=list(itertools.product(pairs,offsets,range(9),[0,1],[0xe000,0x5e8c,0x5e92,0x5e96],[2,0x603],[0,1,2,4,8]));cases +=[(initial,delta,mode,same,32,flags,limit) for initial,delta,mode,same,flags,limit in itertools.product(pairs,offsets[:2],[0,1],[0,1],[2,0x203,0x402,0x603],[0,1,4])]
        for initial,delta,mode,same,sp,flags,limit in cases:
            data=bytearray(base);ss=ds if same else 0x9000;struct.pack_into('<2H',data,ds*16+0x5e90,*initial);frame=struct.pack('<4H',0x1111,0x2222,*delta);data[ss*16+sp:ss*16+sp+8]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xc6c5),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(initial=initial,mode=mode,ss=ss,limit=limit,reads=0,writes=0,instructions=0,critical_word_reads=0,observer_write_events=0,sites=set(),requests=[],and_discriminator=False,executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0xc6c5,0,count=10000);raw=False;root=False;label=f'{load:x}/{initial}/{delta}/{mode}/{same}/{sp:x}/{flags:x}/{limit}'
            while active['return_kind']:
                kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
                if kind=='root':root=True;break
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['site']+5,active['expected_sp']):raw=True;break
                u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=10000)
            require(active['prefix'] or root or raw,'Outcome '+label);native_requests=[]
            @Observer
            def observer(context,memory,q):
                request=q.contents;r=request.incoming;index=len(native_requests);native_requests.append([request.site,request.segment,request.offset,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry])
                def readword(s,o):at=s*16+o;return memory[at]|(memory[at+1]<<8)
                for at,value in changes(mode,initial,index,r,ss,request.stack_sp,readword):
                    for k,b in enumerate(value):memory[at+k]=b
                return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),Observer() if mode==8 else observer,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.reads==active['reads'] and out.bus_writes==active['writes'],'Status/count '+label);require(native_requests==active['requests'],'ObserverABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SSlocals '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['before_read_prefix' if active['prefix'] else 'raw_child_far_return' if raw else 'root_far_return']+=1;coverage['actual_C692_calls']+=out.reads;coverage['critical_IF0_word_reads']+=active['critical_word_reads'];coverage['observer_callbacks']+=len(native_requests);coverage['observer_write_events']+=active['observer_write_events'];coverage['bus_write_events']+=out.bus_writes;coverage['high_greater_low_below_discriminator_cases']+=int(active['and_discriminator']);coverage['raw_root_returns']+=int(root and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['minimumSP32_cases']+=int(sp==32);coverage['no_observer_stable_bus_cases']+=int(mode==8)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['high_greater_low_below_discriminator_cases']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000417'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_relative_wait.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualC6C5+actualC692CLI/read/STI/RETF, rawADD/ADCtwoSSarguments/orderedSSlocals, unsignedhighANDlow guards notlex. Fullbus/nestedSS/GPR/BP/CFIFDF/observerABI/control, criticalwordreadsIF0 andreturnedIF1. Optionalobserver memory-onlysyntheticcounter/SSmutations beforeC692CLI; NULLstablebus, no actualIRQ/timerdelivery orfrequency. Nativebefore-readbudget/observerfailure/rawchildreturns separate. Actualcaller/DSview/sourcewriters/lifetime/bounds/IRQexclusion/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity remainopen; physical086C separateunassignedsource.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
