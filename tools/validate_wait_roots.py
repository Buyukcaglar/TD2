"""Compare four wait roots with actual bridge/counters and explicit input ABI."""
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
from validate_input_bridge import Request as InputRequest,Response as InputResponse,Service as InputService
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

class CounterRequest(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['site','segment','offset','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
Observer=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(CounterRequest))
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['events','input_calls','counter_calls','dynamic_calls','bus_writes']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_wait_roots;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),InputService,Observer,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[0x6a30,0x6a4a,0x7a3b,0xc63e];owned_entries=entries+[0x69fe,0x79c8,0xc692];fence={ip for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in owned_entries] for ip in f['instructions']};outer={0x6a30:(0x69fe,0x6a35),0x6a4a:(0x69fe,0x6a4f),0x6a54:(0x79c8,0x6a59),0x7a3b:(0x79c8,0x7a40),0xc63e:(0x69fe,0xc643),0xc648:(0xc692,0xc64d)};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();pairs=[(0,0,0,0),(1,0,0,1),(0x8000,0x7fff,0x7fff,0x8000),(0xffff,1,0,2),(10,5,9,5),(10,5,10,5),(10,5,11,5),(10,5,0xffff,4),(0xffff,0xffff,0,0),(0,0xffff,0xffff,0xffff),(0x8000,0,0,0),(0,0,0xffff,0xffff)]
    def input_event(q):return ['input',q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
    def counter_event(q):return ['counter',q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536)
        for segment in [0x8000,0x8100,0x8200,0x8300]:base[segment*16+0x100]=0xcb
        u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def pw_mutation(segment,offset,value):return (((segment<<4)+(offset&65535))&0xfffff,struct.pack('<H',value&65535))
        def common_mutations(segment,index,pair):
            lo,hi,unused_low,unused_high=pair
            return [pw_mutation(segment,0x64dc,0x100),pw_mutation(segment,0x64de,0x8000+(index%4)*0x100),pw_mutation(segment,0x6818,lo),pw_mutation(segment,0x681a,hi),pw_mutation(segment,0x68d6,lo),pw_mutation(segment,0x68d8,hi)]
        def input_response(q,index,delay_index,profile,pair):
            rr=StateRegisters.from_buffer_copy(bytes(q.incoming));delays=[0,1,3,None];delay=delays[delay_index];rr.registers.ax=([1,0x100,0x8000,0xffff][delay_index] if delay is not None and index>delay else 0)
            if profile==1:rr.registers.ds=0x7100+(index%2)*0x100;rr.registers.interrupts_enabled=index&1;rr.registers.direction=(index+1)&1
            if profile==2:rr.bp=(0x1234+index)&65535;rr.registers.ax=0xffff if delay_index==0 else rr.registers.ax;rr.registers.si=0x3456^index;rr.registers.di=0x4567^index;rr.registers.es=0x5678;rr.registers.interrupts_enabled=0;rr.registers.direction=1
            rr.carry=index&1;return rr,common_mutations(rr.registers.ds,index,pair)
        def counter_mutations(q,index,pattern,pair,raw):
            lo,hi,current_low,current_high=pair
            if pattern==1 and index>=2:current_low,current_high=lo,hi
            if pattern==2 and index>=2:
                if index==2 and hi<65535 and lo>0:current_low,current_high=0,hi+1
                else:current_low,current_high=lo,hi
            mutations=common_mutations(q.incoming.registers.ds,index,pair);field=0x5e8c if q.offset==0x79c8 else 0x5e90;mutations +=[pw_mutation(q.incoming.registers.ds,field,current_low),pw_mutation(q.incoming.registers.ds,field+2,current_high)]
            if raw:mutations +=[pw_mutation(q.stack_segment,q.stack_sp,0x1234),pw_mutation(q.stack_segment,q.stack_sp+2,0x7777)]
            return mutations
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,unused):
            actual_cs,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if actual_cs in [0x8000,0x8100,0x8200,0x8300] and ip==0x100:
                current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',0x6a02,cs),'Dynamic input far frame');q=InputRequest(1,0x69fe,actual_cs,ip,active['ss'],current,read_regs());active['input_calls']+=1;active['events'].append(input_event(q));rr,mutations=input_response(q,active['input_calls'],active['delay'],active['profile'],active['pair'])
                for at,payload in mutations:u.mem_write(at,payload)
                for reg,value in zip(regs,values(rr.registers)[:8]):u.reg_write(reg,value)
                u.reg_write(UC_X86_REG_BP,rr.bp);flags=u.reg_read(UC_X86_REG_EFLAGS);u.reg_write(UC_X86_REG_EFLAGS,(flags&~0x601)|rr.carry|(rr.registers.interrupts_enabled<<9)|(rr.registers.direction<<10));active['synthetic_returns']+=1;return
            require(actual_cs==cs and ip in fence,'Wait roots escaped '+hex(address))
            if ip in outer:
                if active['outer_events']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['outer_events']+=1;target,ret=outer[ip];active['pending']=(ip,target,ret)
            if ip in [0x69fe,0x79c8,0xc692]:
                site,target,ret=active['pending'];require(ip==target and bytes(u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))==struct.pack('<2H',ret,cs),'Outer far frame')
                if target!=0x69fe:
                    q=CounterRequest(site,cs,target,active['ss'],u.reg_read(UC_X86_REG_SP),read_regs());active['counter_calls']+=1;active['events'].append(counter_event(q))
                    for at,payload in counter_mutations(q,active['counter_calls'],active['pattern'],active['pair'],active['raw']):u.mem_write(at,payload)
            if ip in [0x79d1,0xc69b] and not active['allow_raw_return']:
                site,target,ret=active['pending'];words=struct.unpack('<2H',u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))
                if words!=(ret,cs):active['raw_pending']=ip;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No BIOS/OS/IRQ in admitted opaque input ABI')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(entry,pair_index,delay,profile,same,flags,limit,False) for entry,pair_index,delay,profile,same,flags,limit in itertools.product([1,3],range(len(pairs)),range(4),range(3),[0,1],[2,0x603],[0,1,2,3,8,16])]
        cases +=[(0,0,delay,profile,same,flags,limit,False) for delay,profile,same,flags,limit in itertools.product(range(4),range(3),[0,1],[2,0x603],[0,1,2,3,8,16])]
        cases +=[(2,pair_index,0,0,same,flags,limit,False) for pair_index,same,flags,limit in itertools.product(range(len(pairs)),[0,1],[2,0x603],[0,1])]
        cases +=[(2,5,0,0,same,flags,1,True) for same,flags in itertools.product([0,1],[2,0x603])]
        for entry,pair_index,delay,profile,same,flags,limit,raw in cases:
            pair=pairs[pair_index];pattern=(pair_index+delay+profile)%3;data=bytearray(base);ss=ds if same else 0x9000
            for segment in [ds,0x7100,0x7200]:
                for at,payload in common_mutations(segment,0,pair):data[at:at+len(payload)]=payload
            frame=struct.pack('<2H',0x100,0x1111);guard=b'\x5a\xa5'*4;data[ss*16+sp-32:ss*16+sp+12]=b'\xa5'*32+frame+guard;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(ss=ss,limit=limit,entry=entry,pair=pair,pattern=pattern,delay=delay,profile=profile,raw=raw,prefix=False,raw_pending=0,allow_raw_return=False,pending=None,outer_events=0,input_calls=0,counter_calls=0,events=[],synthetic_returns=0,writes=0,instructions=0,sites=set());u.emu_start(cs*16+entries[entry],0x11210,count=10000)
            if active['raw_pending']:active['allow_raw_return']=True;u.emu_start(cs*16+active['raw_pending'],0,count=1)
            label=f'{load:x}/{entry}/{pair_index}/{delay}/{profile}/{same}/{flags:x}/{limit}/{raw}';require(active['prefix'] or active['raw_pending'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original wait result '+label);require(bool(active['raw_pending'])==raw,'Counter alias profile '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];input_calls=0;counter_calls=0
            def input_callback(ctx,memory,request,response):
                nonlocal input_calls
                try:
                    q=request.contents;input_calls+=1;events.append(input_event(q));rr,mutations=input_response(q,input_calls,delay,profile,pair)
                    for at,payload in mutations:C.memmove(C.byref(bus,at),payload,len(payload))
                    C.memmove(C.byref(response.contents.returned),C.byref(rr),C.sizeof(StateRegisters));response.contents.zero=0;return 1
                except Exception as exc:errors.append(str(exc));return 0
            def observer_callback(ctx,memory,request):
                nonlocal counter_calls
                try:
                    q=request.contents;counter_calls+=1;events.append(counter_event(q))
                    for at,payload in counter_mutations(q,counter_calls,pattern,pair,raw):C.memmove(C.byref(bus,at),payload,len(payload))
                    return 1
                except Exception as exc:errors.append(str(exc));return 0
            out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),InputService(input_callback),Observer(observer_callback),None,limit,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.events==active['outer_events'] and out.input_calls==active['input_calls']==input_calls and out.counter_calls==active['counter_calls']==counter_calls and out.dynamic_calls==input_calls and out.bus_writes==active['writes'] and events==active['events'],'Native wait chain/events '+label+str(errors));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full nested bus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);flags_out=u.reg_read(UC_X86_REG_EFLAGS);require((flags_out&1,(flags_out>>9)&1,(flags_out>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Far/childraw coordinate '+label)
            require(bytes(u.mem_read(ss*16+sp,12))==frame+guard,'Root return/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['prefix' if active['prefix'] else 'raw_counter_returns' if raw else 'root_far_returns']+=1;coverage['outer_calls']+=out.events;coverage['dynamic_input_calls']+=input_calls;coverage['counter_observations']+=counter_calls;coverage['synthetic_input_RET_instructions']+=active['synthetic_returns'];coverage['bus_write_events']+=out.bus_writes;coverage['high_greater_low_less_fixtures']+=int(pair[3]>pair[1] and pair[2]<pair[0])
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised wait/bridge/counter sites '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000164','FN-EGA-000166','FN-EGA-000202','FN-EGA-000248'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_wait_roots.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_input_bridge.py','tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Fouractualroot+69FEbridge+79C8/C692counter Cbodies, materializedouter/dynamicSSfarframes/fullbus/GPR/BP/CFIFDF/rootRETF4. Opaquedynamicinputcallee isexplicitfullreturned-state ABI service withsyntheticRETstub countedseparately; noinputtargetbody/runtime admission. Counterobserveronlymutatessyntheticbus beforeactualread, noIRQ/frequency/timebase. AH-only/rawinputAX, returnedDS/BP/pointerrereads andhigh-greater/low-less contrast retained:6A4A/7A3Blex, C63EhighANDlow. Nativebefore-outer-callprefixes and8rawcounter-returnframe aliases distinct; noSSscratch exclusions. Actualinput/counterwriters/lifetime/exclusion/fullstate/core/resource-fedP2/P3/device/session/game/fidelity remainopen; physical086C unrelated. Nativeinvalid/adapter checks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
