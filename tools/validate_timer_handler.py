"""Compare61BF/6230 with explicit far-callback and old-INT08 ABI adapters."""
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
from validate_music_tick import Registers,Port,Result as MusicResult,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['kind','segment','offset']]+[('registers',Registers)]


Call=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Registers))


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('return_flags',C.c_uint16)]+[(n,C.c_uint32) for n in ['steps','callbacks','old_interrupts']]+[('registers',Registers)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));handler=dll.td2ega_timer_handler;handler.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,Port,Call,C.c_void_p,C.c_uint32,C.POINTER(Result)];handler.restype=None;chain=dll.td2ega_timer_chain_old;chain.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Call,C.c_void_p,C.c_uint32,C.POINTER(Result)];chain.restype=None
    cases=[];boundary=[0,1,2,3,0x7fff,0x8000,0x8001,0xfffe,0xffff]
    for countdown,old_enabled,delay,guard,callbacks in itertools.product(boundary,[0,1],boundary,[0,1],[0,1,2,5,6]):cases.append(('handler','counter_guard_callbacks',{'countdown':countdown,'old_enabled':old_enabled,'delay':delay,'guard':guard,'callbacks':callbacks}))
    for delay,enabled,change in itertools.product(boundary,[0,1,255],[0,1]):cases.append(('chain','old_vector_profiles',{'delay':delay,'bridge_enabled':enabled,'old_change':change}))
    for index in [0,1,2,3,0x60,0x76,0x7fff,0x8000,0xa161,0xfffc,0xffff]:
        for low in boundary:cases.append(('handler','indexed_alias_and_carry',{'index':index,'low':low,'callbacks':2}))
    for mutate,skip,change in itertools.product([0,1],[0,1],[0,1]):cases.append(('handler','mutable_callback_state',{'callbacks':3,'mutate':mutate,'skip':skip,'callback_change':change}))
    for flags in [2,0x247,0x6d7,0xed7]:
        for count in [0,1,6]:cases.append(('handler','iret_flags',{'irq_flags':flags,'callbacks':count}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:61BF','06C9:6230']];require(len(fenced)==2,'Both handler/bridge fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;coverage=Counter();sites=set();active={}
    for load in [0x1000,0x2345]:
        cs,ds,ss,sp=load+0x6c9,load+0x178f,0x9000,0x8000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);base=bytearray(0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base[load*16:load*16+len(relocated)]=relocated;starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def word(segment,offset):return struct.unpack('<H',uc.mem_read(segment*16+(offset&65535),2))[0]
        def read_registers():
            flags=uc.reg_read(UC_X86_REG_EFLAGS);return Registers(*[uc.reg_read(reg) for reg in regids],(flags>>9)&1,(flags>>10)&1)
        def fetch(u,address,size,_):
            if active.get('expected')==address:
                current_sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(ss*16+current_sp,4))==struct.pack('<2H',0x621b,cs),'Callback far frame');active['pending']=(0,u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),read_registers(),current_sp);active['expected']=None;u.emu_stop();return
            require(address in starts,'Timer escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address==cs*16+0x6217:
                group=u.reg_read(UC_X86_REG_DS);di=u.reg_read(UC_X86_REG_DI);active['expected']=word(group,di+0x5f14)*16+word(group,di+0x5f12)
        def interrupt(u,num,_):
            require(num==8 and u.reg_read(UC_X86_REG_IP)==0x625b,'Old INT08 site');flags=u.reg_read(UC_X86_REG_EFLAGS);current_sp=u.reg_read(UC_X86_REG_SP);u.mem_write(ss*16+current_sp-6,struct.pack('<3H',0x625b,cs,flags&65535));u.reg_write(UC_X86_REG_SP,current_sp-6);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300);r=read_registers();active['pending']=(1,word(0,0x22),word(0,0x20),r,current_sp-6);active['interrupt_flags']=flags;u.emu_stop()
        def port_service(events,operation,port,value,enabled):
            require((operation,port) in [(1,0x20),(0,0x61),(1,0x61)],'Timer port domain')
            if operation==0:value=0xa7
            events.append(['port',operation,port,value,enabled]);return value
        def port_in(u,p,size,_):require(size==1,'Read width');return port_service(active['events'],0,p,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,p,size,value,_):require(size==1,'Write width');port_service(active['events'],1,p,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for kind,category,c in cases:
            data=bytearray(base)
            def put(at,v):struct.pack_into('<H',data,ds*16+at,v&65535)
            for at,v in [(0x5e88,0x5678),(0x5e8a,0x4321),(0x5e8c,c.get('low',0xffff)),(0x5e8e,0x7fff),(0x5e90,c.get('low',0xffff)),(0x5e92,0x8000),(0x5e96,c.get('delay',2)),(0x5e98,0xa55a),(0x5e9a,c.get('countdown',1)),(0x5e9c,c.get('index',0)),(0x5e9e,0xffff)]:put(at,v)
            data[ds*16+0x5e94]=c.get('bridge_enabled',1);data[ds*16+0x5e95]=c.get('old_enabled',1);data[ds*16+0x5efe]=c.get('guard',0)
            for i in range(8):struct.pack_into('<2H',data,ds*16+0x5f12+4*i,0x100+i*0x10,0x7000 if i<c.get('callbacks',0) else 0)
            irqflags=c.get('irq_flags',[2,0x247,0x6d7,0xed7][vectors%4]);frame=struct.pack('<3H',0x100,0x1111,irqflags) if kind=='handler' else struct.pack('<H',0x100)
            data[ss*16+sp-32:ss*16+sp+len(frame)+4]=b'\xa5'*32+frame+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);incoming=Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds if kind=='chain' else 0x5000,0x5432,(flags>>9)&1,(flags>>10)&1)
            for reg,val in list(zip(regids,values(incoming)[:8]))+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x61bf if kind=='handler' else 0x6230),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            def call_service(events,write,q):
                events.append(['call',q.kind,q.segment,q.offset,*values(q.registers)]);returned=Registers(*values(q.registers));index=sum(e[0]=='call' for e in events)
                returned.ax=0xa000+q.kind;returned.bx=0xb000+index;returned.cx=0xc000+index;returned.dx=0xd000+index;returned.si=0xe000+index
                returned.interrupts_enabled=index&1;returned.direction=(index>>1)&1
                if q.kind==1 and c.get('old_change'):returned.ds=0x5000;returned.es=0x6000
                if q.kind==0:
                    if c.get('callback_change'):returned.ds=0x5000;returned.es=0x6000
                    if c.get('skip'):returned.di=(returned.di+4)&65535
                    if c.get('mutate'):write(ds*16+0x5f18,b'\0\0')
                write(0x80000+2*index,struct.pack('<H',q.offset));return returned
            active.update(events=[],instructions=0,sites=set(),pending=None,expected=None);end=0x11210 if kind=='handler' else cs*16+0x100;uc.emu_start(cs*16+(0x61bf if kind=='handler' else 0x6230),end,count=4096)
            while active['pending']:
                callkind,seg,off,r,current_sp=active['pending'];active['pending']=None;q=Request(callkind,seg,off,r);returned=call_service(active['events'],lambda at,b:uc.mem_write(at,b),q)
                if callkind:
                    require(bytes(uc.mem_read(ss*16+current_sp,6))==struct.pack('<3H',0x625b,cs,active['interrupt_flags']&65535),'Old interrupt six-byte frame');resume=0x625b;return_sp=current_sp+6;return_flags=active['interrupt_flags']
                else:resume=0x621b;return_sp=current_sp+4;return_flags=2|(returned.interrupts_enabled<<9)|(returned.direction<<10)
                for reg,val in list(zip(regids,values(returned)[:8]))+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,resume),(UC_X86_REG_SP,return_sp),(UC_X86_REG_EFLAGS,return_flags)]:uc.reg_write(reg,val)
                uc.emu_start(cs*16+resume,end,count=4096)
            label=f'{load:x}/{kind}/{category}/{c}';expected_return=(0x1111,0x100,sp+6) if kind=='handler' else (cs,0x100,sp+2);require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==expected_return,'Original ISR/near return '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def port_cb(ctx,qptr,vptr):
                try:q=qptr.contents;vptr.contents.value=port_service(events,q.operation,q.port,q.value if q.operation else 0,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            def call_cb(ctx,m,qptr,rptr):
                try:q=qptr.contents;returned=call_service(events,lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q);C.memmove(rptr,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            ps,cb=Port(port_cb),Call(call_cb);result=Result()
            if kind=='handler':handler(gb,len(data),load,C.byref(incoming),irqflags,ps,cb,None,32,C.byref(result))
            else:chain(gb,len(data),cs,C.byref(incoming),cb,None,32,C.byref(result))
            require(not errors and result.status==0,'Native services '+label+str(errors));require(events==active['events'],'Ordered PIC/oldISR/callback effects '+label)
            actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Full nonstack bus '+label)
            r=result.registers;require([uc.reg_read(reg) for reg in regids]==values(r)[:8],'Registers '+label);require(uc.reg_read(UC_X86_REG_BP)==0x5678 and uc.reg_read(UC_X86_REG_SS)==ss,'BP/SS '+label);require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'IF/DF '+label)
            if kind=='handler':require(uc.reg_read(UC_X86_REG_EFLAGS)&0xffff==result.return_flags==irqflags,'IRET saved flags '+label)
            require(bytes(uc.mem_read(ss*16+sp,len(frame)+4))==frame+b'\xa5'*4,'Returnframe/upperguard '+label);require(result.callbacks==sum(e[:2]==['call',0] for e in events) and result.old_interrupts==sum(e[:2]==['call',1] for e in events),'Invocation counts '+label);sites.update(active['sites']);instructions+=active['instructions'];coverage[category]+=1;vectors+=1
    record={'schema':1,'function_ids':['FN-EGA-000360','FN-EGA-000361'],'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_handler.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':sum(len(f['instructions']) for f in fenced),'limits':'Serialized61BF/6230 fullsyntheticbus withPIC/port, oldINT08 sixbyteIRET ABI andfarcallback mocks. SignedDEC/JG/overflow, carry, indexedaliases, zero-to-sixcallbackrows, mutableDS/ES/DI/table effects andactualIRETregister/flags restoration compared. Stackwrites excludedfrombus andframe/guards checkedseparately. No actualBIOS/PIC/IRQ/nesting/callbackbodies/timerfrequency/086Cmeaning, game/audio/fidelity acceptance. Adapterincidental arithmeticflags outsideprofile.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
