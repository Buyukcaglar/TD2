"""Compose state sequences with actual counter waits, input drain and BIOS wrapper."""
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
from validate_state_messages import Registers,StateRegisters,Request as MessageRequest,Service as MessageService,Result as MessageResult,require,values
from validate_wait_control import Request as WaitRequest,Service as WaitService,Result as WaitResult
from validate_input_bridge import Service as InputService,Result as InputResult
from validate_keyboard import Registers as KeyboardRegisters,Result as KeyboardResult
from validate_bios_block import Request as BiosRequest,Service as BiosService,Result as BiosResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['sequence','latch','wait','input','keyboard','bios']:p.add_argument('--'+name+'-library',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();libraries=[getattr(a,n+'_library').resolve() for n in ['sequence','latch','wait','input','keyboard','bios']];output=a.output.resolve();require(all(p.is_relative_to(ROOT/'analysis') for p in libraries) and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dlls=[C.CDLL(str(p)) for p in libraries];sequence=dlls[0].td2ega_state_sequence;latch=dlls[1].td2ega_wait_latch;wait=dlls[2].td2ega_wait_control;inputs=dlls[3].td2ega_input_bridge;keyboard=dlls[4].td2ega_keyboard_bios;bios=dlls[5].td2ega_bios_block
    sequence.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),MessageService,C.c_void_p,C.c_uint32,C.POINTER(MessageResult)]
    latch.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),WaitService,C.c_void_p,C.c_uint32,C.POINTER(WaitResult)]
    wait.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_int,C.c_uint32,C.POINTER(StateRegisters),WaitService,C.c_void_p,C.c_uint32,C.POINTER(WaitResult)]
    inputs.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),InputService,C.c_void_p,C.c_uint32,C.POINTER(InputResult)]
    keyboard.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(KeyboardRegisters),C.c_uint16,C.c_uint16,C.POINTER(KeyboardResult)]
    bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BiosService,C.c_void_p,C.c_uint32,C.POINTER(BiosResult)]
    for fn in [sequence,latch,wait,inputs,keyboard,bios]:fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=[0x3532,0x3643];extra=[0x5c98,0x7a10,0x7a27,0x79c8,0x7a55,0x6a3b,0x69b7,0xabfa];fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{x:04X}' for x in entries+extra]];require(len(fenced)==10,'Ten composed fences');md=Cs(CS_ARCH_X86,CS_MODE_16);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;coverage=Counter();sp=0xe000
    specs={0x3537:(2,2),0x356a:(2,2),0x3577:(2,4),0x3587:(2,2),0x35c4:(5,5),0x35e4:(1,1),0x360f:(1,1),0x3626:(2,2),0x3648:(2,2),0x5c9d:(2,2),0x366a:(2,2),0x367f:(2,2),0x368c:(2,4),0x369f:(2,2),0x36b7:(4,4)};actual_targets={0x7a10,0x7a27,0x7a55,0x6a3b,0xabfa}
    def reg_event(r):return [values(r.registers),r.bp,r.carry]
    def msg_event(q):return ['far',q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),*reg_event(q.incoming)]
    def counter_event(model,read,write,q):
        model.append(['counter',q.site,q.segment,q.offset,*reg_event(q.incoming)]);at=q.incoming.registers.ds*16+0x5e8c;old=struct.unpack('<I',read(at,4))[0];write(at,struct.pack('<I',(old+0x10000)&0xffffffff))
    def bios_event(q):return ['bios10',q.site,q.stack_segment,q.stack_sp,q.saved_flags,*reg_event(q.incoming)]
    def bios_model(model,q):
        model.append(bios_event(q));r=StateRegisters(Registers(*values(q.incoming.registers)),0xcafe,1-q.incoming.carry);r.registers.interrupts_enabled=1-((q.saved_flags>>9)&1);r.registers.direction=1-r.registers.direction;return r
    def bios16_event(model,site,ss,current,saved,r):model.append(['bios16',site,ss,current,saved,*reg_event(r)])
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000,0x9000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            if int(f['entry'][5:],16) not in entries+[0x5c98]:continue
            for c in f['calls']:
                ip=int(c['site'][5:],16);segment,target=[int(x,16) for x in c['target'].split(':')]
                if target==0x5c98 and segment==0x6c9:continue
                size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc,live=specs.get(ip,(0,0));calls[cs*16+ip]=(ip,load+segment,target,ip+size,argc,live)
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            if active.get('expected') and address==active['expected'][1]*16+active['expected'][2]:
                site,segment,target,ret,argc,live=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Sequence platform far frame');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+4,live*2))) if live else [];q=MessageRequest(site,segment,target,argc,live,active['ss'],current,(C.c_uint16*10)(*(args+[0]*(10-live))),read_regs());active['expected']=None
                if target in actual_targets:active['events'].append(msg_event(q))
                else:active['pending']=('far',q,ret);u.emu_stop();return
            require(address in starts,'Sequence platform escaped fence')
            if address==cs*16+0x79c8 and not active['resume_counter']:
                current=u.reg_read(UC_X86_REG_SP);ret=struct.unpack('<H',u.mem_read(active['ss']*16+current,2))[0];q=WaitRequest(0,ret-5,cs,0x79c8,read_regs());active['pending']=('counter',q,0x79c8);u.emu_stop();return
            active['resume_counter']=False;active['instructions']+=1
            if address in calls:active['expected']=calls[address]
        def interrupt(cpu,num,_):
            require(num in [0x10,0x16],'Only BIOS10/16');ret=u.reg_read(UC_X86_REG_IP);flags=u.reg_read(UC_X86_REG_EFLAGS);current=u.reg_read(UC_X86_REG_SP)-6;u.mem_write(active['ss']*16+current,struct.pack('<3H',ret,cs,flags&65535));u.reg_write(UC_X86_REG_SP,current);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300)
            if num==0x10:active['pending']=('bios10',BiosRequest(ret-2,num,active['ss'],current,flags&0x603,read_regs()),ret)
            else:bios16_event(active['events'],ret-2,active['ss'],current,flags&0x603,read_regs());active['pending']=('bios16',None,0x69b7);u.reg_write(UC_X86_REG_IP,0x69b7)
            u.emu_stop()
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,count,start,profile,same,flags in itertools.product(range(2),[0,1,2],[0,0xfffffff0],range(3),[0,1],[2,0x603]):
            ss=ds if same else 0x9000;data=bytearray(base)
            for row in range(7):
                bp=0x4000+row*0x800
                for index in range(256):struct.pack_into('<2H',data,ss*16+bp+index*4,0x1201+profile*0x100,0x1302-profile*0x100)
                struct.pack_into('<H',data,ss*16+0x2c9e+2*row,bp);data[ss*16+0x2e22+row]=count if row==0 else 1
            for page in [ds,0x5000]:
                struct.pack_into('<I',data,page*16+0x5e8c,start)
                for at in range(0x22da,0x2300,2):struct.pack_into('<H',data,page*16+at,(at+page)&65535)
                for at in [0x3008,0x300a,0x300c,0x300e,0x2fd8,0x2fda,0x536c,0x536e]:struct.pack_into('<H',data,page*16+at,(at+page)&65535)
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+8]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def leaf(model,write,q):
                model.append(msg_event(q));index=len(model);r=StateRegisters(Registers(*values(q.incoming.registers)),q.incoming.bp,index&1);rr=r.registers;rr.ax=0xa000+(index%4096);rr.bx=0xb000+(index%4096);rr.cx=0xc000+(index%4096);rr.dx=0xd000+(index%4096);rr.es=0x6000;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if profile==1 and q.site in [0x3537,0x3648]:rr.ds=0x5000
                if profile==2 and q.site==0x35c4:write(rr.ds*16+0x2e29,b'\x01')
                return r
            active.update(expected=None,pending=None,resume_counter=False,events=[],instructions=0,ss=ss);u.emu_start(cs*16+entries[entry],0x11210,count=100000)
            while active['pending']:
                kind,q,ret=active['pending'];active['pending']=None;require(len(active['events'])<4096,'Finite composed fixture')
                if kind=='bios16':u.emu_start(cs*16+ret,0x11210,count=100000);continue
                if kind=='counter':counter_event(active['events'],lambda at,n:bytes(u.mem_read(at,n)),lambda at,b:u.mem_write(at,b),q);active['resume_counter']=True;u.emu_start(cs*16+ret,0x11210,count=100000);continue
                r=bios_model(active['events'],q) if kind=='bios10' else leaf(active['events'],lambda at,b:u.mem_write(at,b),q);rr=r.registers;current=q.stack_sp+(6 if kind=='bios10' else 4)
                for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,0x11210,count=100000)
            label=f'{load:x}/{entry}/{count}/{start:x}/{profile}/{same}/{flags:x}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Composed return '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def write(at,b):C.memmove(C.byref(bus,at),b,len(b))
            def counter_cb(ctx,m,q,r):
                try:counter_event(events,lambda at,n:bytes(bus[at:at+n]),write,q.contents);return 1
                except Exception as e:errors.append(str(e));return 0
            def bios_cb(ctx,m,q,r):
                try:returned=bios_model(events,q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            def input_cb(ctx,m,q,r):
                try:
                    q=q.contents;require(q.kind==0,'Only composed BIOS16 drain');before=r.contents.returned;sf=2|before.carry|(before.registers.interrupts_enabled<<9)|(before.registers.direction<<10);bios16_event(events,q.site,ss,q.stack_sp,sf,q.incoming);kr=KeyboardResult();keyboard(bus,len(bus),load,C.byref(q.incoming.registers),sf&~0x300,sf,C.byref(kr));require(kr.status==0,'Native installedBIOS');r.contents.returned=StateRegisters(kr.registers,q.incoming.bp,kr.return_flags&1);r.contents.zero=(kr.return_flags>>6)&1;return 1
                except Exception as e:errors.append(str(e));return 0
            wc,bc,ic=WaitService(counter_cb),BiosService(bios_cb),InputService(input_cb)
            def message_cb(ctx,m,q,r):
                try:
                    q=q.contents
                    if q.offset not in actual_targets:returned=leaf(events,write,q)
                    else:
                        events.append(msg_event(q))
                        if q.live_argument_count:write(ss*16+q.stack_sp+4,struct.pack('<'+'H'*q.live_argument_count,*list(q.arguments)[:q.live_argument_count]))
                        if q.offset in [0x7a10,0x7a27]:result=WaitResult();latch(bus,len(bus),load,ss,q.stack_sp,int(q.offset==0x7a27),C.byref(q.incoming),wc,None,32,C.byref(result))
                        elif q.offset==0x7a55:result=WaitResult();wait(bus,len(bus),load,q.stack_sp,0,q.arguments[0]|(q.arguments[1]<<16),C.byref(q.incoming),wc,None,32,C.byref(result))
                        elif q.offset==0x6a3b:result=InputResult();inputs(bus,len(bus),load,ss,q.stack_sp,4,C.byref(q.incoming),ic,None,32,C.byref(result))
                        else:result=BiosResult();bios(bus,len(bus),ss,q.stack_sp,C.byref(q.incoming),bc,None,1,C.byref(result))
                        require(result.status==0,'Native actualcallee '+hex(q.offset));returned=result.returned
                    C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            mc=MessageService(message_cb);result=MessageResult();sequence(bus,len(bus),load,ss,sp,entry,C.byref(incoming),mc,None,4096,C.byref(result));require(not errors and result.status==0,'Native composition '+label+str(errors));require(events==active['events'],'Ordered composedinterfaces '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=result.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);coverage[f'{entries[entry]:04X}']+=1;coverage['same_DS_SS_'+str(same)]+=1;coverage['counter_boundaries']+=sum(e[0]=='counter' for e in events);coverage['BIOS16_actual_handler_calls']+=sum(e[0]=='bios16' for e in events);coverage['BIOS10_ABI_calls']+=sum(e[0]=='bios10' for e in events);vectors+=1;instructions+=active['instructions']
    deps=['tools/validate_state_messages.py','tools/validate_wait_control.py','tools/validate_input_bridge.py','tools/validate_keyboard.py','tools/validate_bios_block.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':sha,'native_libraries':[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in libraries],'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual3532/3643/5C98 with7A10/7A27/7A55/79C8/6A3B/installed69B7/ABFA instruction/nativecomposition; actualBIOS16 pendingwordhandler, syntheticcounter-boundaryupdates/INTframes. BIOS10 andremaininggraphics/stateleaves ABI mocks. NativeSSargument scratchmaterialized onlyinsideexcludedliveframearea. No actualIRQ/rate/tickhistory/device/rendering/fullstate/resource/core/game/fidelity; separate fromhelpervector totals.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
