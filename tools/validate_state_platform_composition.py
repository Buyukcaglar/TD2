"""Compose1B2C with all reviewed state handlers and actual platform helpers."""
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
from validate_state_loop import Request as RootRequest,Service as RootService,Result as RootResult
from validate_mutable_control import State
from validate_input_bridge import Request as InputRequest
from validate_wait_control import Request as WaitRequest,Service as WaitService,Result as WaitResult
from validate_input_bridge import Service as InputService,Result as InputResult
from validate_keyboard import Registers as KeyboardRegisters,Result as KeyboardResult
from validate_bios_block import Request as BiosRequest,Service as BiosService,Result as BiosResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['sequence','latch','wait','input','keyboard','bios','root','messages']:p.add_argument('--'+name+'-library',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();libraries=[getattr(a,n+'_library').resolve() for n in ['sequence','latch','wait','input','keyboard','bios','root','messages']];output=a.output.resolve();require(all(p.is_relative_to(ROOT/'analysis') for p in libraries) and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dlls=[C.CDLL(str(p)) for p in libraries];sequence=dlls[0].td2ega_state_sequence;latch=dlls[1].td2ega_wait_latch;wait=dlls[2].td2ega_wait_control;inputs=dlls[3].td2ega_input_bridge;keyboard=dlls[4].td2ega_keyboard_bios;bios=dlls[5].td2ega_bios_block;root=dlls[6].td2ega_state_loop;messages=dlls[7].td2ega_state_message
    sequence.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),MessageService,C.c_void_p,C.c_uint32,C.POINTER(MessageResult)]
    latch.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),WaitService,C.c_void_p,C.c_uint32,C.POINTER(WaitResult)]
    wait.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_int,C.c_uint32,C.POINTER(StateRegisters),WaitService,C.c_void_p,C.c_uint32,C.POINTER(WaitResult)]
    inputs.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),InputService,C.c_void_p,C.c_uint32,C.POINTER(InputResult)]
    keyboard.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(KeyboardRegisters),C.c_uint16,C.c_uint16,C.POINTER(KeyboardResult)]
    bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BiosService,C.c_void_p,C.c_uint32,C.POINTER(BiosResult)]
    root.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(State),C.POINTER(StateRegisters),RootService,C.c_void_p,C.c_uint32,C.POINTER(RootResult)]
    messages.argtypes=sequence.argtypes
    for fn in [sequence,latch,wait,inputs,keyboard,bios,root,messages]:fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=[0x3532,0x3643];message_entries=[0x36e0,0x3713,0x371f,0x372b,0x3737,0x3743,0x374f,0x375f,0x3788,0x3f0d,0x5c98];extra=message_entries+[0x1b2c,0x7a10,0x7a27,0x79c8,0x7a55,0x6a6a,0x69fe,0x6a03,0x6a3b,0x69b7,0xabfa];fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{x:04X}' for x in entries+extra]];require(len(fenced)==24,'Twenty-four composed fences');md=Cs(CS_ARCH_X86,CS_MODE_16);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;coverage=Counter();sp=0xe000
    specs={0x3537:(2,2),0x356a:(2,2),0x3577:(2,4),0x3587:(2,2),0x35c4:(5,5),0x35e4:(1,1),0x360f:(1,1),0x3626:(2,2),0x3648:(2,2),0x5c9d:(2,2),0x366a:(2,2),0x367f:(2,2),0x368c:(2,4),0x369f:(2,2),0x36b7:(4,4)};actual_targets={0x7a10,0x7a27,0x7a55,0x6a6a,0x69fe,0x6a3b,0xabfa};root_actual=set(entries+message_entries);targets=[0x1bac,0x1c51,0x1c02,0x1c23,0x1c2a,0x1c35,0x1c3c,0x1c43,0x1c4a,0x1c59]
    specs.update({0x36eb:(2,2),0x36f8:(2,4),0x3708:(2,2),0x3775:(3,3),0x3635:(2,2),0x3f1c:(2,2),0x3f37:(2,2),0x3794:(2,2),0x37ad:(5,5),0x37c6:(5,10),0x1b4e:(2,2),0x1c6d:(2,2),0x1c7a:(2,4)})
    def reg_event(r):return [values(r.registers),r.bp,r.carry]
    def msg_event(q):return ['far',q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),*reg_event(q.incoming)]
    def root_event(q):return ['root',q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,list(q.arguments),*reg_event(q.incoming)]
    def root_prefix(model,write,q):
        model.append(root_event(q))
        if q.site==0x1b88:
            loops=sum(e[0]=='root' and e[1]==0x1b88 for e in model);wait_once=int(profile==3);value=0 if loops<=wait_once else state if loops==wait_once+1 else 0xff;write(q.incoming.registers.ds*16+0x5490,bytes([value]))
        if q.site==0x1c0d:write(q.incoming.registers.ds*16+0x5490,bytes([2 if profile==1 else 9]))
    def input_event(q):return ['inputfar',q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,*reg_event(q.incoming)]
    def wait_input_event(q):return ['waitinput',q.site,q.segment,q.offset,*reg_event(q.incoming)]
    def counter_event(model,read,write,q):
        model.append(['counter',q.site,q.segment,q.offset,*reg_event(q.incoming)]);at=q.incoming.registers.ds*16+0x5e8c;old=struct.unpack('<I',read(at,4))[0];write(at,struct.pack('<I',(old+0x10000)&0xffffffff))
        if profile==3 and q.site==0x6a70:write(ds*16+0x62b6,struct.pack('<H',0x8000))
    def bios_event(q):return ['bios10',q.site,q.stack_segment,q.stack_sp,q.saved_flags,*reg_event(q.incoming)]
    def bios_model(model,q):
        model.append(bios_event(q));r=StateRegisters(Registers(*values(q.incoming.registers)),0xcafe,1-q.incoming.carry);r.registers.interrupts_enabled=1-((q.saved_flags>>9)&1);r.registers.direction=1-r.registers.direction;return r
    def bios16_event(model,site,ss,current,saved,r):model.append(['bios16',site,ss,current,saved,*reg_event(r)])
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;cpus={tail:Uc(UC_ARCH_X86,UC_MODE_16) for tail in [0,1]};relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000,0x9000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            if int(f['entry'][5:],16) not in entries+message_entries+[0x1b2c,0x6a6a]:continue
            for c in f['calls']:
                ip=int(c['site'][5:],16);segment,target=[int(x,16) for x in c['target'].split(':')]
                owner=int(f['entry'][5:],16)
                if target in [0x5c98,0x3788,0x3f0d] and segment==0x6c9 and owner!=0x1b2c:continue
                if owner==0x6a6a and target!=0x69fe:continue
                size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc,live=specs.get(ip,(0,0));calls[cs*16+ip]=(ip,load+segment,target,ip+size,argc,live,'root' if owner==0x1b2c else 'waitinput' if owner==0x6a6a else 'far')
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            if active.get('expected') and address==active['expected'][1]*16+active['expected'][2]:
                site,segment,target,ret,argc,live,tag=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Sequence platform far frame');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+4,live*2))) if live else [];q=MessageRequest(site,segment,target,argc,live,active['ss'],current,(C.c_uint16*10)(*(args+[0]*(10-live))),read_regs());active['expected']=None
                if tag=='root':
                    rq=RootRequest(site,segment,target,argc,live,(C.c_uint16*4)(*list(q.arguments)[:4]),q.incoming)
                    if target in root_actual:root_prefix(active['events'],lambda at,b:u.mem_write(at,b),rq)
                    else:active['pending']=('root',rq,ret,current);u.emu_stop();return
                elif tag=='waitinput':active['events'].append(wait_input_event(WaitRequest(1,site,segment,target,q.incoming)))
                elif tag=='inputfar':active['events'].append(input_event(InputRequest(1,site,segment,target,active['ss'],current,q.incoming)))
                elif target in actual_targets:active['events'].append(msg_event(q))
                else:active['pending']=('far',q,ret,current);u.emu_stop();return
            require(address in starts,'State platform escaped fence '+hex(address)+' CSIP='+hex(u.reg_read(UC_X86_REG_CS))+':'+hex(u.reg_read(UC_X86_REG_IP))+' case='+str((state,count,profile,same,tail))+' expected='+str(active.get('expected')))
            if address==cs*16+0x79c8 and not active['resume_counter']:
                current=u.reg_read(UC_X86_REG_SP);ret=struct.unpack('<H',u.mem_read(active['ss']*16+current,2))[0];q=WaitRequest(0,ret-5,cs,0x79c8,read_regs());active['pending']=('counter',q,0x79c8,current);u.emu_stop();return
            active['resume_counter']=False;active['instructions']+=1
            if address in calls:active['expected']=calls[address]
            if address==cs*16+0x69fe:
                currentds=u.reg_read(UC_X86_REG_DS);offset,segment=struct.unpack('<2H',u.mem_read(currentds*16+0x64dc,4));active['expected']=(0x69fe,segment,offset,0x6a02,0,0,'inputfar')
            if address==cs*16+0x1ba8:
                currentds=u.reg_read(UC_X86_REG_DS);bx=u.reg_read(UC_X86_REG_BX);active['dispatch_target']=struct.unpack('<H',u.mem_read(currentds*16+((bx+0x2302)&65535),2))[0]
        def interrupt(cpu,num,_):
            require(num in [0x10,0x16],'Only BIOS10/16');ret=u.reg_read(UC_X86_REG_IP);flags=u.reg_read(UC_X86_REG_EFLAGS);current=u.reg_read(UC_X86_REG_SP)-6;u.mem_write(active['ss']*16+current,struct.pack('<3H',ret,cs,flags&65535));u.reg_write(UC_X86_REG_SP,current);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300)
            if num==0x10:active['pending']=('bios10',BiosRequest(ret-2,num,active['ss'],current,flags&0x603,read_regs()),ret,current)
            else:bios16_event(active['events'],ret-2,active['ss'],current,flags&0x603,read_regs());active['pending']=('bios16',None,0x69b7,current);u.reg_write(UC_X86_REG_IP,0x69b7)
            u.emu_stop()
        for cpu in cpus.values():cpu.mem_map(0,0x100000);cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_INTR,interrupt)
        for state,count,profile,same,tail in itertools.product(range(1,10),[0,1,2],range(4),[0,1],[0,1]):
            u=cpus[tail];start=0xfffffff0 if profile==3 else 0;flags=0x603 if profile&1 else 2;ss=ds if same else 0x9000;data=bytearray(base);data[cs*16+0x1bf7]=0xcb if tail else 0xf8
            for row in range(7):
                bp=0x4000+row*0x800
                for index in range(256):struct.pack_into('<2H',data,ss*16+bp+index*4,0x1201+profile*0x100,0x1302-profile*0x100)
                struct.pack_into('<H',data,ss*16+0x2c9e+2*row,bp);data[ss*16+0x2e22+row]=2
            for page in [ds,0x5000]:
                struct.pack_into('<I',data,page*16+0x5e8c,start);struct.pack_into('<2H',data,page*16+0x64dc,0x6a03,cs);struct.pack_into('<H',data,page*16+0x8424,count);struct.pack_into('<H',data,page*16+0x9410,int(profile==1));struct.pack_into('<H',data,page*16+0x8a9a,int(profile==2));struct.pack_into('<11H',data,page*16+0x2300,0x1bac,*targets)
                for at,value in [(0x52ca,0x3b52),(0x52d2,0xffff),(0x380f,0x100),(0x331e,0xabcd),(0x8658,0xffff),(0x2282,0x1111),(0x2284,0x2222),(0x2286,0x3333),(0x2288,0x4444)]:struct.pack_into('<H',data,page*16+at,value)
                struct.pack_into('<H',data,page*16+0x62b6,0x100 if profile==1 else 0)
                for at in range(0x22da,0x2300,2):struct.pack_into('<H',data,page*16+at,(at+page)&65535)
                for at in [0x3008,0x300a,0x300c,0x300e,0x2fd8,0x2fda,0x536c,0x536e]:struct.pack_into('<H',data,page*16+at,(at+page)&65535)
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+8]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x1b2c),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def leaf(model,write,q,is_root=False):
                if is_root:root_prefix(model,write,q)
                else:model.append(msg_event(q))
                index=len(model);r=StateRegisters(Registers(*values(q.incoming.registers)),q.incoming.bp,index&1);rr=r.registers;rr.ax=0xa000+(index%4096);rr.bx=0xb000+(index%4096);rr.cx=0xc000+(index%4096);rr.dx=0xd000+(index%4096);rr.es=0x6000;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if profile==1 and q.site in [0x3537,0x3648]:rr.ds=0x5000
                if profile==2 and q.site==0x35c4:write(rr.ds*16+0x2e29,b'\x01')
                if q.site==0x3775:write(rr.ds*16+0x2f20,b'12\0')
                return r
            active.update(expected=None,pending=None,resume_counter=False,events=[],instructions=0,ss=ss,dispatch_target=0);u.emu_start(cs*16+0x1b2c,0x11210,count=100000)
            while active['pending']:
                kind,q,ret,callee_sp=active['pending'];active['pending']=None;require(len(active['events'])<4096,'Finite composed fixture')
                if kind=='bios16':u.emu_start(cs*16+ret,0x11210,count=100000);continue
                if kind=='counter':counter_event(active['events'],lambda at,n:bytes(u.mem_read(at,n)),lambda at,b:u.mem_write(at,b),q);active['resume_counter']=True;u.emu_start(cs*16+ret,0x11210,count=100000);continue
                r=bios_model(active['events'],q) if kind=='bios10' else leaf(active['events'],lambda at,b:u.mem_write(at,b),q,kind=='root');rr=r.registers;current=callee_sp+(6 if kind=='bios10' else 4)
                for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,0x11210,count=100000)
            label=f'{load:x}/{state}/{count}/{profile}/{same}/{tail}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Composed return '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];wait_entry=[0]
            def write(at,b):C.memmove(C.byref(bus,at),b,len(b))
            def counter_cb(ctx,m,q,r):
                try:
                    q=q.contents
                    if q.kind==0:counter_event(events,lambda at,n:bytes(bus[at:at+n]),write,q)
                    else:
                        events.append(wait_input_event(q));result=InputResult();inputs(bus,len(bus),load,ss,wait_entry[0]-10,0,C.byref(q.incoming),ic,None,32,C.byref(result));require(result.status==0,'Actual timed inputbridge');C.memmove(r,C.byref(result.returned),C.sizeof(result.returned))
                    return 1
                except Exception as e:errors.append(str(e));return 0
            def bios_cb(ctx,m,q,r):
                try:returned=bios_model(events,q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            def input_cb(ctx,m,q,r):
                try:
                    q=q.contents
                    if q.kind==1:
                        events.append(input_event(q));require((q.segment,q.offset)==(cs,0x6a03),'Observed6A03target');nested=InputResult();inputs(bus,len(bus),load,ss,q.stack_sp,1,C.byref(q.incoming),ic,None,32,C.byref(nested));require(nested.status==0,'Actual nativepoll');C.memmove(C.byref(r.contents.returned),C.byref(nested.returned),C.sizeof(nested.returned));return 1
                    before=r.contents.returned;sf=2|before.carry|(before.registers.interrupts_enabled<<9)|(before.registers.direction<<10);bios16_event(events,q.site,ss,q.stack_sp,sf,q.incoming);kr=KeyboardResult();keyboard(bus,len(bus),load,C.byref(q.incoming.registers),sf&~0x300,sf,C.byref(kr));require(kr.status==0,'Native installedBIOS');r.contents.returned=StateRegisters(kr.registers,q.incoming.bp,kr.return_flags&1);r.contents.zero=(kr.return_flags>>6)&1;return 1
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
                        elif q.offset in [0x7a55,0x6a6a]:wait_entry[0]=q.stack_sp;result=WaitResult();wait(bus,len(bus),load,q.stack_sp,int(q.offset==0x6a6a),q.arguments[0]|(q.arguments[1]<<16),C.byref(q.incoming),wc,None,32,C.byref(result))
                        elif q.offset in [0x6a3b,0x69fe]:result=InputResult();inputs(bus,len(bus),load,ss,q.stack_sp,4 if q.offset==0x6a3b else 0,C.byref(q.incoming),ic,None,32,C.byref(result))
                        else:result=BiosResult();bios(bus,len(bus),ss,q.stack_sp,C.byref(q.incoming),bc,None,1,C.byref(result))
                        require(result.status==0,'Native actualcallee '+hex(q.offset));returned=result.returned
                    C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            mc=MessageService(message_cb)
            def root_cb(ctx,m,q,r):
                try:
                    q=q.contents
                    if q.offset in root_actual:
                        root_prefix(events,write,q);child=MessageResult();entry_sp=sp-10
                        if q.offset in entries:sequence(bus,len(bus),load,ss,entry_sp,entries.index(q.offset),C.byref(q.incoming),mc,None,4096,C.byref(child))
                        else:messages(bus,len(bus),load,ss,entry_sp,message_entries.index(q.offset),C.byref(q.incoming),mc,None,4096,C.byref(child))
                        require(child.status==0,'Actual native statehandler '+hex(q.offset));returned=child.returned
                    else:returned=leaf(events,write,q,True)
                    C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            rc=RootService(root_cb);code_state=State();code_state.returns_state=tail;result=RootResult();root(bus,len(bus),load,C.byref(code_state),C.byref(incoming),rc,None,4096,C.byref(result));require(not errors and result.status==0,'Native composition '+label+str(errors));require(events==active['events'],'Ordered composedinterfaces '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=result.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(result.dispatch_target==active['dispatch_target'] and result.calls==sum(e[0]=='root' for e in events),'Rootdispatch/calls '+label);coverage['state_'+str(state)]+=1;coverage['returns_state_'+str(tail)]+=1;coverage['same_DS_SS_'+str(same)]+=1;coverage['counter_boundaries']+=sum(e[0]=='counter' for e in events);coverage['BIOS16_actual_handler_calls']+=sum(e[0]=='bios16' for e in events);coverage['BIOS10_ABI_calls']+=sum(e[0]=='bios10' for e in events);vectors+=1;instructions+=active['instructions']
    deps=['tools/validate_state_loop.py','tools/validate_mutable_control.py','tools/validate_state_messages.py','tools/validate_wait_control.py','tools/validate_input_bridge.py','tools/validate_keyboard.py','tools/validate_bios_block.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':sha,'native_libraries':[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in libraries],'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual1B2C withall11message/sharedentries,3532/3643,7A10/7A27/7A55/6A6A/79C8,69FE->6A03/6A3B/installed69B7/ABFA:24entry instruction/nativecomposition. Observedtarget6A03, syntheticcounterevents/interruptframes andcontrolledstatewriters; BIOS10/graphics/otherrootleaves ABImocks. Bothmutabletailstates are separateCPUs, nottransitioncoverage. NativeSSargument scratchmaterializedinsideexcludedliveframearea. No actualIRQ/rate/tickhistory/device/rendering/fullstate/resource/core/game/fidelity; separate fromhelpertotals.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
