"""Compare complete420A with recovered input/control/motion native composition.

Callback bodies are far-frame ABI mocks; no BIOS/device/IRQ session executes.
"""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import random
import itertools
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_key_dispatch import Registers,Request as KeyRequest,Callback,require
from validate_gameport import Request as PortRequest,Service as PortService
from validate_mutable_control import State
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class BiosRequest(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['operation','ax','interrupts_enabled','direction']]


class BiosResponse(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['ax','zero','interrupts_enabled','direction']]


BiosService=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(BiosRequest),C.POINTER(BiosResponse))


class Services(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['callback_segment','original_ds','original_ss']]+[('max_gameport_reads',C.c_uint32),('bios',BiosService),('bios_context',C.c_void_p),('port',PortService),('port_context',C.c_void_p),('callback',Callback),('callback_context',C.c_void_p)]


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','stage','bp','di','raw_bits']]+[('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_input_update;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(C.c_uint8),C.POINTER(Services),C.POINTER(State),C.POINTER(Registers),C.c_uint16,C.c_uint16,C.POINTER(Result)];native.restype=None
    key_at=[0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305];cases=[]
    for paused in [0,1]:
        for available in [0,1]:
            for same in [0,1]:
                for busy in [0,1]:
                    for flags in [2,0x202,0x402,0x602]:
                        for idle in [0,0x95f,0x960,0x961,0xffff]:
                            for activity in [0,1,2]:
                                for mask in [0,1,3,0x155,0x2aa,0x3ff]:
                                    cases.append((paused,[0,1,2,3,0x100,0x8400,0x8500,0xffff][mask%8],available,same,busy,flags,mask,idle,activity,bool(mask&1),'complete_branches',None))
    for mask in range(1024):
        for shared in [False,True]:cases.append((0,mask&255,1,1,0,0x602,mask,0,2,shared,'all_direction_masks',None))
    rng=random.Random(0x420a)
    for _ in range(4096):
        changes=[(at,rng.randrange(256),1) for at in [0x33d5,0x3365,0x3366,0x3367,0x90a8,0x33af,0x5490,0x2f56,0x23a6]]+[(at,rng.randrange(65536),2) for at in [0x332c,0x23aa,0x23ac,0x23ae,0x3328,0x52ce,0x2f4c,0x2f4e,0x3324,0x3326,0x23c8,0x335a,0x3322]]
        cases.append((rng.randrange(2),rng.randrange(65536),rng.randrange(2),rng.randrange(2),rng.randrange(2),rng.choice([2,0x202,0x402,0x602]),rng.randrange(1024),rng.randrange(65536),rng.randrange(3),bool(rng.randrange(2)),'varied_composed_states',changes))
    coverage=Counter();vectors=instructions=0;sp=0xe000;baseline=bytearray(bytes((i*37+11)&255 for i in range(65536)))
    for i in range(128):struct.pack_into('<H',baseline,0x6048+2*i,[0,0x100,0x200,0x300][i%4])
    for i in range(133):struct.pack_into('<H',baseline,0x6148+2*i,[0x300,0x200,0x100,0][i%4])
    for load in [0x1000,0x2345]:
        forms=list(itertools.product([0,2],[0,2],[1,2]));cpus={f:Uc(UC_ARCH_X86,UC_MODE_16) for f in forms}
        for cpu in cpus.values():cpu.mem_map(0,0x100000)
        cs=load+0x6c9;ds=load+0x178f;starts=set();active={}
        relocated=bytearray(image)
        for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
        for form,cpu in cpus.items():
            cpu.mem_write(load*16,bytes(relocated))
            for at,f in zip([0x424a,0x4275,0x42ad],form):cpu.mem_write(cs*16+at,bytes([{0:0x76,1:0x77,2:0x75}[f]]))
        graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entry_set={'06C9:'+f'{ip:04X}' for ip in [0x420a,0x4281,0x43c3,0x4441,0x448a,0x44a6,0x4612,0x6620,0x6828,0x6686,0x6601,0x6528]}|{'06B3:0008','13A8:2EE8'}
        fenced=[f for f in graph['functions'] if f['entry'] in entry_set];require(len(fenced)==len(entry_set),'Missing composed fence');starts={((load+int(f['entry'].split(':')[0],16))*16+ip) for f in fenced for ip in f['instructions']}
        def fetch(u,address,size,_):
            if address in [cs*16+i for i in [0x100,0x200,0x300]]:active['callback']=address-cs*16;u.emu_stop();return
            require(address in starts,'Input escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x6528:active['dispatches']+=1
            if address==cs*16+0x6686:active['gameports']+=1
            if address==cs*16+0x4216:active['raw_bits']=u.reg_read(UC_X86_REG_AX)
        def bios(model,operation,ax,enabled,direction):
            require(operation in [0,1],'BIOS operation');model['bios'].append([operation,ax,enabled,direction])
            returned_if=1 if profile==1 and operation==1 else enabled
            returned_df=direction^1 if profile==2 else direction
            if operation==1:return active['key']^0xff00,int(not active['available']),returned_if,returned_df
            return active['key'],(active['key']>>1)&1,returned_if,returned_df
        def interrupt(u,num,_):
            require(num==0x16,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);flags=u.reg_read(UC_X86_REG_EFLAGS);value,zero,enabled,direction=bios(active['guest'],ax>>8,ax,(flags>>9)&1,(flags>>10)&1);u.reg_write(UC_X86_REG_AX,value);u.reg_write(UC_X86_REG_EFLAGS,(flags&~0x640)|(zero<<6)|(enabled<<9)|(direction<<10))
        def port(model,operation,value,enabled):
            if operation==1:require(model['phase']=='after_initial' and enabled==0 and value==active['initial'],'Port trigger');model['phase']='poll';model['ports'].append([operation,value,enabled]);return 0
            if model['phase']=='initial':value=active['initial'];model['phase']='after_initial'
            elif model['phase']=='poll' and enabled==0:
                tick=model['polls'];model['polls']+=1;value=(1 if tick<(active['key']&1) else 0)|(2 if tick<((active['key']>>1)&1) else 0)
            else:require(model['phase']=='poll' and enabled==1,'Final port read');value=active['final'];model['phase']='done'
            model['reads']+=1;model['ports'].append([operation,value,enabled]);return value
        def port_in(u,p,size,_):require(p==0x201 and size==1,'Port read');return port(active['guest'],0,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,p,size,value,_):require(p==0x201 and size==1,'Port write');port(active['guest'],1,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        for cpu in cpus.values():
            cpu.hook_add(UC_HOOK_CODE,fetch);cpu.hook_add(UC_HOOK_INTR,interrupt);cpu.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);cpu.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        def model():return {'bios':[],'ports':[],'callbacks':[],'phase':'initial','polls':0,'reads':0}
        for profile,form,case in itertools.product([0,1,2],forms,cases):
            paused,key,available,same,busy,flags,mask,idle,activity,shared,category,changes=case
            uc=cpus[form];state=State();state.load_segment=load;state.branch_424a,state.branch_4275,state.branch_42ad=form
            ss=ds if same else 0x9000;es=ds if shared else 0x7000;data=bytearray(baseline);data[0x6252]=busy;data[0x6cfc]=1 if vectors&1 else 0;data[0x6cfe]=1;data[0x33d4]=paused
            struct.pack_into('<6H',data,0x6282,0,200,5000,8,50,150);struct.pack_into('<6H',data,0x628e,0,200,5000,8,50,150);struct.pack_into('<H',data,0x3352,idle);struct.pack_into('<H',data,0x8a9a,activity)
            data[0x33d6:0x33db]=bytes([0,1,2,3,0xff]);struct.pack_into('<5H',data,0x33dc,0x44bf,0x44c5,0x44c5,0x44d2,0x44d2)
            for i,at in enumerate(key_at):data[at]=[1,0x80,0xff][mask%3] if mask&(1<<i) else 0
            if changes:
                for at,value,width in changes:
                    if width==1:data[at]=value
                    else:struct.pack_into('<H',data,at,value)
            esdata=bytearray(baseline);esdata[0x33d6:0x33db]=bytes([0,0xff,3,2,1])
            uc.mem_write(ds*16,bytes(data))
            if not shared:uc.mem_write(es*16,bytes(esdata))
            uc.mem_write(ss*16+sp-64,b'\xa5'*64+struct.pack('<H',0x400)+b'\xa5'*6)
            if same:data[sp-64:sp+8]=b'\xa5'*64+struct.pack('<H',0x400)+b'\xa5'*6
            incoming=Registers(0xa55a,0x1234,0x4567,0x7654,(flags>>9)&1,(flags>>10)&1);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_SI,0x3456),(UC_X86_REG_ES,es)]
            for reg,val in preserved+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_DI,0x2345),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x420a),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(key=key,available=available,initial=0xff,final=0xdf,callback=None,instructions=0,dispatches=0,gameports=0,raw_bits=0,guest=model());uc.emu_start(cs*16+0x420a,cs*16+0x400,count=100000)
            def callback_values(offset):return Registers(0xdead,offset^0xbeef,key^0x1357,key^0x2468,(key>>2)&1,(key>>3)&1)
            def callback_changes(write):write(0x6252,bytes([key&255]));write(0x6300,struct.pack('<H',key^0xface))
            if active['callback'] is not None:
                offset=active['callback'];current_sp=uc.reg_read(UC_X86_REG_SP);require(bytes(uc.mem_read(ss*16+current_sp,4))==struct.pack('<2H',0x655b,cs),'Farcallback frame');v=[uc.reg_read(reg) for reg in [UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX]];fl=uc.reg_read(UC_X86_REG_EFLAGS);active['guest']['callbacks'].append([cs,offset,*v,(fl>>9)&1,(fl>>10)&1]);values=callback_values(offset);callback_changes(lambda at,b:uc.mem_write(ds*16+at,b))
                for reg,val in [(UC_X86_REG_AX,values.ax),(UC_X86_REG_BX,values.bx),(UC_X86_REG_CX,values.cx),(UC_X86_REG_DX,values.dx),(UC_X86_REG_SI,0xdead),(UC_X86_REG_DI,0xbeef),(UC_X86_REG_EFLAGS,2|(values.interrupts_enabled<<9)|(values.direction<<10)),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x655b),(UC_X86_REG_SP,current_sp+4)]:uc.reg_write(reg,val)
                uc.emu_start(cs*16+0x655b,cs*16+0x400,count=256)
            gb=(C.c_uint8*65536).from_buffer_copy(data);native_model=model();errors=[]
            def bios_cb(ctx,request_ptr,response_ptr):
                try:q=request_ptr.contents;response_ptr.contents.ax,response_ptr.contents.zero,response_ptr.contents.interrupts_enabled,response_ptr.contents.direction=bios(native_model,q.operation,q.ax,q.interrupts_enabled,q.direction);return 1
                except Exception as e:errors.append(str(e));return 0
            def port_cb(ctx,request_ptr,read_ptr):
                try:q=request_ptr.contents;require(q.port==0x201,'Native port');read_ptr.contents.value=port(native_model,q.operation,q.value,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            def callback_cb(ctx,group_ptr,request_ptr,returned_ptr):
                try:
                    q=request_ptr.contents;v=q.registers;native_model['callbacks'].append([q.segment,q.offset,v.ax,v.bx,v.cx,v.dx,v.interrupts_enabled,v.direction]);callback_changes(lambda at,b:C.memmove(C.byref(gb,at),b,len(b)));values=callback_values(q.offset);C.memmove(returned_ptr,C.byref(values),C.sizeof(values));return 1
                except Exception as e:errors.append(str(e));return 0
            bs,ps,ks=BiosService(bios_cb),PortService(port_cb),Callback(callback_cb);services=Services(cs,ds,ss,5000,bs,None,ps,None,ks,None);result=Result();eb=gb if shared else (C.c_uint8*65536).from_buffer_copy(esdata);native(gb,65536,eb,C.byref(services),C.byref(state),C.byref(incoming),0x5678,0x2345,C.byref(result));label=f'{load:x}/{profile}/{form}/{paused}/{key:x}/{available}/{same}/{busy}/{flags:x}/{mask}/{idle}/{activity}/{shared}/{category}'
            require(not errors and result.status==0,'Native services '+label+str(errors));require(native_model==active['guest'],'Ordered service events '+label)
            actual=bytearray(uc.mem_read(ds*16,65536));expected=bytearray(gb)
            if same:actual[sp-64:sp+8]=expected[sp-64:sp+8]
            require(actual==expected,'Full nonstack group '+label);r=result.registers;require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(r.ax,r.bx,r.cx,r.dx),'Scratch outputs '+label)
            require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==r.interrupts_enabled and (uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==r.direction,'IF/DF '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label);require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(cs,0x400,sp+2),'Near return '+label)
            require(uc.reg_read(UC_X86_REG_BP)==result.bp and uc.reg_read(UC_X86_REG_DI)==result.di and result.stage==3,'BP/DI/composed stage '+label);require(result.raw_bits==active['raw_bits'],'Raw bit capture '+label)
            if not shared:require(bytes(eb)==bytes(uc.mem_read(es*16,65536)),'Independent ES view unchanged')
            coverage['BIOS_flag_profile_'+str(profile)]+=1;coverage[category]+=1;coverage['paused_'+str(paused)]+=1;coverage['same_DS_SS_'+str(bool(same))]+=1;coverage['same_DS_ES_'+str(shared)]+=1;coverage['callbacks']+=len(native_model['callbacks']);coverage['gameport_calls']+=active['gameports'];instructions+=active['instructions'];vectors+=1
    deps=['tools/validate_key_dispatch.py','tools/validate_gameport.py','tools/validate_mutable_control.py'];record={'schema':1,'function_id':'FN-EGA-000367','result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_update.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'executed_entries':sorted(entry_set),'code_states':{'branch_combinations':8,'observed_stable_forms':[[0,0,1],[2,2,2]],'other_combinations':'Synthetic states, no transition reachability admitted'},'bios_flag_profiles':['historical_preserve','AH1_IF1','synthetic_DF_toggle'],'limits':'ExplicitresponseIFDF; actual69B7bodycomposition separate. Explicit424A/4275/42AD forms; Complete420A andactualfourteen-entrycalleecomposition with recoverednative input/control/motion helpers; syntheticBIOS/port/farcallback adapters, boundedscanner targets, DS/SS/ES distinct/shared profiles. Fullgroup except72byteSSframearea whenDS=SS; frames,BP/DI/scratch/IF/DF checked. NoactualBIOS/input/device/IRQ, callbackbodies/fullstate/core/resource/game/fidelity acceptance. Byte-ring notcalled orintegrated.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
