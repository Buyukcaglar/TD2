"""Compare65C5/6601/6620 with actual dispatch/gameport and synthetic BIOS.

Callback bodies are far-frame ABI mocks; no BIOS/device/IRQ session executes.
"""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_key_dispatch import Registers,Request as KeyRequest,Callback,require
from validate_gameport import Request as PortRequest,Service as PortService
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
    _fields_=[(n,C.c_uint16) for n in ['status','bios_probes','bios_reads','dispatch_used','gameport_used']]+[('registers',Registers),('dispatch_argument',C.c_uint16),('gameport_reads',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));functions={'poll':dll.td2ega_input_poll,'consume':dll.td2ega_input_consume_if_stack_group,'bits':dll.td2ega_input_direction_bits}
    for fn in functions.values():fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Services),C.POINTER(Registers),C.POINTER(Result)];fn.restype=None
    entries={'poll':0x65c5,'consume':0x6601,'bits':0x6620};key_at=[0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305];cases=[]
    for kind in ['poll','consume']:
        for key in [0,1,0xa,0x1b,0x7f,0x80,0xff,0x100,0x8400,0x8500,0xff00,0xffff,0x8001,0x4200,0x013a]:
            for available in [0,1]:
                for same in [0,1]:
                    for busy in [0,1]:
                        for flags in [2,0x202,0x402,0x602]:cases.append((kind,key,available,same,busy,flags,0,1,0x33,0x33,0,'wrapper_guards'))
        for key in sorted(set(range(256))|{i<<8 for i in range(256)}):cases.append((kind,key,1,1,0,0x602,0,1,0xff,0xff,0,'all_bios_byte_domains'))
    for mask in range(1024):
        for nonzero in [1,0x80,0xff]:
            for same in [0,1]:cases.append(('bits',0,0,same,0,0x602,mask,nonzero,0x33,0x33,0,'all_direction_boolean_masks'))
    for initial in [0,0x33,0xff,0xdf,0xef]:
        for final in [0,0x33,0xff,0xdf,0xef]:
            for previous in [0,0xd,0x1234]:cases.append(('poll',0,0,1,0,0x402,0,1,initial,final,previous,'gameport_repeat_map'))
    coverage=Counter();vectors=instructions=0;sp=0xe000;baseline=bytearray(bytes((i*37+11)&255 for i in range(65536)))
    for i in range(128):struct.pack_into('<H',baseline,0x6048+2*i,[0,0x100,0x200,0x300][i%4])
    for i in range(133):struct.pack_into('<H',baseline,0x6148+2*i,[0x300,0x200,0x100,0][i%4])
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;ds=load+0x178f;starts=set();active={}
        for ip,length in [(0x6528,93),(0x65c5,60),(0x6601,31),(0x6620,102),(0x6686,388)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            if address in [cs*16+i for i in [0x100,0x200,0x300]]:active['callback']=address-cs*16;u.emu_stop();return
            require(address in starts,'Input escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x6528:active['dispatches']+=1
            if address==cs*16+0x6686:active['gameports']+=1
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
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        def model():return {'bios':[],'ports':[],'callbacks':[],'phase':'initial','polls':0,'reads':0}
        for profile,case in ((p,c) for c in cases for p in ([0] if c[0]=='bits' else [0,1,2])):
            kind,key,available,same,busy,flags,mask,nonzero,initial,final,previous,category=case
            ss=ds if same else 0x9000;data=bytearray(baseline);data[0x6252]=busy;data[0x6cfc]=1 if vectors&1 else 0;data[0x6cfe]=1
            struct.pack_into('<6H',data,0x6282,0,200,5000,8,50,150);struct.pack_into('<6H',data,0x628e,0,200,5000,8,50,150);struct.pack_into('<H',data,0x6274,previous)
            for i,at in enumerate(key_at):data[at]=nonzero if mask&(1<<i) else 0
            uc.mem_write(ds*16,bytes(data));uc.mem_write(ss*16+sp-64,b'\xa5'*64+struct.pack('<2H',0x400,0xa000)+b'\xa5'*4)
            if same:data[sp-64:sp+8]=b'\xa5'*64+struct.pack('<2H',0x400,0xa000)+b'\xa5'*4
            incoming=Registers(0xa55a,0x1234,0x4567,0x7654,(flags>>9)&1,(flags>>10)&1);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[kind]),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(key=key,available=available,initial=initial,final=final,callback=None,instructions=0,dispatches=0,gameports=0,guest=model());uc.emu_start(cs*16+entries[kind],0xa0400,count=100000)
            def callback_values(offset):return Registers(0xdead,offset^0xbeef,key^0x1357,key^0x2468,(key>>2)&1,(key>>3)&1)
            def callback_changes(write):write(0x6252,bytes([key&255]));write(0x6300,struct.pack('<H',key^0xface))
            if active['callback'] is not None:
                offset=active['callback'];current_sp=uc.reg_read(UC_X86_REG_SP);require(bytes(uc.mem_read(ss*16+current_sp,4))==struct.pack('<2H',0x655b,cs),'Farcallback frame');v=[uc.reg_read(reg) for reg in [UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX]];fl=uc.reg_read(UC_X86_REG_EFLAGS);active['guest']['callbacks'].append([cs,offset,*v,(fl>>9)&1,(fl>>10)&1]);values=callback_values(offset);callback_changes(lambda at,b:uc.mem_write(ds*16+at,b))
                for reg,val in [(UC_X86_REG_AX,values.ax),(UC_X86_REG_BX,values.bx),(UC_X86_REG_CX,values.cx),(UC_X86_REG_DX,values.dx),(UC_X86_REG_SI,0xdead),(UC_X86_REG_DI,0xbeef),(UC_X86_REG_EFLAGS,2|(values.interrupts_enabled<<9)|(values.direction<<10)),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x655b),(UC_X86_REG_SP,current_sp+4)]:uc.reg_write(reg,val)
                uc.emu_start(cs*16+0x655b,0xa0400,count=128)
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
            bs,ps,ks=BiosService(bios_cb),PortService(port_cb),Callback(callback_cb);services=Services(cs,ds,ss,5000,bs,None,ps,None,ks,None);result=Result();functions[kind](gb,65536,C.byref(services),C.byref(incoming),C.byref(result));label=f'{load:x}/{profile}/{kind}/{key:x}/{available}/{same}/{busy}/{flags:x}/{mask}/{category}'
            require(not errors and result.status==0,'Native services '+label+str(errors));require(native_model==active['guest'],'Ordered service events '+label)
            actual=bytearray(uc.mem_read(ds*16,65536));expected=bytearray(gb)
            if same:actual[sp-64:sp+8]=expected[sp-64:sp+8]
            require(actual==expected,'Full nonstack group '+label);r=result.registers;require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(r.ax,r.bx,r.cx,r.dx),'Scratch outputs '+label)
            require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==r.interrupts_enabled and (uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==r.direction,'IF/DF '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label);require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4),'Far return '+label)
            require(result.dispatch_used==active['dispatches'] and result.gameport_used==active['gameports'],'Helper composition '+label);require(result.bios_probes==sum(e[0]==1 for e in native_model['bios']) and result.bios_reads==sum(e[0]==0 for e in native_model['bios']) and result.gameport_reads==native_model['reads'],'Service counts')
            if result.dispatch_used:require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp-2,2)))[0]==result.dispatch_argument,'Private pushed key argument')
            coverage['BIOS_flag_profile_'+str(profile)]+=1;coverage[kind]+=1;coverage[category]+=1;coverage['same_DS_SS_'+str(bool(same))]+=1;coverage['callbacks']+=len(native_model['callbacks']);coverage['gameport_calls']+=result.gameport_used;instructions+=active['instructions'];vectors+=1
    deps=['tools/validate_key_dispatch.py','tools/validate_gameport.py'];record={'schema':1,'function_ids':['FN-EGA-000155','FN-EGA-000410','FN-EGA-000411'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_poll.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'bios_flag_profiles':['historical_preserve','AH1_IF1','synthetic_DF_toggle'],'limits':'ExplicitresponseIFDF; actual69B7bodycomposition separate. Complete65C5/6601/6620 with actual dispatcher/gameport callees, syntheticBIOS/portservices andfarcallback ABImocks. DS=SS andindependentSS profiles, all1024directionmasks, BIOShigh/lowbyte domains, repeatmap andscratch/IF/DF. Fullgroup compared except72-byte live/historicalstackrange whenDS=SS, with farframes/argumentwitnesses checkedseparately. NoactualBIOS/input/device/IRQ, callbackbodies/fullcaller/resource/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
