"""Compare6686/680A/6828 with synthetic port201 response streams.

The poll count is an instruction effect, not elapsed-time or hardware fidelity.
No real device, keyboard IRQ or DOS process executes.
"""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['operation','port','value','interrupts_enabled']]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Request),C.POINTER(C.c_uint8))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','ax','bx','cx','dx','interrupts_enabled']]+[('reads',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));sample=dll.td2ega_gameport_sample;sample.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,Service,C.c_void_p,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint32,C.POINTER(Result)];sample.restype=None;initialize=dll.td2ega_gameport_initialize;initialize.argtypes=[C.POINTER(C.c_uint8)];initialize.restype=None;translate=dll.td2ega_gameport_translate;translate.argtypes=[C.POINTER(C.c_uint8),C.c_uint16];translate.restype=C.c_uint16
    rng=random.Random(0x6686);cases=[];baseline=bytes((i*37+11)&255 for i in range(65536))
    profiles=[(0x50,0,0x4e20,8,0,0),(0,4000,500,8,100,300),(100,300,200,1,125,275),(100,300,200,0,125,275),(0x7fff,0x8000,0xffff,1,0x7ffe,0x8001),(0x8000,0x7fff,0x8001,1,0xffff,0),(0xffff,0,0x7fff,0xffff,0x8000,0x7fff)]
    delays=[(0,0),(0,1),(1,0),(1,2),(2,1),(79,81),(81,79),(80,80),(3999,3999),(4000,4000),(4001,4001),(2,4001),(4001,2)]
    for x,y in delays:
        for xp in profiles:
            for yp in profiles[:4]:
                for initial,final in [(0,0),(0x33,0x33),(0xff,0xdf),(0xdf,0xef)]:cases.append((x,y,xp,yp,initial,final,1,1,'structured'))
    for _ in range(1024):cases.append((rng.randrange(9),rng.randrange(9),tuple(rng.randrange(65536) for _ in range(6)),tuple(rng.randrange(65536) for _ in range(6)),rng.randrange(256),rng.randrange(256),rng.choice([1,0xff]),rng.choice([1,3,0xff]),'random_state'))
    for enabled,config in [(0,0),(0,1),(1,0),(1,2),(0xff,0xfe)]:cases.append((0,0,profiles[0],profiles[0],0xff,0,enabled,config,'disabled'))
    coverage=Counter();vectors=instructions=0;ds,ss,sp=0x5000,0x9000,0x8000
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;first,length=0x6c90+0x6686,0x6839-0x6686;code=bytearray(image[first:first+length])
        for r in relocs:
            if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
        uc.mem_write(cs*16+0x6686,bytes(code));starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x6686)};active={}
        def fetch(u,address,size,_):require(address in starts,'Gameport escaped instruction fence');active['instructions']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def service(model,op,port,value,enabled):
            require(port==0x201,'Unexpected port')
            if op==1:
                require(model['phase']=='after_initial' and enabled==0 and value==active['initial'],'Trigger request');model['phase']='poll';model['events'].append([op,port,value,enabled]);return 0
            if model['phase']=='initial':result=active['initial'];model['phase']='after_initial'
            elif model['phase']=='poll' and enabled==0:
                tick=model['polls'];model['polls']+=1;result=(0xf0 if tick&1 else 0x0c)|(1 if tick<active['x'] else 0)|(2 if tick<active['y'] else 0)
            else:require(model['phase']=='poll' and enabled==1,'Final read phase');result=active['final'];model['phase']='done'
            model['reads']+=1;model['events'].append([op,port,result,enabled]);return result
        def port_in(u,port,size,_):require(size==1,'Port width');return service(active['guest'],0,port,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,port,size,value,_):require(size==1,'Port width');service(active['guest'],1,port,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
        def prepare(entry,flags):
            uc.mem_write(ss*16+sp,struct.pack('<3H',0x100,0xa000,active.get('argument',0)))
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_BX,0xa55a),(UC_X86_REG_CX,0x4567),(UC_X86_REG_DX,0x7654),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,guest={'phase':'initial','polls':0,'reads':0,'events':[]})
        def check_return():
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Far return');require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers')
        for x,y,xp,yp,initial,final,enabled,config,category in cases:
            data=bytearray(baseline);data[0x6cfc]=enabled;data[0x6cfe]=config;struct.pack_into('<6H',data,0x6282,*xp);struct.pack_into('<6H',data,0x628e,*yp);uc.mem_write(ds*16,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10)
            active.update(x=x,y=y,initial=initial,final=final);prepare(0x6686,flags);uc.emu_start(cs*16+0x6686,0xa0100,count=100000);gb=(C.c_uint8*65536).from_buffer_copy(data);model={'phase':'initial','polls':0,'reads':0,'events':[]};errors=[]
            def native_service(ctx,request_ptr,read_ptr):
                try:
                    q=request_ptr.contents;read_ptr.contents.value=service(model,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            callback=Service(native_service);result=Result();sample(gb,65536,callback,None,0xa55a,0x4567,0x7654,(flags>>9)&1,5000,C.byref(result));label=f'{load:x}/{category}/{x}/{y}/{xp}/{yp}/{initial:x}/{final:x}'
            require(not errors,'Native service '+label+str(errors));require(result.status==0 and model==active['guest'],'Service effects '+label);require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(result.ax,result.bx,result.cx,result.dx),'Scratch outputs '+label);check_return()
            require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==result.interrupts_enabled and uc.reg_read(UC_X86_REG_EFLAGS)&0x400==flags&0x400,'IF/DF '+label);require(result.reads==model['reads'],'Read count');coverage[category]+=1;coverage['poll_timeout' if model['polls']>=4000 else 'poll_completed']+=1;instructions+=active['instructions'];vectors+=1
        for fill in [0,0xff,0xa5,0x3c]:
            for flags in [2,0x202,0x402,0x602]:
                data=bytes([fill])*65536;uc.mem_write(ds*16,data);prepare(0x680a,flags);uc.emu_start(cs*16+0x680a,0xa0100,count=32);gb=(C.c_uint8*65536).from_buffer_copy(data);initialize(gb);require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Initializer group');check_return();require(not active['guest']['events'],'Initializer ports');require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'Initializer IF/DF');coverage['initialize']+=1;instructions+=active['instructions'];vectors+=1
        uc.mem_write(ds*16,baseline);gb=(C.c_uint8*65536).from_buffer_copy(baseline)
        for argument in range(65536):
            active['argument']=argument;prepare(0x6828,0x602);uc.emu_start(cs*16+0x6828,0xa0100,count=32);value=translate(gb,argument);require(value==uc.reg_read(UC_X86_REG_AX)==baseline[0x629e+(argument&15)],'Translation');require(uc.reg_read(UC_X86_REG_BX)==argument&15 and uc.reg_read(UC_X86_REG_CX)==0x4567 and uc.reg_read(UC_X86_REG_DX)==0x7654,'Translation scratch');check_return();require(bytes(uc.mem_read(ds*16,65536))==bytes(gb) and not active['guest']['events'],'Translation data/ports');coverage['translate']+=1;instructions+=active['instructions'];vectors+=1
    diagnostics=0
    for service_fn,budget in [(Service(),5000),(Service(lambda ctx,req,res:0),5000),(Service(lambda ctx,req,res:1),0)]:
        data=(C.c_uint8*65536)();data[0x6cfc]=data[0x6cfe]=1;r=Result();sample(data,65536,service_fn,None,0,0,0,0,budget,C.byref(r));require(r.status==2,'Native service/budget diagnostic');diagnostics+=1
    record={'schema':1,'function_ids':['FN-EGA-000156','FN-EGA-000412','FN-EGA-000413'],'result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_gameport.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete6686/680A/6828 bounded synthetic fullgroup andport201 streams, serialized noIRQ adapterprofile. Pollcounts, timeoutdefaults, signed/unsigned calibration andSUBoverflow, orderedIF/ports andscratchoutputs compared; no actual gameport timing/hardware, inputsession, caller/resource/IRQ or game/fidelity acceptance. Native service/budget diagnostics areoutside original.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
