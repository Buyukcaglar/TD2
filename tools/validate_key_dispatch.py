"""Compare6528 with synthetic far-callback adapters, retaining pushed segment.

Callback bodies are explicit ABI mocks; no real input/device/IRQ executes.
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
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Registers(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['ax','bx','cx','dx','interrupts_enabled','direction']]


class Request(C.Structure):
    _fields_=[('segment',C.c_uint16),('offset',C.c_uint16),('registers',Registers)]


Callback=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Registers))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','argument','called','callback_offset','callback_segment']]+[('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_key_dispatch;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(Registers),Callback,C.c_void_p,C.POINTER(Result)];native.restype=None
    coverage=Counter();vectors=instructions=0;ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytearray(bytes((i*37+11)&255 for i in range(65536)))
    for i in range(128):struct.pack_into('<H',baseline,0x6048+2*i,[0,0x100,0x200,0x300][i%4])
    for i in range(133):struct.pack_into('<H',baseline,0x6148+2*i,[0x300,0x200,0x100,0][i%4])
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;first,length=0x6c90+0x6528,93;code=bytearray(image[first:first+length])
        for r in relocs:
            if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
        uc.mem_write(cs*16+0x6528,bytes(code));starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x6528)};active={}
        def fetch(u,address,size,_):
            if address in [cs*16+off for off in [0x100,0x200,0x300]]:
                active['callback']=address-cs*16;u.emu_stop();return
            require(address in starts,'Dispatcher escaped instruction fence');active['instructions']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def writer(u,access,address,size,value,_):
            if address==ds*16+0x6252:
                require(size==1,'Guard writer width');active['guard_writes'].append([value&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1])
            else:require(ss*16+sp-24<=address and address+size<=ss*16+sp+6,'Unexpected dispatcher CPU writer')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_MEM_WRITE,writer)
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
        for key in range(65536):
            for busy in [0,1]:
                data=bytearray(baseline);data[0x6252]=busy;flags=2|((key&1)<<9)|(((key>>1)&1)<<10);incoming=Registers(0xa55a,0x1234,0x4567,0x7654,(flags>>9)&1,(flags>>10)&1)
                uc.mem_write(ds*16,bytes(data));uc.mem_write(ss*16+sp-24,b'\xa5'*24+struct.pack('<3H',0x400,0xa000,key))
                for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6528),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
                active.update(callback=None,instructions=0,guard_writes=[]);uc.emu_start(cs*16+0x6528,0xa0400,count=128);request_observation=None
                def return_values(offset):return Registers(0xdead,offset^0xbeef,key^0x1357,key^0x2468,(key>>2)&1,(key>>3)&1)
                def group_changes(write):
                    # Explicit ABI mock effects, not original callback claims.
                    write(0x6252,bytes([key&255]));write(0x6300,struct.pack('<H',key^0xface))
                if active['callback'] is not None:
                    offset=active['callback'];require(uc.reg_read(UC_X86_REG_SP)==sp-10,'Pushed-segment nearCALL frame depth')
                    require(bytes(uc.mem_read(ss*16+sp-10,4))==struct.pack('<2H',0x655b,cs),'Actual savedIP/pushedsegment far frame')
                    require(bytes(uc.mem_read(ss*16+sp-6,4))==struct.pack('<2H',0x3456,0x2345),'Saved SI/DI ordering')
                    require(uc.reg_read(UC_X86_REG_AX)==cs and uc.reg_read(UC_X86_REG_BX)==offset and (uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==1,'Callback input registers/IF')
                    require(bytes(uc.mem_read(ds*16+0x6252,1))==b'\x01','Guard raised beforecallback')
                    request_observation=[cs,offset,cs,offset,0x4567,0x7654,1,incoming.direction];values=return_values(offset);group_changes(lambda at,b:uc.mem_write(ds*16+at,b))
                    for reg,val in [(UC_X86_REG_AX,values.ax),(UC_X86_REG_BX,values.bx),(UC_X86_REG_CX,values.cx),(UC_X86_REG_DX,values.dx),(UC_X86_REG_SI,0xdead),(UC_X86_REG_DI,0xbeef),(UC_X86_REG_EFLAGS,2|(values.interrupts_enabled<<9)|(values.direction<<10)),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x655b),(UC_X86_REG_SP,sp-6)]:uc.reg_write(reg,val)
                    uc.emu_start(cs*16+0x655b,0xa0400,count=64)
                gb=(C.c_uint8*65536).from_buffer_copy(data);errors=[];native_requests=[]
                def native_callback(ctx,group_ptr,request_ptr,returned_ptr):
                    try:
                        q=request_ptr.contents;v=q.registers;native_requests.append([q.segment,q.offset,v.ax,v.bx,v.cx,v.dx,v.interrupts_enabled,v.direction]);require(group_ptr[0x6252]==1,'Native guard beforecallback')
                        group_changes(lambda at,b:C.memmove(C.cast(C.byref(gb,at),C.c_void_p),b,len(b)));values=return_values(q.offset);C.memmove(returned_ptr,C.byref(values),C.sizeof(values));return 1
                    except Exception as e:errors.append(str(e));return 0
                callback=Callback(native_callback);result=Result();native(gb,65536,key,cs,C.byref(incoming),callback,None,C.byref(result));label=f'{load:x}/{key:04x}/{busy}'
                require(not errors and result.status==0,'Native callback '+label+str(errors));require(native_requests==([request_observation] if request_observation else []),'Callback request '+label);require(result.called==int(request_observation is not None),'Called flag '+label)
                require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
                regs=result.registers;require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(regs.ax,regs.bx,regs.cx,regs.dx),'Register outputs '+label)
                require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==regs.interrupts_enabled and (uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==regs.direction,'IF/DF '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved/SI-DI restore '+label)
                require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4),'Outer farreturn '+label);require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp+4,2)))[0]==result.argument,'Mutated caller key argument '+label)
                wanted=[] if busy else [[1,0],[0,regs.interrupts_enabled]];require(active['guard_writes']==wanted,'Ordered original guard/IF '+label)
                coverage['busy' if busy else 'callback' if result.called else 'missing']+=1;coverage['extended' if key&255==0 else 'ascii']+=1;instructions+=active['instructions'];vectors+=1
    diagnostics=0
    for callback in [Callback(),Callback(lambda ctx,g,req,res:0)]:
        data=(C.c_uint8*65536).from_buffer_copy(baseline);data[0x6252]=0;r=Result();incoming=Registers();native(data,65536,1,0x16c9,C.byref(incoming),callback,None,C.byref(r));require(r.status==2 and data[0x6252]==1,'Native callback diagnostic');diagnostics+=1
    record={'schema':1,'function_id':'FN-EGA-000153','result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_key_dispatch.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete6528 dispatch control with all65536keywords, busy/clear guard, two loadbases andexplicit synthetic farcallback ABImocks. ActualPUSHsegment/nearCALL frame, SI/DI restore, argumentmask, group mutations andIF/DF compared. Callbackbodies/actualkeyinput/IRQ, alltablewriters, DS-changingcallback domains and game/fidelity remainopen; native callbackfault diagnostics outsideoriginal.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
