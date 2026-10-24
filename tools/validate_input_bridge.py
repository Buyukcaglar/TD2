"""Compare five input bridge bodies with explicit BIOS16 and dynamic far services."""
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
from validate_state_loop import Registers,StateRegisters,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['kind','site','segment','offset','stack_segment','stack_sp']]+[('incoming',StateRegisters)]


class Response(C.Structure):
    _fields_=[('returned',StateRegisters),('zero',C.c_uint16)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Response))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','return_bytes']]+[('calls',C.c_uint32),('returned',StateRegisters)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_input_bridge;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    entries=[0x69fe,0x6a03,0x6a17,0x6a28,0x6a3b];g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in g['functions'] if f['entry'] in ['06C9:'+f'{ip:04X}' for ip in entries]];require(len(fenced)==5,'Five entry fences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];coverage=Counter();vectors=instructions=0;sites=set();active={}
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def hook(cpu,address,size,_):
            if active.get('far') and address==active['far'][0]*16+active['far'][1]:
                segment,offset=active['far'];active['far']=None;sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+sp,4))==struct.pack('<2H',0x6a02,cs),'Dynamic far frame');active['pending']=(Request(1,0x69fe,segment,offset,active['ss'],sp,read_regs()),0x6a02,4);u.emu_stop();return
            require(address in starts,'Bridge escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address==cs*16+0x69fe:
                current=u.reg_read(UC_X86_REG_DS);offset,segment=struct.unpack('<2H',u.mem_read(current*16+0x64dc,4));active['far']=(segment,offset)
        def interrupt(cpu,number,_):
            require(number==0x16,'Only BIOS16 ABI');ret=u.reg_read(UC_X86_REG_IP);site=ret-2;sp=u.reg_read(UC_X86_REG_SP)-6;flags=u.reg_read(UC_X86_REG_EFLAGS);u.mem_write(active['ss']*16+sp,struct.pack('<3H',ret,cs,flags&65535));u.reg_write(UC_X86_REG_SP,sp);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300);active['pending']=(Request(0,site,0,0x16,active['ss'],sp,read_regs()),ret,6);u.emu_stop()
        u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=list(itertools.product(range(5),[0,1,0xff,0x100,0x1b00,0x7f00,0x8000,0xffff],[0,1,3],[0,1,2,3],[0,1]))
        cases += [(2,key,0,0,2) for key in [0,1,0x64dc,0xffff]]
        for entry,key,drain,profile,stackprofile in cases:
            ss=ds if stackprofile else 0x9000;sp=0x64d6 if stackprofile==2 else 0xe000;data=bytearray(base)
            for page in [ds,0x5000]:struct.pack_into('<2H',data,page*16+0x64dc,0x6a03 if profile&1 else 0x7654,cs if profile&1 else 0x6789)
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-16:ss*16+sp+12]=b'\xa5'*16+frame+struct.pack('<2H',key,key^0x5a5a)+b'\xa5'*4
            u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def model():return {'events':[],'consumed':0}
            def service(model,write,q):
                index=len(model['events'])+1;event=[q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry];response=Response(StateRegisters(Registers(*values(q.incoming.registers)),q.incoming.bp,q.incoming.carry),0);r=response.returned;rr=r.registers
                rr.ax=key;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.si=0xe000+index;rr.di=0xf000+index;rr.es=0x6000;r.bp=0x8000+index;r.carry=index&1;rr.interrupts_enabled=(profile>>1)&1;rr.direction=profile&1
                if profile==3:rr.ds=0x5000 if rr.ds==ds else ds
                if q.kind==0:
                    if q.site in [0x6a05,0x6a3d]:response.zero=int(model['consumed']>=drain)
                    else:model['consumed']+=1
                write(0x80000+index*2,struct.pack('<H',q.site));return event,response
            active.update(pending=None,far=None,ss=ss,instructions=0,sites=set(),model=model());u.emu_start(cs*16+entries[entry],0x11210,count=256)
            while active['pending']:
                q,ret,framebytes=active['pending'];active['pending']=None;require(len(active['model']['events'])<32,'Finite input fixture');event,response=service(active['model'],lambda at,b:u.mem_write(at,b),q);active['model']['events'].append(event);r=response.returned;rr=r.registers
                for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+framebytes),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10)|(response.zero<<6))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,0x11210,count=256)
            label=f'{load:x}/{entry}/{key}/{drain}/{profile}/{stackprofile}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original far return '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);native_model=model();errors=[]
            def callback(ctx,bus,q,r):
                try:event,response=service(native_model,lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q.contents);native_model['events'].append(event);C.memmove(r,C.byref(response),C.sizeof(response));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);out=Result();fn(gb,len(gb),load,ss,sp,entry,C.byref(incoming),cb,None,32,C.byref(out));require(not errors and out.status==0 and active['model']==native_model,'Native services '+label+str(errors));require(out.current_sp==sp+4 and out.return_bytes==4 and out.calls==len(native_model['events']),'Native stack/calls '+label)
            actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-16:ss*16+sp]=expected[ss*16+sp-16:ss*16+sp];require(actual==expected,'Full nonframe bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Returned registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,4))==frame,'Root far frame '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'{entries[entry]:04X}']+=1;coverage['service_calls']+=out.calls;coverage['setter_argument_alias']+=int(stackprofile==2)
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(r['id'] for r in registry if r['entries'][0].get('segment')==0x6c9 and r['entries'][0].get('segment_offset')==ip) for ip in entries];require(len(sites)==len(starts),'All input bridge locations exercised')
    result={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_bridge.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Five complete input bridge bodies, ordered farpointer publication/argument alias, dynamic far target, BIOS16ZF/CFIFDF/segments/register responses, ASCII/extended lowbyte behavior and finite drain compared. BIOS/far leaves are ABI mocks with synthetic interrupt frames, not actual installed handler or device. Dynamic target domain/lifetimes, IRQ/nesting, inputsession/core/game/fidelity pending. Native diagnostics separate.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['result','vectors','function_ids','instruction_sites_exercised','original_instructions_executed']},indent=2))


if __name__=='__main__':main()
