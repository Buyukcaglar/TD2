"""Compare ABFA raw BIOS10 block wrapper and far/interrupt frame conventions."""
import argparse
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['site','interrupt_number','stack_segment','stack_sp','saved_flags']]+[('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('current_sp',C.c_uint16),('calls',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_bios_block;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in g['functions'] if f['entry']=='06C9:ABFA');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();sp=0xe000
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for ip in f['instructions']}
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):require(address in starts,'ABFA escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(cpu,num,_):
            require(num==0x10,'Only BIOS10');ret=u.reg_read(UC_X86_REG_IP);flags=u.reg_read(UC_X86_REG_EFLAGS);current=u.reg_read(UC_X86_REG_SP)-6;u.mem_write(active['ss']*16+current,struct.pack('<3H',ret,cs,flags&65535));u.reg_write(UC_X86_REG_SP,current);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300);active['pending']=Request(0xac08,0x10,active['ss'],current,flags&0x603,read_regs());u.emu_stop()
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for pointer,flags,profile,same in itertools.product([0,1,0x2e08,0x2e10,0x7fff,0x8000,0xfffe,0xffff],[2,3,0x202,0x203,0x402,0x403,0x602,0x603],range(4),[0,1]):
            ss=ds if same else 0x9000;data=bytearray(base);frame=struct.pack('<3H',0x100,0x1111,pointer);data[ss*16+sp-16:ss*16+sp+10]=b'\xa5'*16+frame+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xabfa),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def service(write,q):
                event=[q.site,q.interrupt_number,q.stack_segment,q.stack_sp,q.saved_flags,values(q.incoming.registers),q.incoming.bp,q.incoming.carry];returned=StateRegisters(Registers(*values(q.incoming.registers)),q.incoming.bp,q.incoming.carry);r=returned.registers;r.interrupts_enabled=(q.saved_flags>>9)&1
                if profile&1:
                    r.ax=0x1234;r.bx=0x2345;r.cx=0x3456;r.dx=0x4567;r.si=0x5678;r.di=0x6789;r.ds=0x5000;r.es=0x6000;returned.bp=0xffff;returned.carry=1-returned.carry;r.interrupts_enabled=1-r.interrupts_enabled;r.direction=1-r.direction
                if profile>=2:write(((q.incoming.registers.es<<4)+q.incoming.registers.dx)&0xfffff,b'\x5a')
                return event,returned
            active.update(ss=ss,pending=None,instructions=0,sites=set());u.emu_start(cs*16+0xabfa,0x11210,count=32);require(active['pending'] is not None,'BIOS request');q=active['pending'];event,returned=service(lambda at,b:u.mem_write(at,b),q);r=returned.registers
            for reg,val in list(zip(regs,values(r)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_SP,q.stack_sp+6),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xac0a),(UC_X86_REG_EFLAGS,2|returned.carry|(r.interrupts_enabled<<9)|(r.direction<<10))]:u.reg_write(reg,val)
            u.emu_start(cs*16+0xac0a,0x11210,count=32);label=f'{load:x}/{pointer:x}/{flags:x}/{profile}/{same}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'OriginalRETf '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,bus,q,r):
                try:
                    require(r.contents.registers.interrupts_enabled==((q.contents.saved_flags>>9)&1),'Response initializedpreINT');ev,ret=service(lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q.contents);events.append(ev);C.memmove(r,C.byref(ret),C.sizeof(ret));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);out=Result();fn(gb,len(gb),ss,sp,C.byref(incoming),cb,None,1,C.byref(out));require(not errors and out.status==0 and out.calls==1 and out.current_sp==sp+4 and events==[event],'Native BIOS/interface '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-16:ss*16+sp]=expected[ss*16+sp-16:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp==incoming.bp,'Registers/BPrestore '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,10))==frame+b'\xa5'*4,'Frame/argguard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
    require(len(sites)==len(starts),'All ABFA sites');record={'schema':1,'result':'pass','function_id':'FN-EGA-000236','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_bios_block.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'limits':'CompleteABFA raw BIOS10AX1002/ESincomingDS/DXnearSSargument, sixbyteinterrupt/farreturn frames, BP restoration and explicit returnedCFIFDF/registers compared. BIOSbody ABI mock; no assignedblock extent/decodedpalette/text semantics, actualBIOS/device/rendering/IRQ/core/game/fidelity. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed']},indent=2))


if __name__=='__main__':main()
