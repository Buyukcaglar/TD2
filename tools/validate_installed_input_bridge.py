"""Compose input bridge with actual installed69B7 and native keyboard code."""
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
from validate_input_bridge import Registers,StateRegisters,Request,Response,Service,Result,require,values
from validate_keyboard import Registers as KeyboardRegisters,Result as KeyboardResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bridge-library',type=Path,required=True);p.add_argument('--keyboard-library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();libraries=[a.bridge_library.resolve(),a.keyboard_library.resolve()];out=a.output.resolve();require(all(x.is_relative_to(ROOT/'analysis') for x in libraries) and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    bridge=C.CDLL(str(libraries[0])).td2ega_input_bridge;bridge.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bridge.restype=None
    bios=C.CDLL(str(libraries[1])).td2ega_keyboard_bios;bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(KeyboardRegisters),C.c_uint16,C.c_uint16,C.POINTER(KeyboardResult)];bios.restype=None
    g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());wanted=['06C9:'+x for x in ['69FE','6A03','6A3B','69B7']];fenced=[f for f in g['functions'] if f['entry'] in wanted];require(len(fenced)==4,'Four composed fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;coverage=Counter();sp=0xe000
    cases=list(itertools.product([0,1,4],[0,1,0xff,0x100,0x1b00,0x7f00,0x8000,0xffff],[2,0x203,0x402,0x603],[0,1]))
    cases += [(entry,key,2,1) for entry,key in itertools.product([0,1,4],sorted(set(range(256))|{i<<8 for i in range(256)}))]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def code(cpu,address,size,_):
            require(address in starts,'Installed bridge escaped');active['instructions']+=1
        def interrupt(cpu,num,_):
            require(num==0x16,'Only INT16');flags=u.reg_read(UC_X86_REG_EFLAGS);ret=u.reg_read(UC_X86_REG_IP);current_sp=u.reg_read(UC_X86_REG_SP);active['events'].append([ret-2,u.reg_read(UC_X86_REG_AX),flags&1,(flags>>9)&1,(flags>>10)&1,current_sp-6]);u.mem_write(active['ss']*16+current_sp-6,struct.pack('<3H',ret,cs,flags&65535));u.reg_write(UC_X86_REG_SP,current_sp-6);u.reg_write(UC_X86_REG_IP,0x69b7);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300);active['pending']=True;u.emu_stop()
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,key,flags,same in cases:
            ss=ds if same else 0x9000;data=bytearray(base);struct.pack_into('<H',data,ds*16+0x62b6,key);struct.pack_into('<2H',data,ds*16+0x64dc,0x6a03,cs);frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-32:ss*16+sp+8]=b'\xa5'*32+frame+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regids,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,{0:0x69fe,1:0x6a03,4:0x6a3b}[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            active.update(pending=False,ss=ss,events=[],instructions=0);u.emu_start(cs*16+{0:0x69fe,1:0x6a03,4:0x6a3b}[entry],0x11210,count=512)
            while active['pending']:active['pending']=False;u.emu_start(cs*16+0x69b7,0x11210,count=512)
            label=f'{load:x}/{entry}/{key:x}/{flags:x}/{same}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Composed return '+label)
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];saved_flags=[flags]
            def callback(ctx,m,qptr,rptr):
                try:
                    q=qptr.contents
                    if q.kind==1:
                        require((q.segment,q.offset)==(cs,0x6a03),'Observed installed poll target');nested=Result();bridge(bus,len(bus),load,ss,q.stack_sp,1,C.byref(q.incoming),cb,None,16,C.byref(nested));require(nested.status==0,'Native nested poll');C.memmove(C.byref(rptr.contents.returned),C.byref(nested.returned),C.sizeof(StateRegisters));return 1
                    events.append([q.site,q.incoming.registers.ax,saved_flags[0]&1,(saved_flags[0]>>9)&1,(saved_flags[0]>>10)&1,q.stack_sp]);incoming_bios=KeyboardRegisters(*values(q.incoming.registers));result=KeyboardResult();bios(bus,len(bus),load,C.byref(incoming_bios),saved_flags[0]&~0x300,saved_flags[0],C.byref(result));require(result.status==0,'Native69B7');rptr.contents.returned=StateRegisters(result.registers,q.incoming.bp,result.return_flags&1);rptr.contents.zero=(result.return_flags>>6)&1;saved_flags[0]=result.return_flags;return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);result=Result();bridge(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,16,C.byref(result));require(not errors and result.status==0,'Native installed composition '+label+str(errors));require(events==active['events'],'Exact BIOS flags/stack/event sequence '+label)
            actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=result.returned;require([u.reg_read(reg) for reg in regids]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'Actual IFDFCF '+label);require(r.registers.interrupts_enabled==1,'AH1 forcesIF1');coverage[str(entry)]+=1;coverage['same_DS_SS_'+str(same)]+=1;instructions+=active['instructions'];vectors+=1
    record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':sha,'native_libraries':[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in libraries],'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_input_bridge.py','tools/validate_keyboard.py']],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual69FE->6A03 and6A03/6A3B plusinstalled69B7 instructions compared withnativeinputbridge+keyboard, syntheticINT16 frames/initialpendingword. NoBIOSreturnvaluemock. Observedtarget6A03only, CFIFDF/AXextendednormalization andpendingconsumption retained. No actualBIOS/device/IRQ/asynchronousinput/completecallbackdomain/core/game/fidelity acceptance; separate fromhelpervector totals.'}
    out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed']},indent=2))


if __name__=='__main__':main()
