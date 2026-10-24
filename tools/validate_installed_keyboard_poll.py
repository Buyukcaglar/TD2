"""Compose65C5/6601 with actual69B7 and recovered native BIOS/input code.

Synthetic interrupts/frames only; no device, real IRQ or callback body executes.
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
from validate_input_poll import Registers,Result,BiosService,Services
from validate_key_dispatch import Callback
from validate_gameport import Service as PortService
from validate_keyboard import Registers as KeyboardRegisters,Result as KeyboardResult,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input-library',type=Path,required=True);ap.add_argument('--keyboard-library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();libraries=[a.input_library.resolve(),a.keyboard_library.resolve()];output=a.output.resolve();require(all(p.is_relative_to(ROOT/'analysis') for p in libraries) and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private libraries/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    inputs=C.CDLL(str(libraries[0]));functions={'poll':inputs.td2ega_input_poll,'consume':inputs.td2ega_input_consume_if_stack_group}
    for fn in functions.values():fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Services),C.POINTER(Registers),C.POINTER(Result)];fn.restype=None
    bios=C.CDLL(str(libraries[1])).td2ega_keyboard_bios;bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(KeyboardRegisters),C.c_uint16,C.c_uint16,C.POINTER(KeyboardResult)];bios.restype=None
    cases=[]
    for kind in ['poll','consume']:
        for pending in [0,1,0xa,0x1b,0x80,0x100,0x8000,0x8400,0x8500,0xffff,0x8001,0x4200,0x013a]:
            for same in [0,1]:
                for busy in [0,1]:
                    for flags in [2,0x202,0x402,0x602]:cases.append((kind,pending,same,busy,flags,'installed_handler_guards'))
        for pending in sorted(set(range(256))|{i<<8 for i in range(256)}):cases.append((kind,pending,1,0,2,'all_pending_byte_domains'))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries={'06C9:65C5','06C9:6601','06C9:6528','06C9:6686','06C9:69B7'};fenced=[f for f in graph['functions'] if f['entry'] in entries];require(len(fenced)==len(entries),'Installedcomposition fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX];vectors=instructions=0;coverage=Counter();active={};sp=0xe000
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        uc.mem_write(load*16,bytes(relocated));starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def fetch(u,address,size,_):require(address in starts,'Installedkeyboard composition escaped');active['instructions']+=1
        def interrupt(u,num,_):
            require(num==0x16,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);flags=u.reg_read(UC_X86_REG_EFLAGS);current_sp=u.reg_read(UC_X86_REG_SP);return_ip=u.reg_read(UC_X86_REG_IP);active['events'].append([ax>>8,ax,(flags>>9)&1,(flags>>10)&1]);frame=struct.pack('<3H',return_ip,cs,flags&65535);u.mem_write(active['ss']*16+current_sp-6,frame);require(bytes(u.mem_read(active['ss']*16+current_sp-6,6))==frame,'INT16 sixbyteframe');u.reg_write(UC_X86_REG_SP,current_sp-6);u.reg_write(UC_X86_REG_CS,cs);u.reg_write(UC_X86_REG_IP,0x69b7);u.reg_write(UC_X86_REG_EFLAGS,flags&~0x300);active['pending']=True;u.emu_stop()
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for kind,pending,same,busy,flags,category in cases:
            ss=ds if same else 0x9000;data=bytearray(65536);struct.pack_into('<H',data,0x62b6,pending);data[0x6252]=busy;data[0x6cfc]=0;data[0x6cfe]=1;struct.pack_into('<H',data,0x6254,0x1234);struct.pack_into('<H',data,0x6274,0x1234);uc.mem_write(ds*16,bytes(data));frame=b'\xa5'*64+struct.pack('<2H',0x400,0xa000)+b'\xa5'*4;uc.mem_write(ss*16+sp-64,frame)
            if same:data[sp-64:sp+8]=frame
            incoming=Registers(0xa55a,0x1234,0x4567,0x7654,(flags>>9)&1,(flags>>10)&1);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_ES,0x5432),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_BP,0x5678)];entry=0x65c5 if kind=='poll' else 0x6601
            for reg,val in preserved+list(zip(regids,[incoming.ax,incoming.bx,incoming.cx,incoming.dx]))+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(events=[],instructions=0,pending=False,ss=ss);uc.emu_start(cs*16+entry,0xa0400,count=512)
            while active['pending']:active['pending']=False;uc.emu_start(cs*16+0x69b7,0xa0400,count=512)
            label=f'{load:x}/{kind}/{pending:x}/{same}/{busy}/{flags:x}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4),'Composed farreturn '+label)
            gb=(C.c_uint8*65536).from_buffer_copy(data);bus=(C.c_uint8*0x100000)();events=[];errors=[]
            def bios_cb(ctx,qptr,rptr):
                try:
                    q=qptr.contents;events.append([q.operation,q.ax,q.interrupts_enabled,q.direction]);C.memmove(C.byref(bus,ds*16),gb,65536);registers=KeyboardRegisters(q.ax,0,0,0,0,0,ds,0,q.interrupts_enabled,q.direction);entry_flags=2|(q.interrupts_enabled<<9)|(q.direction<<10);result=KeyboardResult();bios(bus,len(bus),load,C.byref(registers),entry_flags,entry_flags,C.byref(result));require(result.status==0,'NativeinstalledBIOS');C.memmove(gb,C.byref(bus,ds*16),65536);rptr.contents.ax=result.registers.ax;rptr.contents.zero=(result.return_flags>>6)&1;rptr.contents.interrupts_enabled=result.registers.interrupts_enabled;rptr.contents.direction=result.registers.direction;return 1
                except Exception as e:errors.append(str(e));return 0
            def reject_port(*_):errors.append('Disabledgameport mustnotrequestports');return 0
            def reject_callback(*_):errors.append('Zerocallbacktable mustnotdispatchbody');return 0
            bs,ps,ks=BiosService(bios_cb),PortService(reject_port),Callback(reject_callback);services=Services(cs,ds,ss,32,bs,None,ps,None,ks,None);result=Result();functions[kind](gb,len(gb),C.byref(services),C.byref(incoming),C.byref(result));require(not errors and result.status==0 and events==active['events'],'NativeinstalledBIOS composition '+label+str(errors));actual=bytearray(uc.mem_read(ds*16,65536));expected=bytearray(gb)
            if same:actual[sp-64:sp+8]=expected[sp-64:sp+8]
            require(actual==expected,'Sharedgroup '+label);r=result.registers;require([uc.reg_read(reg) for reg in regids]==[r.ax,r.bx,r.cx,r.dx],'Registers '+label);require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'InstalledIFDF '+label);require(r.interrupts_enabled==1,'ActualAH1IF1 propagated '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preservedregisters '+label);require(bytes(uc.mem_read(ss*16+sp,8))==struct.pack('<2H',0x400,0xa000)+b'\xa5'*4,'Rootfarframe '+label);coverage[category]+=1;coverage[kind]+=1;coverage['same_DS_SS_'+str(bool(same))]+=1;instructions+=active['instructions'];vectors+=1
    deps=['tools/validate_input_poll.py','tools/validate_keyboard.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':sha,'native_libraries':[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in libraries],'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual65C5/6601 +69B7 instructioncomposition, syntheticINT16 frames, nativeinputpoll+nativekeyboardBIOSadapter; noBIOSreturnvaluemocks. ActualAH1IF1, zero/nonzeropending, DS=SS consumptiongate, busy/missingcallback/disabledgameport. BIOSoutputsconsumedbywrappers compared; incidentalAH0flags outsideAPIprofile. SSframearea separate, no actualkeyboard/BIOS/IRQ/inputsession/callbackbody/core/resource/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
