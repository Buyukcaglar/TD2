"""Compare keyboard install/restore/IRQ09/INT16 including RETF2 query flags."""
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
from validate_music_tick import Registers,Port,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','return_flags','flags_mask']]+[('registers',Registers)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));install=dll.td2ega_keyboard_install;install.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Port,C.c_void_p,C.POINTER(Result)];restore=dll.td2ega_keyboard_restore;restore.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Registers),Port,C.c_void_p,C.POINTER(Result)];irq=dll.td2ega_keyboard_irq;irq.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,Port,C.c_void_p,C.POINTER(Result)];bios=dll.td2ega_keyboard_bios;bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint16,C.POINTER(Result)]
    for fn in [install,restore,irq,bios]:fn.restype=None
    cases=[];boundary=[0,1,2,0x7f,0x80,0xff,0x7fff,0x8000,0xfffe,0xffff]
    for scan,modifiers in itertools.product(range(256),range(32)):cases.append(('irq','all_scans_modifiers',{'scan':scan,'modifiers':modifiers,'mapping':(scan*3+modifiers*5)&255}))
    for mapping,row in itertools.product(range(256),range(5)):cases.append(('irq','all_translated_bytes',{'scan':1,'modifiers':[0,4,16,2,1][row],'mapping':mapping,'constant_mapping':True}))
    for ah,pending in itertools.product(range(256),boundary):cases.append(('bios','all_BIOS_operations',{'ah':ah,'pending':pending,'left':ah,'right':pending&255}))
    for low,high,flags in itertools.product(range(256),[0,0x7f,0x80,0xff],[2,0x247,0x6d7,0xed7]):cases.append(('bios','query_logic_flags',{'ah':1,'pending':low|(high<<8),'flags':flags}))
    for left,right in itertools.product(range(256),[0,1,0x80,0xff]):cases.append(('bios','shift_byte_OR',{'ah':2,'left':left,'right':right}))
    for mask,vector in itertools.product(range(256),range(4)):cases.append(('install','all_PIC_masks_vector_guards',{'mask':mask,'vector':vector}))
    for mask,old in itertools.product(range(256),[0,1,0x6907,0xffff]):cases.append(('restore','all_PIC_masks_restore_guards',{'mask':mask,'old':old}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries={'install':0x6860,'restore':0x68c4,'irq':0x6907,'bios':0x69b7};fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{ip:04X}' for ip in entries.values()]];require(len(fenced)==4,'Four keyboard fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];coverage=Counter();vectors=instructions=0;sites=set();active={};group=bytes((i*37+11)&255 for i in range(65536))
    for load in [0x1000,0x2345]:
        cs,ds,ss,sp=load+0x6c9,load+0x178f,0x9000,0x8000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);base=bytearray(0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=group;base[0x50000:0x60000]=group;starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def fetch(u,address,size,_):require(address in starts,'Keyboard escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def service(events,operation,port,value,enabled):
            require((operation,port) in [(0,0x21),(1,0x21),(0,0x60),(0,0x61),(1,0x61),(1,0x20)],'Keyboard port domain')
            if operation==0:value={0x21:active['mask'],0x60:active['scan'],0x61:active['latch']}[port]
            events.append([operation,port,value,enabled]);return value
        def port_in(u,p,size,_):require(size==1,'Read width');return service(active['events'],0,p,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,p,size,value,_):require(size==1,'Write width');service(active['events'],1,p,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for kind,category,c in cases:
            data=bytearray(base);flags=c.get('flags',[2,0x247,0x6d7,0xed7][vectors%4]);irqflags=[0x247,2,0xed7,0x6d7][vectors%4];incomingds=ds if kind=='bios' else 0x5000;incomingds=ds if kind in ['install','restore'] and c.get('mask',0)&1 else incomingds
            if kind=='irq':
                modifiers=c['modifiers'];mapping=c['mapping']
                for row,at in enumerate([0x6314,0x636f,0x63ca,0x6425,0x6480]):data[ds*16+at:ds*16+at+90]=bytes((mapping if c.get('constant_mapping') else mapping+i*17+row*37)&255 for i in range(90))
                for i,at in enumerate([0x62f2,0x62d7,0x62e4,0x62f0,0x62f4]):data[ds*16+at]=1 if modifiers&(1<<i) else 0xfe
            elif kind=='bios':
                struct.pack_into('<H',data,ds*16+0x62b6,c.get('pending',0));data[ds*16+0x62e4]=c.get('left',0);data[ds*16+0x62f0]=c.get('right',0)
            elif kind=='install':
                vector=c['vector'];struct.pack_into('<2H',data,0x24,0x6907 if vector in [1,2] else [0,0,0,0xffff][vector],cs if vector==1 else 0x4321);struct.pack_into('<2H',data,0x58,0x1234,0x5678)
            else:
                struct.pack_into('<4H',data,incomingds*16+0x62ae,c['old'],0x1234,0x5678,0x9abc);data[0x417]=c['mask']^0x55
            framed=kind in ['irq','bios'];frame=struct.pack('<3H',0x100,0x1111,irqflags) if framed else struct.pack('<2H',0x100,0x1111);data[ss*16+sp-16:ss*16+sp+len(frame)+4]=b'\xa5'*16+frame+b'\xa5'*4;uc.mem_write(0,bytes(data));incoming=Registers((c.get('ah',0xa5)<<8)|0x5a,0xb123,0xc456,0xd789,0x3456,0x2345,incomingds,0x5432,(flags>>9)&1,(flags>>10)&1)
            for reg,val in list(zip(regids,values(incoming)[:8]))+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[kind]),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(events=[],instructions=0,sites=set(),scan=c.get('scan',0),mask=c.get('mask',0x55),latch=(vectors*13)&255);uc.emu_start(cs*16+entries[kind],0x11210,count=256);label=f'{load:x}/{kind}/{category}/{c}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+(6 if framed else 4)),'Original return/cleanup '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,qptr,vptr):
                try:q=qptr.contents;vptr.contents.value=service(events,q.operation,q.port,q.value if q.operation else 0,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Port(callback);result=Result()
            if kind=='install':install(gb,len(data),cs,C.byref(incoming),cb,None,C.byref(result))
            elif kind=='restore':restore(gb,len(data),C.byref(incoming),cb,None,C.byref(result))
            elif kind=='irq':irq(gb,len(data),load,C.byref(incoming),irqflags,cb,None,C.byref(result))
            else:bios(gb,len(data),load,C.byref(incoming),flags,irqflags,C.byref(result))
            require(not errors and result.status==0 and events==active['events'],'Native port/API '+label+str(errors));actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-16:ss*16+sp]=expected[ss*16+sp-16:ss*16+sp];require(actual==expected,'Full nonstack bus '+label)
            r=result.registers;require([uc.reg_read(reg) for reg in regids]==values(r)[:8],'Registers '+label);require(uc.reg_read(UC_X86_REG_BP)==0x5678 and uc.reg_read(UC_X86_REG_SS)==ss,'BP/SS '+label);require(uc.reg_read(UC_X86_REG_EFLAGS)&result.flags_mask==result.return_flags&result.flags_mask,'Defined flags/IRETvsRETF2 '+label);require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'IF/DF '+label);require(bytes(uc.mem_read(ss*16+sp,len(frame)+4))==frame+b'\xa5'*4,'Returnframe/upperguard '+label)
            if kind=='irq':require(bytes(uc.mem_read(ss*16+sp-10,10))==struct.pack('<5H',incoming.ds,incoming.dx,incoming.cx,incoming.bx,incoming.ax),'IRQsavedregisters '+label)
            elif kind=='bios':require(bytes(uc.mem_read(ss*16+sp-4,4))==struct.pack('<2H',incoming.ds,incoming.bx),'BIOSsavedregisters '+label)
            elif kind=='install':require(bytes(uc.mem_read(ss*16+sp-2,2))==struct.pack('<H',incoming.di),'Install savedDI '+label)
            else:require(bytes(uc.mem_read(ss*16+sp-16,16))==b'\xa5'*16,'Restorelowerguard '+label)
            coverage[category]+=1;instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
    record={'schema':1,'function_ids':[f'FN-EGA-{i:06}' for i in range(157,161)],'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_keyboard.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':sum(len(f['instructions']) for f in fenced),'limits':'Four serializedkeyboard install/restore/IRQ09/INT16 entries, syntheticfullbus andtypedports. Allscancodes/modifierpriorities/translatedbytes/PICmasks/BIOSAH, pendingword/logicflag boundaries, offsetonlyvector guard andconditionalBIOS417clear. ActualIRET vsAH1RETF2 flags/cleanup/frames checked; AFundefined onORquery excluded. No actualkeyboard/PIC/BIOS/IRQ/nesting/inputsession/callbackdispatch/game/fidelity. Nativeargument/adapterdiagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
