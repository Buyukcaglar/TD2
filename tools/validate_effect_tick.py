"""Compare6269 effect bytecode/counters/queued pointers and port requests."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_music_tick import Registers,Port,Result,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_effect_tick;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Port,C.c_void_p,C.c_uint32,C.POINTER(Result)];native.restype=None
    cases=[];boundary=[0,1,2,3,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xfffe,0xffff]
    for mode,remaining,threshold in itertools.product([0,1,2,3,255],boundary,boundary):cases.append(('entry_counter_profiles',{'mode':mode,'remaining':remaining,'threshold':threshold}))
    for note in range(256):
        for count in [0,1,0x7fff,0x8000,0xffff]:cases.append(('all_event_bytes',{'note':note,'count':count,'loop_count':count}))
    for shift in range(256):
        for duration in boundary:cases.append(('all_shift_bytes',{'shift':shift,'duration':duration}))
    for command,count in itertools.product(range(0xf5,0x100),boundary):cases.append(('loop_signed_boundaries',{'note':command,'loop_count':count,'count':count}))
    for event in [0,1,0xfffc,0xfffd,0xfffe,0xffff]:
        for note in [0,65,0xff]:cases.append(('effective_offset_wrap',{'event':event,'note':note}))
    for queued in [0,1,255]:
        for absent in [0,1]:cases.append(('queued_pointer_transfer',{'queued':queued,'absent':absent,'note':0xff}))
    for event in [0x5ef6,0x5ef8,0x5efa,0x5f00,0x5f2e]:cases.append(('source_group_alias',{'shared':True,'event':event,'note':0 if event==0x5ef6 else 65}))
    rng=random.Random(0x6269)
    for _ in range(2048):cases.append(('varied_finite_states',{'mode':rng.randrange(256),'remaining':rng.randrange(65536),'threshold':rng.randrange(65536),'shift':rng.randrange(256),'note':rng.randrange(256),'loop_count':rng.randrange(65536),'duration':rng.randrange(65536),'count':rng.randrange(65536),'queued':rng.randrange(2),'absent':rng.randrange(2)}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in graph['functions'] if f['entry']=='06C9:6269');coverage=Counter();vectors=instructions=0;sites=set();active={};regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
    for load in [0x1000,0x2345]:
        cs,ds,ss,sp=load+0x6c9,load+0x178f,0x9000,0x8000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);base=bytearray(0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base[load*16:load*16+len(relocated)]=relocated;starts={cs*16+ip for ip in f['instructions']}
        def fetch(u,address,size,_):require(address in starts,'Effect escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def service(events,operation,port,value,enabled):
            require(port in [0x61,0x42] and (operation==1 or port==0x61),'Port domain')
            if operation==0:value=[0xa5,0xfe,1,0x83][len(events)%4]
            events.append([operation,port,value,enabled]);return value
        def port_in(u,p,size,_):require(size==1,'Read width');return service(active['ports'],0,p,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,p,size,value,_):require(size==1,'Write width');service(active['ports'],1,p,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for category,c in cases:
            data=bytearray(base);segment=ds if c.get('shared') else 0x6000;event=c.get('event',0x1000);note=c.get('note',65)
            def put(at,value):struct.pack_into('<H',data,ds*16+at,value&65535)
            for at,value in [(0x5eee,0 if c.get('absent') else segment),(0x5ef0,event),(0x5ef2,0x7000),(0x5ef4,0x2000),(0x5ef6,c.get('remaining',0)),(0x5ef8,c.get('threshold',0)),(0x5f00,c.get('loop_count',0)),(0x5f02,c.get('loop_count',0)),(0x5f04,c.get('loop_count',0)),(0x5f06,0x2000),(0x5f08,0x2000),(0x5f0a,0x2000),(0x5f0c,0x2000),(0x5f0e,0x2000),(0x5f10,0x2000)]:put(at,value)
            for i in range(128):put(0x5f2e+i*2,i*317+11)
            data[ds*16+0x5efb]=c.get('mode',3);data[ds*16+0x5efc]=1;data[ds*16+0x5efd]=c.get('queued',0);data[ds*16+0x5efa]=c.get('shift',1)
            if 0xfb<=note<=0xfd:stream=bytes([note])+struct.pack('<H',c.get('count',0))+bytes([65,2,0])
            elif note==0xfe:stream=bytes([note,c.get('count',0)&255,65,2,0])
            elif note>=0xf5 and note<=0xfa:stream=bytes([note,65,2,0])
            else:stream=bytes([note])+struct.pack('<H',c.get('duration',2))
            for i,b in enumerate(stream):data[segment*16+((event+i)&65535)]=b
            for source in [segment,0x7000]:data[source*16+0x2000:source*16+0x2003]=bytes([65,2,0])
            # Shared fixtures restore entry controls, retaining aliases in
            # event operands and the subsequent read/write order.
            if c.get('shared'):
                put(0x5eee,segment);put(0x5ef0,event);put(0x5ef6,0);data[ds*16+0x5efb]=3;data[ds*16+0x5efd]=0
            data[ss*16+sp-4:ss*16+sp+8]=b'\xa5'*4+struct.pack('<2H',0x100,0x1111)+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);incoming=Registers(0xa55a,0xa534,0x4567,0x7654,0x3456,0x2345,ds,0x4321,(flags>>9)&1,(flags>>10)&1)
            for reg,value in list(zip(regids,[incoming.ax,incoming.bx,incoming.cx,incoming.dx,incoming.si,incoming.di,incoming.ds,incoming.es]))+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6269),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x5678),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,value)
            active.update(ports=[],instructions=0,sites=set());uc.emu_start(cs*16+0x6269,0x11210,count=20000);label=f'{load:x}/{category}/{c}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original far return '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,qptr,vptr):
                try:q=qptr.contents;vptr.contents.value=service(events,q.operation,q.port,q.value if q.operation else 0,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Port(callback);result=Result();native(gb,len(data),load,C.byref(incoming),cb,None,128,C.byref(result));require(not errors and result.status==0,'Native finite completion '+label+str(errors));require(events==active['ports'],'Ordered ports '+label);require(bytes(gb)==bytes(uc.mem_read(0,len(data))),'Full bus '+label)
            r=result.registers;require([uc.reg_read(reg) for reg in regids]==[r.ax,r.bx,r.cx,r.dx,r.si,r.di,r.ds,r.es],'Register effects '+label);require(uc.reg_read(UC_X86_REG_BP)==0x5678 and uc.reg_read(UC_X86_REG_SS)==ss,'BP/SS '+label);require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'IF/DF '+label)
            require(bytes(uc.mem_read(ss*16+sp-4,12))==data[ss*16+sp-4:ss*16+sp+8],'Far frame/guards '+label);sites.update(active['sites']);instructions+=active['instructions'];coverage[category]+=1;vectors+=1
    record={'schema':1,'function_id':'FN-EGA-000403','result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_effect_tick.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(f['instructions']),'limits':'Serialized6269 syntheticfullbus/finiteeventprofiles with11commandtargets, threeJSloopcounters, queuedpointer transfers, source/groupaliases, ordinaryword/effectiveoffsetwrap, maskedshift andtypedports. Fullbus/register/IF/DF/farframe compared. No actualsourcecorpus/PIT/speaker/IRQ/timebase/audio/game/fidelity. Nonreturning profiles/nativebudget/adapterdiagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
