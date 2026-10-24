"""Compare75EA command/state/source/port effects using synthetic memory only."""
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
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *


def require(test,message):
    if not test:raise RuntimeError(message)


class Registers(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['ax','bx','cx','dx','si','di','ds','es','interrupts_enabled','direction']]


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['operation','port','value','interrupts_enabled']]


Port=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Request),C.POINTER(C.c_uint8))


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('steps',C.c_uint32),('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_music_tick;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Port,C.c_void_p,C.c_uint32,C.POINTER(Result)];native.restype=None
    # Each case starts with explicit finite source records and stable code.
    cases=[]
    for mode,start,active in itertools.product([0,1,2,3,4,255],[0,1,255],[0,1,255]):cases.append(('entry_gates',{'mode':mode,'start':start,'active':active}))
    for note in range(256):
        for duration in [0,1,2,127,128,255]:cases.append(('all_note_bytes',{'note':note,'duration':duration}))
    boundary=[0,1,2,3,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xfffe,0xffff]
    for on,rest,phase,delay in itertools.product(boundary,[0,1,2,0xffff],[0,1,2],[0,1,0xffff]):cases.append(('counter_boundaries',{'start':0,'active':1,'on':on,'rest':rest,'phase':phase,'delay':delay}))
    for command in range(0xfb,0x100):
        for operand in range(256):cases.append(('all_command_operands',{'commands':bytes([command,operand]),'note':65,'duration':2}))
    for shift in range(256):
        for duration in [1,0x7f,0x80,0xff]:cases.append(('masked_shift_counts',{'shift':shift,'duration':duration,'note':0x7f}))
    for minimum,maximum,delta,current,direction,limitmode in itertools.product([0,0x8000],[0x7fff,0xffff],[0,1,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],[1,255],[0,1]):
        # Bouncing when both directions exceed the bounds can be nonterminating;
        # give those cases a one-way reset instead, and test diagnostics separately.
        if limitmode==0 and minimum==0 and maximum==0xffff:continue
        cases.append(('pitch_signed_boundaries',{'start':0,'active':1,'on':3,'delay':0,'minimum':minimum,'maximum':maximum,'delta':delta,'current':current,'direction':direction,'limitmode':limitmode}))
    for source in [0,0x65f0,0x6607,0x6608,0x6609,0x660a,0x660b,0x6610,0xffe5,0xfffe,0xffff]:
        cases.append(('voice_group_alias_copy',{'commands':bytes([0xfd,0]),'voice_group':True,'voice_offset':source}))
    for song,event in itertools.product([1,0x7fe,0xfffe,0xffff],[1,0x1000,0xfffe,0xffff]):
        if {(song+i)&65535 for i in range(3)} & {(event+i)&65535 for i in range(4)}:continue
        cases.append(('source_offset_wrap',{'song_offset':song,'event_offset':event,'note':0xfb,'duration':0}))
    rng=random.Random(0x75ea)
    for _ in range(2048):cases.append(('varied_finite_states',{'note':rng.randrange(128),'duration':rng.randrange(256),'shift':rng.randrange(256),'transpose':rng.randrange(65536),'on':rng.choice(boundary),'rest':rng.choice(boundary),'phase':rng.choice(boundary),'delay':rng.choice(boundary),'start':rng.randrange(2),'active':rng.randrange(2),'delta':rng.randrange(65536),'current':rng.randrange(65536),'minimum':0x8000,'maximum':0x7fff,'direction':rng.choice([1,255]),'limitmode':1}))
    vectors=instructions=0;coverage=Counter();active={};regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());function=next(f for f in graph['functions'] if f['entry']=='06C9:75EA')
    for load in [0x1000,0x2345]:
        cs,ds,ss,sp=load+0x6c9,load+0x178f,0x9000,0x8000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);base=bytearray(0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base[load*16:load*16+len(relocated)]=relocated;starts={cs*16+ip for ip in function['instructions']}
        def fetch(u,address,size,_):require(address in starts,'Music escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def service(events,operation,port,value,enabled):
            require(port in [0x61,0x42] and (operation==1 or port==0x61),'Port domain')
            if operation==0:value=[0xa5,0xfe,1,0x83][len(events)%4]
            events.append([operation,port,value,enabled]);return value
        def port_in(u,p,size,_):require(size==1,'Read width');return service(active['ports'],0,p,0,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(u,p,size,value,_):require(size==1,'Write width');service(active['ports'],1,p,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        sites=set()
        for category,c in cases:
            data=bytearray(base);songseg,voiceseg=0x6000,ds if c.get('voice_group') else 0x7000;song=c.get('song_offset',0x800);event=c.get('event_offset',0x1000);voice=c.get('voice_offset',0x100)
            def put(at,v):struct.pack_into('<H',data,ds*16+at,v&65535)
            for at,v in [(0x65d3,3),(0x65d5,c.get('transpose',0)),(0x65d9,0),(0x65ed,song),(0x65ef,0x1234),(0x65f1,0),(0x65f5,songseg),(0x65f7,voiceseg),(0x65f9,voice),(0x65e9,event),(0x65e1,c.get('on',3)),(0x65e5,c.get('rest',2)),(0x65ff,c.get('phase',1)),(0x6601,0xffff),(0x6603,c.get('delay',1)),(0x6607,c.get('current',0)),(0x6609,c.get('shift',1)),(0x660b,2),(0x660d,3),(0x660f,7),(0x6619,2),(0x661b,3),(0x661f,c.get('delta',1)),(0x6621,c.get('minimum',0x8000)),(0x6623,c.get('maximum',0x7fff))]:put(at,v)
            for at,v in [(0x5efb,c.get('mode',3)),(0x65d2,c.get('start',1)),(0x5efc,c.get('active',1)),(0x6605,c.get('direction',1)),(0x661d,c.get('limitmode',1))]:data[ds*16+at]=v
            data[ds*16+0x6611:ds*16+0x6619]=bytes([0,1,2,3,4,5,6,7])
            for i in range(128):struct.pack_into('<H',data,ds*16+0x663b+i*2,(i*317+11)&65535)
            struct.pack_into('<H',data,songseg*16+song,event);data[songseg*16+((song+2)&65535)]=0
            commands=c.get('commands',b'');stream=commands+bytes([c.get('note',65),c.get('duration',2),0xfb,0])
            for i,b in enumerate(stream):data[songseg*16+((event+i)&65535)]=b
            # Voice data are opaque synthetic bytes; group overlap retains
            # actual forward-copy and postwrite field-read behavior.
            if c.get('voice_group'):
                for i in range(28):data[voiceseg*16+((voice+i)&65535)]=(i*17+3)&255
                # Copy may modify interpreter controls only at6609..6624.
            data[ss*16+sp-4:ss*16+sp+8]=b'\xa5'*4+struct.pack('<2H',0x100,0x1111)+b'\xa5'*4
            uc.mem_write(0,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);incoming=Registers(0xa55a,0x1234,0x4567,0x7654,0x3456,0x2345,ds,0x4321,(flags>>9)&1,(flags>>10)&1)
            for reg,val in list(zip(regids,[incoming.ax,incoming.bx,incoming.cx,incoming.dx,incoming.si,incoming.di,incoming.ds,incoming.es]))+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x75ea),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x5678),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(ports=[],instructions=0,sites=set());uc.emu_start(cs*16+0x75ea,0x11210,count=20000)
            label=f'{load:x}/{category}/{c}'
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original far return '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def native_port(ctx,qptr,vptr):
                try:q=qptr.contents;vptr.contents.value=service(events,q.operation,q.port,q.value if q.operation else 0,q.interrupts_enabled);return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Port(native_port);result=Result();native(gb,len(data),load,C.byref(incoming),cb,None,128,C.byref(result));require(not errors and result.status==0,'Native finite completion '+label+str(errors));require(events==active['ports'],'Port event order '+label)
            actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-2:ss*16+sp]=expected[ss*16+sp-2:ss*16+sp]
            require(actual==expected,'Full nonstack memory '+label)
            r=result.registers;require([uc.reg_read(reg) for reg in regids]==[r.ax,r.bx,r.cx,r.dx,r.si,r.di,r.ds,r.es],'Registers '+label);require(uc.reg_read(UC_X86_REG_BP)==0x5678 and uc.reg_read(UC_X86_REG_SS)==ss,'Preserved BP/SS '+label)
            require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'IF/DF '+label);require(bytes(uc.mem_read(ss*16+sp,8))==struct.pack('<2H',0x100,0x1111)+b'\xa5'*4,'Far frame '+label)
            if 0x76a2 in active['sites']:require(bytes(uc.mem_read(ss*16+sp-2,2))==struct.pack('<H',incoming.di),'Saved DI frame '+label)
            sites.update(active['sites']);instructions+=active['instructions'];coverage[category]+=1;vectors+=1
    record={'schema':1,'function_id':'FN-EGA-000362','result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_music_tick.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(function['instructions']),'limits':'Serialized75EA with synthetic20bit bus, explicit finite song/voice fixtures, source/group alias copies, effectiveoffset/ordinaryword wrap, register/IF/DF/farframe andtypedport effects. x86maskedshift profile, no actual PIT/speaker/IRQ/timebase, sourceformat/corpus/VOICES2bytebounds, timer exclusion, game/audio/fidelity acceptance. Nativebudget/adapterdiagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
