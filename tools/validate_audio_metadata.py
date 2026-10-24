"""Compare five pointer/flag helpers with original instructions, no audio.

Synthetic disjoint source/state/stack views only. No sequencer, PIT/speaker,
callback, supplied song/voice file or game session executes.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class State(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['song_offset','song_other_offset','restart_offset','restart_other_offset',
               'song_segment','voice_segment','voice_offset','active_segment','active_offset','queued_segment','queued_offset']]+[
               (name,ctypes.c_uint8) for name in ['mode','active_flag','queued_flag','song_flag']]


class Result(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['status','enables_interrupts','selected_offset']]


FIELDS={'song_offset':(0x65ed,2),'song_other_offset':(0x65ef,2),'restart_offset':(0x65f1,2),'restart_other_offset':(0x65f3,2),
        'song_segment':(0x65f5,2),'voice_segment':(0x65f7,2),'voice_offset':(0x65f9,2),
        'active_segment':(0x5eee,2),'active_offset':(0x5ef0,2),'queued_segment':(0x5ef2,2),'queued_offset':(0x5ef4,2),
        'mode':(0x5efb,1),'active_flag':(0x5efc,1),'queued_flag':(0x5efd,1),'song_flag':(0x65d2,1)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();library,output=args.library.resolve(),args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    specs=[('song',0x758a,0x3e,'td2ega_song_select_metadata','FN-EGA-000189'),
           ('voice',0x75c8,0x11,'td2ega_voice_set_metadata','FN-EGA-000190'),
           ('queue',0x7946,0x2b,'td2ega_effect_queue_metadata','FN-EGA-000196'),
           ('cancel',0x7971,6,'td2ega_effect_cancel_queued','FN-EGA-000197'),
           ('set',0x7977,0x18,'td2ega_effect_set_metadata','FN-EGA-000198')]
    dll=ctypes.CDLL(str(library));functions={}
    for kind,entry,length,name,fid in specs:
        fn=getattr(dll,name);fn.restype=None
        if kind=='song':fn.argtypes=[ctypes.POINTER(State),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.POINTER(Result)]
        elif kind=='cancel':fn.argtypes=[ctypes.POINTER(State),ctypes.POINTER(Result)]
        else:fn.argtypes=[ctypes.POINTER(State),ctypes.c_uint16,ctypes.c_uint16,ctypes.POINTER(Result)]
        functions[kind]=fn
    rng=random.Random(0x758a7977);source=bytes(rng.randrange(256) for _ in range(65536));source_buf=(ctypes.c_uint8*65536).from_buffer_copy(source)
    def random_state():
        state=State()
        for name,(offset,width) in FIELDS.items():setattr(state,name,rng.randrange(1<<(8*width)))
        return state
    fixtures={kind:[] for kind,*_ in specs}
    pairs=[(0,0),(1,1),(0xffff,0xffff),(0x1234,0x5678),(0xfffe,0),(0,0xffff),(0x8000,0x8000),(0x7fff,0x7fff)]
    for kind in fixtures:
        if kind!='song':
            for offset,segment in pairs+[(rng.randrange(65536),rng.randrange(65536)) for _ in range(256)]:
                state=random_state();state.active_flag=[0,1,255][len(fixtures[kind])%3]
                fixtures[kind].append((bytes(state),offset,segment,0))
    index_pairs=[(offset,selector) for offset in [0,1,0xfffc,0xfffe] for selector in [0,1,0x3fff,0x4000,0xffff]]
    index_pairs += [(rng.randrange(65536),rng.randrange(65536)) for _ in range(28)]
    for mode in [0,1,2,3,4,255]:
        for active_flag in [0,1,255]:
            for offset,selector in index_pairs:
                index=(offset+4*selector)&65535
                if mode==3 and (index==65535 or (index+2)&65535==65535):continue
                state=random_state();state.mode=mode;state.active_flag=active_flag
                fixtures['song'].append((bytes(state),offset,0x6000,selector))
    counts={kind:0 for kind in fixtures};instructions=0
    ds,ss,sp=0x5000,0x7000,0x8000
    for load in [0x1000,0x2345]:
        cs=load+0x6c9;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);starts=set()
        for kind,entry,length,name,fid in specs:
            code=image[0x6c90+entry:0x6c90+entry+length];uc.mem_write(cs*16+entry,code)
            starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,entry))
        uc.mem_write(0x60000,source);active={}

        def code_hook(u,address,size,_):
            require(address in starts,'Metadata helper escaped code fence');active['instructions']+=1

        def write_hook(u,access,address,size,value,_):
            if ss*16+sp-8<=address and address+size<=ss*16+sp:return
            require((address-ds*16,size) in FIELDS.values(),'Unexpected metadata writer')
            active['write_ifs'].append((u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)

        def interrupt(*_):raise RuntimeError('Unexpected actual service/IRQ')
        uc.hook_add(UC_HOOK_CODE,code_hook);uc.hook_add(UC_HOOK_MEM_WRITE,write_hook);uc.hook_add(UC_HOOK_INTR,interrupt)
        for kind,entry,length,name,fid in specs:
            for packed,offset,segment,selector in fixtures[kind]:
                state=State.from_buffer_copy(packed)
                baseline=bytearray(b'\xa5'*65536)
                for field,(at,width) in FIELDS.items():baseline[at:at+width]=int(getattr(state,field)).to_bytes(width,'little')
                for initial_if in [0,1]:
                    for initial_df in [0,1]:
                        uc.mem_write(ds*16,bytes(baseline));uc.mem_write(ss*16+sp-8,b'\xa5'*8+struct.pack('<5H',0x100,0x8000,offset,segment,selector))
                        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x1234),(UC_X86_REG_SI,0x2345),
                                   (UC_X86_REG_DI,0x3456),(UC_X86_REG_DX,0xabcd),(UC_X86_REG_CX,0x6789)]
                        for reg,value in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_ES,0x6789),
                              (UC_X86_REG_BX,0x4567),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_EFLAGS,3|(initial_if<<9)|(initial_df<<10))]:uc.reg_write(reg,value)
                        active.update(instructions=0,write_ifs=[]);uc.emu_start(cs*16+entry,0x80100,count=64)
                        native_state=State.from_buffer_copy(packed);result=Result()
                        if kind=='song':functions[kind](ctypes.byref(native_state),source_buf,65536,segment,offset,selector,ctypes.byref(result))
                        elif kind=='cancel':functions[kind](ctypes.byref(native_state),ctypes.byref(result))
                        else:functions[kind](ctypes.byref(native_state),offset,segment,ctypes.byref(result))
                        require(result.status==0,'Admitted native metadata operation')
                        expected=bytearray(baseline)
                        for field,(at,width) in FIELDS.items():expected[at:at+width]=int(getattr(native_state,field)).to_bytes(width,'little')
                        require(bytes(uc.mem_read(ds*16,65536))==bytes(expected),'Original/native full state segment mismatch')
                        masked=kind in ['queue','set'] or kind=='song' and state.mode==3
                        require(result.enables_interrupts==int(masked),'Native IF effect')
                        require(all(flag==(0 if masked else initial_if) for flag in active['write_ifs']),'Original write masking')
                        require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==(1 if masked else initial_if),'Final IF')
                        require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==initial_df,'DF preservation')
                        require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
                        require(all(uc.reg_read(reg)==value for reg,value in preserved),'Preserved registers')
                        index=(offset+4*selector)&65535
                        song_active=kind=='song' and state.mode==3
                        ax=int.from_bytes(source[((index+2)&65535):((index+2)&65535)+2],'little') if song_active else offset if kind in ['voice','queue','set'] else 0xbeef
                        require(uc.reg_read(UC_X86_REG_AX)==ax,'AX contract')
                        require(uc.reg_read(UC_X86_REG_ES)==(segment if song_active else 0x6789),'ES contract')
                        require(uc.reg_read(UC_X86_REG_BX)==(index if song_active else 0x4567),'BX contract')
                        require(result.selected_offset==(index if song_active else 0),'Selected offset metadata')
                        counts[kind]+=1;instructions+=active['instructions']
    diagnostics=0
    for kind in fixtures:
        result=Result()
        if kind=='song':functions[kind](None,None,0,0,0,0,ctypes.byref(result))
        elif kind=='cancel':functions[kind](None,ctypes.byref(result))
        else:functions[kind](None,0,0,ctypes.byref(result))
        require(result.status==2,'Native null-state diagnostic');diagnostics+=1
    state=State();state.mode=3
    for src,length,offset in [(None,65536,0),(source_buf,1,0),(source_buf,65536,65535),(source_buf,65536,65533)]:
        before=bytes(state);result=Result();functions['song'](ctypes.byref(state),src,length,0,offset,0,ctypes.byref(result))
        require(result.status==2 and bytes(state)==before,'Native source-bound diagnostic');diagnostics+=1
    result={'schema':1,'result':'pass','function_ids':[spec[4] for spec in specs],'image_sha256':sha,
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_audio_metadata.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'vectors':sum(counts.values()),'vectors_by_operation':counts,'native_only_diagnostics':diagnostics,
            'original_instructions_executed':instructions,
            'limits':'Only disjoint syntheticsource/state/stack metadata contract. OriginalwordaccessatFFFF excluded; source/resultaliasing, actualcaller lifetimes/bounds, sequencer/IRQ/PIT/speaker/audio/device andgame/fidelity acceptance remainopen. Nativeoperationsserialized; IFoutputs preserveoriginalpolicy ratherthanclaimhostconcurrency.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
