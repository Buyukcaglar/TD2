"""Compare near412C/4441/4588 state/arithmetic with synthetic full groups."""
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['ax','bx','cx','dx']]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));update=dll.td2ega_update_sample_targets;update.argtypes=[C.POINTER(C.c_uint8),C.c_uint16,C.POINTER(Result)];update.restype=None;delta=dll.td2ega_compare_target_delta;delta.argtypes=[C.POINTER(C.c_uint8),C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(Result)];delta.restype=None;adjust=dll.td2ega_adjust_target;adjust.argtypes=delta.argtypes;adjust.restype=None
    coverage=Counter();vectors=instructions=0;ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536));boundaries=[0,1,95,96,97,799,800,801,0xa8b,0xa8c,0xa8d,0xbb7,0xbb8,0xbb9,0x7ffe,0x7fff,0x8000,0x8001,0xffff]
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;starts=set();active={}
        for ip,length in [(0x412c,222),(0x4441,73),(0x4588,55)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):require(address in starts,'Targets escaped instruction fence');active['instructions']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
        def compare(kind,changes,category,cx=0x4567,dx=0x7654):
            nonlocal vectors,instructions
            data=bytearray(baseline)
            for at,value,width in changes:
                if width==1:data[at]=value
                else:struct.pack_into('<H',data,at,value)
            uc.mem_write(ds*16,bytes(data));uc.mem_write(ss*16+sp-16,b'\xa5'*16+struct.pack('<H',0x100)+b'\xa5'*8);flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);entry={'update':0x412c,'delta':0x4441,'adjust':0x4588}[kind]
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_BX,0xa55a),(UC_X86_REG_CX,cx),(UC_X86_REG_DX,dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active['instructions']=0;uc.emu_start(cs*16+entry,cs*16+0x100,count=256);gb=(C.c_uint8*65536).from_buffer_copy(data);result=Result()
            if kind=='update':update(gb,dx,C.byref(result))
            else:({'delta':delta,'adjust':adjust}[kind])(gb,0xa55a,cx,dx,C.byref(result))
            label=f'{load:x}/{kind}/{category}/{changes}/{cx:x}/{dx:x}'
            require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(result.ax,result.bx,result.cx,result.dx),'Scratch outputs '+label)
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'Near return '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label);require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'IF/DF '+label)
            require(bytes(uc.mem_read(ss*16+sp-16,26))==b'\xa5'*16+struct.pack('<H',0x100)+b'\xa5'*8,'Near frame/stack guards '+label);coverage[category]+=1;instructions+=active['instructions'];vectors+=1
        for value in range(65536):
            for enabled,sign in [(0,1),(0,0xff),(1,1)]:compare('adjust',[(0x332c,value,2),(0x2f56,enabled,1),(0x336c,sign,1)],'all_target_words')
        for current in boundaries:
            for target in boundaries:
                for mode in range(8):compare('update',[(0x332a,current,2),(0x332c,target,2),(0x3374,mode&1,1),(0x33bc,(mode>>1)&1,1),(0x3368,1,1),(0x336f,(mode>>2)&1,1)],'smoothing_signed_boundaries')
        for counter in range(256):
            for mode in range(8):compare('update',[(0x336a,counter,1),(0x3374,0,1),(0x33bc,0,1),(0x3368,mode&1,1),(0x336f,(mode>>1)&1,1),(0x33b2,0xff if mode&4 else 0,1)],'counter_and_countdown')
        for oscillator in [0,1,2,0x5da,0x5db,0x5dc,0x5dd,0x706,0x707,0x708,0x709,0x7ffe,0x7fff,0x8000,0xfffe,0xffff]:
            for direction in [0,1,0x7f,0x80,0xff]:compare('update',[(0x3374,1,1),(0x942e,8,2),(0x3350,oscillator,2),(0x335c,direction,1)],'oscillator_wrap_and_sign')
        for index in range(2048):
            value=(index*32)&65535;compare('update',[(0x332a,value,2),(0x332c,value,2)],'all_second_table_indices_and_aliases')
        for cx in boundaries:
            for dx in boundaries:
                for enabled,limit,used,multiplier in [(0,255,0,255),(1,255,0,255),(1,0,255,255),(1,100,100,255),(1,100,99,1),(1,128,1,56)]:compare('delta',[(0x2f56,enabled,1),(0x2418,limit,1),(0x33c6,used,1),(0x3329,multiplier,1)],'delta_signed_unsigned_boundaries',cx,dx)
        rng=random.Random(0x412c)
        for _ in range(2048):
            changes=[(at,rng.randrange(256),1) for at in [0x336a,0x3374,0x33bc,0x3368,0x336f,0x33b2,0x335c]]+[(at,rng.randrange(65536),2) for at in [0x332a,0x332c,0x3350,0x942e,0x3346]];compare('update',changes,'varied_sample_states')
            compare('delta',[(at,rng.randrange(256),1) for at in [0x2f56,0x2418,0x33c6,0x3329,0x52cf]],'varied_delta_states',rng.randrange(65536),rng.randrange(65536))
    record={'schema':1,'function_ids':['FN-EGA-000366','FN-EGA-000370','FN-EGA-000375'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sim_targets.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete near412C/4441/4588 code effects, serialized syntheticfullgroup including indexedpostwritealiases, signed/unsigned wrappedarithmetic andscratchoutputs. Alltargetworddomains, smoothing/oscillator/delta boundaries. No resource/table schema/physicalunits, completecaller/IRQ/state-machine, renderer/audio/game/fidelity acceptance; incidentalflagconsumers remainopen.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
