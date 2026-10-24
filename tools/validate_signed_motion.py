"""Compare06B3:0008 and actual callee-clean13A8:2EE8 on synthetic groups."""
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
sys.path.insert(0,str(ROOT/'tools'))
from validate_sim_targets import Result as Registers,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Result(C.Structure):
    _fields_=[('registers',Registers)]+[(n,C.c_uint16) for n in ['damped','error','correction']]+[('product',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));multiply=dll.td2ega_long_multiply;multiply.argtypes=[C.c_uint32,C.c_uint32,C.c_uint16,C.POINTER(Registers)];multiply.restype=None;motion=dll.td2ega_update_signed_motion;motion.argtypes=[C.POINTER(C.c_uint8),C.POINTER(Registers),C.POINTER(Result)];motion.restype=None
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536));boundary=[0,1,0xff,0x100,0x101,0x5ff,0x600,0x601,0xbff,0xc00,0xc01,0xe7f,0xe80,0xe81,0x7fff,0x8000,0x8001,0xf17f,0xf180,0xf181,0xffff]
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);motion_cs=load+0x6b3;runtime_cs=load+0x13a8;starts=set();active={}
        for segment,ip,length in [(0x6b3,8,345),(0x13a8,0x2ee8,52)]:
            first=segment*16+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write((load+segment)*16+ip,bytes(code));starts.update((load+segment)*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            require(address in starts,'Signedmotion escaped instruction fence');active['instructions']+=1
            if address==motion_cs*16+0x119:active['product']=(u.reg_read(UC_X86_REG_DX)<<16)|u.reg_read(UC_X86_REG_AX)
            if address==motion_cs*16+0xa7:active['damped']=True
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
        def prepare(cs,ip,flags,frame):
            uc.mem_write(ss*16+sp-32,b'\xa5'*32+frame+b'\xa5'*8)
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xaa55),(UC_X86_REG_BX,0xa55a),(UC_X86_REG_CX,0x4567),(UC_X86_REG_DX,0x7654),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,product=0,damped=False)
        def check(regs,flags,pop):
            require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(regs.ax,regs.bx,regs.cx,regs.dx),'Scratch outputs')
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+pop),'Farreturn/callee cleanup');require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers');require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'IF/DF')
        def product_case(first,second,category):
            nonlocal vectors,instructions
            flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);frame=struct.pack('<2H2I',0x400,0xa000,first,second);prepare(runtime_cs,0x2ee8,flags,frame);uc.emu_start(runtime_cs*16+0x2ee8,0xa0400,count=64);result=Registers();multiply(first,second,0x4567,C.byref(result));label=f'{load:x}/{first:x}/{second:x}'
            require(((result.dx<<16)|result.ax)==(first*second)&0xffffffff,'Low32 product '+label);check(result,flags,12);require(bytes(uc.mem_read(ss*16+sp,len(frame)))==frame,'Four argument words unchanged '+label);coverage[category]+=1;instructions+=active['instructions'];vectors+=1
        for low in range(65536):
            product_case(low,0xffff,'all_lowwords_fast_product');product_case(0xffff0000|low,0x10001,'all_lowwords_cross_product')
        words=[0,1,0xffff,0x10000,0x10001,0x7fffffff,0x80000000,0xffffffff,0xffff0000,0x12345678]
        for first in words:
            for second in words:product_case(first,second,'long_product_boundaries')
        rng=random.Random(0x2ee8)
        for _ in range(4096):product_case(rng.randrange(1<<32),rng.randrange(1<<32),'varied_long_products')
        def motion_case(steer,sample,rotation,lateral,drag,other,factor_input,shift_input,category):
            nonlocal vectors,instructions
            data=bytearray(baseline);data[0x336d]=steer;data[0x336e]=drag;data[0x30e4]=sample
            for at,value in [(0x2f46,rotation),(0x2f4a,lateral),(0x3322,other),(0x30e6,factor_input),(0x335a,shift_input)]:struct.pack_into('<H',data,at,value)
            uc.mem_write(ds*16,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);frame=struct.pack('<2H',0x400,0xa000);prepare(motion_cs,8,flags,frame);uc.emu_start(motion_cs*16+8,0xa0400,count=256);gb=(C.c_uint8*65536).from_buffer_copy(data);incoming=Registers(0xaa55,0xa55a,0x4567,0x7654);result=Result();motion(gb,C.byref(incoming),C.byref(result));label=f'{load:x}/{steer:x}/{sample:x}/{rotation:x}/{lateral:x}/{drag}/{other}/{factor_input:x}/{shift_input:x}'
            require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            try:check(result.registers,flags,4)
            except RuntimeError as e:raise RuntimeError(str(e)+' '+label)
            require(result.damped==int(active['damped']) and result.product==active['product'],'Path/product '+label);require(bytes(uc.mem_read(ss*16+sp-6,4))==struct.pack('<2H',result.correction,result.error),'Actual stacklocals '+label);coverage[category]+=1;coverage['damping_path' if result.damped else 'product_path']+=1;instructions+=active['instructions'];vectors+=1
        for steer in range(256):
            for sample in range(256):motion_case(steer,sample,boundary[(steer+sample)%len(boundary)],(steer*257)^sample,1,1,(sample<<8)|steer,(steer<<8)|sample,'all_signed_byte_pairs')
        for rotation in boundary:
            for lateral in boundary:
                for steer in [0,1,0x7f,0x80,0xff]:
                    for drag,other in [(0,0),(1,0),(1,1)]:motion_case(steer,0x80,rotation,lateral,drag,other,0xffff,0xffff,'damping_and_clamp_boundaries')
        for shift_input in [0,1,0x1ff,0x200,0x201,0x7fff,0x8000,0xffff]:
            for factor_input in [0,1,0x3ff,0x400,0x401,0x7fff,0x8000,0xffff]:
                for steer in [0,1,0x7f,0x80,0xff]:motion_case(steer,0xff,0x1000,0x8000,1,1,factor_input,shift_input,'logical_shift_factor_boundaries')
        rng=random.Random(0x6b3)
        for _ in range(4096):motion_case(rng.randrange(256),rng.randrange(256),rng.randrange(65536),rng.randrange(65536),rng.choice([0,1,0xff]),rng.choice([0,1,0xffff]),rng.randrange(65536),rng.randrange(65536),'varied_motion_states')
    record={'schema':1,'function_ids':['FN-EGA-000344','FN-EGA-000364'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_signed_motion.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sim_targets.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_targets.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete06B3:0008 and13A8:2EE8 withactualcallee-cleanmultiply, serializedsyntheticfullgroup. Arithmeticrightshift/CBW/CWD, wrappedabsolute8000/damping, productextraction/clamps, scratchoutputs/stacklocals andRETF8 checked. No originalphysicalunits/resourcefields/callerflag/IRQ/fullstate, renderer/audio/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
