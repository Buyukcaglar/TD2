"""Compare original forward/backward paragraph moves on synthetic byte pools.

Only admitted nonwrapping pool ranges execute. Code and active stack remain
disjoint; no DOS, resource format or actual game payload is involved.
"""
import argparse
from collections import Counter
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();library=a.library.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    require(library.is_relative_to(ROOT/'analysis'),'Private library required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x110000)
    cs,ss,sp=0xb000,0xe000,0x8000;origin=0x1000;pool_bytes=0x90000;pool_at=origin*16
    starts=set();spans=[];instructions=[0];counts=Counter();total=0
    for ip,length in [(0x6fe8,72),(0x7030,83)]:
        offset=0x6c90+ip;code=image[offset:offset+length]
        uc.mem_write(cs*16+ip,code);starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(code).hexdigest()})
    def fetch(u,address,size,_):
        require(address in starts,'Copy escaped instruction fence');instructions[0]+=1
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));functions={}
    for direction in ['forward','backward']:
        function=getattr(dll,'td2ega_paragraph_copy_'+direction)
        function.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16];function.restype=ctypes.c_int
        functions[direction]=function
    rng=random.Random(0x6fe87030);initial=rng.randbytes(pool_bytes);guard=b'\xa5'*8
    def compare(direction,source,destination,paragraphs,fixture_origin=origin,
                fixture_bytes=initial):
        nonlocal total
        fixture_pool_at=fixture_origin*16;fixture_pool_bytes=len(fixture_bytes)
        require(fixture_origin<=source and fixture_origin<=destination and
                (max(source,destination)+paragraphs)*16<=fixture_pool_at+fixture_pool_bytes,'Fixture pool bounds')
        uc.mem_write(fixture_pool_at-8,guard+fixture_bytes+guard)
        uc.mem_write(ss*16+sp,struct.pack('<HHHHH',0x100,0xf000,source,destination,paragraphs))
        ip=0x6fe8 if direction=='forward' else 0x7030
        preserved=[(UC_X86_REG_DS,0x278f),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_DX,0x3456)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_BX,0x1111),(UC_X86_REG_CX,0x2222),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        uc.emu_start(cs*16+ip,0xf0100,count=paragraphs*8+16384)
        require(uc.reg_read(UC_X86_REG_CS)==0xf000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved copy registers/segments')
        require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'DF must return cleared')
        expected_es=((destination+((paragraphs+0xfff)//0x1000)*0x1000)&65535) if direction=='forward' else destination
        expected_ax=(expected_es if paragraphs else 0xbeef) if direction=='forward' else ((((paragraphs-1)%0x1000+1)*16-2)&65535 if paragraphs else destination)
        require(uc.reg_read(UC_X86_REG_ES)==expected_es and uc.reg_read(UC_X86_REG_AX)==expected_ax,'AX/ES chunk effects')
        require(uc.reg_read(UC_X86_REG_BX)==0 and uc.reg_read(UC_X86_REG_CX)==(0 if paragraphs else 0x2222),'BX/CX effect')
        buffer=(ctypes.c_uint8*(fixture_pool_bytes+16)).from_buffer_copy(guard+fixture_bytes+guard)
        ok=functions[direction](ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8)),fixture_pool_bytes,fixture_origin,source,destination,paragraphs)
        require(ok==1 and bytes(buffer)==bytes(uc.mem_read(fixture_pool_at-8,fixture_pool_bytes+16)),f'Native/original wholepool mismatch{direction}/{source:04x}/{destination:04x}/{paragraphs:04x}')
        require(bytes(uc.mem_read(ss*16+sp+4,6))==struct.pack('<HHH',source,destination,paragraphs),'Caller arguments changed')
        counts[direction]+=1;total+=1
    sizes=[0,1,2,7,0xfff,0x1000,0x1001,0x1fff,0x2000,0x2001,0x3001,0x6000]
    for direction in functions:
        for paragraphs in sizes:
            for source,destination in [(0x1000,0x4000),(0x4000,0x1000),(0x2000,0x2000),(0x2000,0x2001),(0x2001,0x2000)]:
                if max(source,destination)+paragraphs<=0xa000:compare(direction,source,destination,paragraphs)
        for case in range(48):
            paragraphs=rng.randrange(0x3001);source=rng.randrange(origin,0xa001-paragraphs);destination=rng.randrange(origin,0xa001-paragraphs)
            compare(direction,source,destination,paragraphs)
        for paragraphs in [0,1]:compare(direction,0xffff,0xffff,paragraphs,0xffff,bytes(range(16)))
    # Empty operations at the segment-word boundary, and oversized host bound
    # arithmetic, are native diagnostics outside the exercised guest profile.
    raw=(ctypes.c_uint8*32)(*range(32));before=bytes(raw);extra=0
    for function in functions.values():
        for size,base,source,destination,paragraphs in [(32,0x1000,0xfff,0x1000,1),(32,0x1000,0x1000,0x1000,3),(0xffffffff,0xffff,0xffff,0xffff,1),(32,0xffff,0xffff,0xffff,1)]:
            require(function(raw,size,base,source,destination,paragraphs)==0 and bytes(raw)==before,'Native invalid-bound write/diagnostic');extra+=1
    result={'schema':1,'function_ids':['FN-EGA-000179','FN-EGA-000180'],'result':'pass','vectors':total,'vectors_by_direction':dict(counts),'native_only_diagnostic_cases':extra,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_paragraph_copy.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions[0],
            'coverage':['Both original copy functions with whole synthetic576KiB pool/guards','Zero,64KiB chunk boundaries, multiple chunks andlarge span',
                        'Identical spans andboth overlap directions, including originalunsafe order','48 varied spanlengths/positions per direction; lastphysical paragraph boundary',
                        'Farreturn/argument/register effects, chunk AX/ES andDF0','Native overflow/out-of-pool diagnostics without writes'],
            'limits':'Nonwrapping disjoint livecode/stack andexternalbytepool only. Segment-word/physical wrap outside admitted domain. No real resource, cachemanager lifetime, codec, DOS, renderer/audio orgameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
