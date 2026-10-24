"""Compare compiled basename C to only the original32byte leaf.

Synthetic filename bytes only; no file open, resource codec, DOS or game.
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class GuardedOffset(ctypes.Structure):
    _fields_=[('before',ctypes.c_uint8*8),('value',ctypes.c_uint16),('after',ctypes.c_uint8*8)]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();library=a.library.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    require(library.is_relative_to(ROOT/'analysis'),'Private DLL required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    s,ip,length=0x6c9,0x7083,32;offset=s*16+ip;code=image[offset:offset+length]
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    reloc={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    require(not any(offset<=r<offset+length for r in reloc),'Leaf has relocations; revise fixture')
    dll=ctypes.CDLL(str(library));scan=dll.td2ega_basename_offset
    scan.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint16)];scan.restype=ctypes.c_int
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    cs,ds,ss,sp=0x16c9,0x5000,0x7000,0x8000;start=cs*16+ip
    uc.mem_write(start,code)
    boundaries={start+i.address-ip for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip)}
    instruction_count=[0]
    def fetch(u,address,size,_):
        require(address in boundaries and address+size<=start+length,'Execution escaped leaf')
        instruction_count[0]+=1
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    preserved={UC_X86_REG_BX:0x1234,UC_X86_REG_CX:0x2345,UC_X86_REG_DX:0x3456,
               UC_X86_REG_DI:0x4567,UC_X86_REG_BP:0x5678,UC_X86_REG_SI:0xbeef,UC_X86_REG_ES:0x6789}
    total=0
    def native(raw,available=None):
        buf=(ctypes.c_uint8*(len(raw)+16)).from_buffer_copy(bytes([0xa5])*8+raw+bytes([0xa5])*8)
        result=GuardedOffset();result.before[:]=[0xa5]*8;result.after[:]=[0xa5]*8;result.value=0xbeef
        pointer=ctypes.cast(ctypes.byref(buf,8),ctypes.POINTER(ctypes.c_uint8))
        status=scan(pointer,len(raw) if available is None else available,ctypes.cast(ctypes.byref(result,8),ctypes.POINTER(ctypes.c_uint16)))
        require(bytes(buf)==bytes([0xa5])*8+raw+bytes([0xa5])*8,'Native input/guards changed')
        require(bytes(result.before)==bytes([0xa5])*8 and bytes(result.after)==bytes([0xa5])*8,'Native output guards changed')
        return status,result.value
    def compare(raw,name_start):
        nonlocal total
        require(0 in raw and name_start+len(raw)<=65536,'Fixture outside nonwrapping input contract')
        data=ds*16+name_start;guard=bytes([0xa5])*8
        uc.mem_write(data-8,guard+raw+guard)
        uc.mem_write(ss*16+sp,struct.pack('<HHH',0x100,0x8000,name_start))
        for reg,val in preserved.items():uc.reg_write(reg,val)
        for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                        (UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xabcd),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        uc.emu_start(start,0x80100,count=len(raw)*12+32)
        require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100,'Far return')
        require(uc.reg_read(UC_X86_REG_SP)==sp+4,'Caller-owned argument cleanup')
        ax=uc.reg_read(UC_X86_REG_AX)
        status,relative=native(raw)
        require(status==1 and ax==name_start+relative,'Native/original basename mismatch')
        require(bytes(uc.mem_read(data-8,len(raw)+16))==guard+raw+guard,'Guest input/guards changed')
        require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp+4,2)))[0]==ax,'Original argument-copy postcondition')
        require(uc.reg_read(UC_X86_REG_DS)==ds and uc.reg_read(UC_X86_REG_SS)==ss,'Guest segments')
        require(all(uc.reg_read(reg)==val for reg,val in preserved.items()),'Guest preserved registers')
        # OR AL,AL at terminating zero gives these defined flags; CLD clearsDF.
        require(uc.reg_read(UC_X86_REG_EFLAGS)&0xcc5==0x44,'Guest defined flags (AF excluded)')
        total+=1
    fixed=[b'\0',b'FILE\0',b'C:FILE\0',b'C:\\DIR\\FILE.PES\0',b'ROOT/FILE\0',
           b'A:B:C\0',b'\\\0',b'C:\\DIR\\\0',b'x:y\\z/a\0',b'NAME\0IGNORED']
    for raw in fixed:
        for position in [0,1,0x8123,0xfe00]:compare(raw,position)
    for byte in range(256):
        compare(bytes([byte,0]),0)
        compare(b'C:'+bytes([byte,0]),0x0120)
        compare(b'ROOT\\'+bytes([byte,0]),0xfe00)
    for position in range(256):
        compare(b'A'*position+b'\\'+b'B'*(255-position)+b'\0',0x0120)
        compare(b'A'*position+b':'+b'B'*(255-position)+b'\0',0xfe00)
    rng=random.Random(0x7083)
    for case in range(512):
        raw=bytes(rng.randrange(1,256) for _ in range(rng.randrange(128)))+b'\0'
        compare(raw,[0,0x0120,0x8123,0xfe00][case%4])
    # Full16bit span and last-byte terminator/last-valid separator positions.
    compare(b'A'*65535+b'\0',0)
    compare(b'A'*65534+b'\\\0',0)
    compare(b'A'*65534+b':\0',0)
    for raw,available in [(b'',0),(b'NO_TERMINATOR',13),(b'\0',65537)]:
        require(native(raw,available)==(0,0),'Native diagnostic outside original input domain')
    result={'schema':1,'function_id':'FN-EGA-000181','result':'pass','vectors':total,'native_only_diagnostic_cases':3,
            'image_sha256':hashlib.sha256(image).hexdigest(),'function_module_offset':offset,'function_length':length,
            'function_sha256':hashlib.sha256(code).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_filename.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instruction_count[0],
            'coverage':['All256 bytevalues inthree contexts','Separator positions0..255','Seeded512 variedbyte paths',
                        'Empty input, offsetzero, case/slash distinctions, embeddedterminator andfull64KiB spans',
                        'Guest AX/argumentcopy, preservedregisters/segments, farframe, flags and memoryguards'],
            'limits':'Nonwrapping terminatedbyte spans only. Native missing-terminator diagnostics have no original-equivalence claim. No DOS/filesystem, resource codec, secondcompiler/host, game integration or fidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
