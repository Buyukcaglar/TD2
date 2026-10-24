"""Compare6E4E/6E59 directory lookup on synthetic segment/selector views."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','found','offset','segment','matched_index']]+[('comparisons',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh output')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_directory_find;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(C.c_uint8),C.c_uint16,C.c_uint32,C.POINTER(Result)];native.restype=None
    rng=random.Random(0x6e59);cases=[]
    # count is a literal header word, not an admitted archive-schema length.
    for count in [0,1,2,7,31]:
        for index in [-1,0,count//2,count]:
            for selector in [b'ABCD',b'A\0xy',b'\0xyz',b'abcD',b'AB\0\0',b'AB D']:
                for offset in [0,0x120,0xffe0]:
                    for relative in [0,15,16,0xfffff,0x7fffffff,0xffffffff]:cases.append((count,index,selector,offset,relative,'structured'))
    for count in [0x7ffe,0x7fff,0x8000,0x8001,0x8002,0xffff]:cases.append((count,-1,b'ABCD',0,0,'signed_count'))
    for offset in [0xfff5,0xfffb,0xfffc,0xffff]:
        for index in [-1,0,1]:cases.append((1,index,b'ABCD',offset,0xffffffff,'word_and_near_wrap'))
    for byte in range(256):cases.append((1,0,bytes([byte])+b'XYZ',0x123,byte*0x01010101,'all_selector_bytes'))
    for _ in range(512):cases.append((rng.randrange(1,32),rng.randrange(-1,33),rng.randbytes(4),rng.randrange(65536),rng.randrange(1<<32),'random_near_wrap'))
    coverage=Counter();vectors=instructions=0;ss,sp,caller_ds=0x9000,0x8000,0x4567
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x110000);cs=load+0x6c9;group=load+0x178f;fatal=(load+0x16a7)*16+2;active={};first,length=0x6c90+0x6e4e,207
        code=bytearray(image[first:first+length])
        for r in relocs:
            if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
        uc.mem_write(cs*16+0x6e4e,bytes(code));starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x6e4e)}
        def fetch(u,address,size,_):
            if address==fatal:
                active['fatal']=True;require(struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0]==0x651a,'Fatal message');u.emu_stop();return
            require(address in starts,'Directory escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x6e88:active['comparisons']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for count,index,selector,offset,relative,category in cases:
            source=bytearray(b'\x7e'*65537)
            def put_word(at,value):struct.pack_into('<H',source,at,value)
            put_word((offset+4)&65535,count)
            if index>=0:
                record=(offset+6+4*index)&65535
                # Original accepts the first NUL-vs-space mismatch early;
                # deliberately leave nonzero junk after that source NUL.
                name=bytearray(selector)
                if 0 in selector:name[selector.index(0)+1:]=b'Z'*(3-selector.index(0))
                for j,b in enumerate(name):source[(record+j)&65535]=b
                table=(record+4*count)&65535;put_word(table,relative&65535);put_word((table+2)&65535,relative>>16)
            # Overlaps between constructed names/tables/header are allowed;
            # native and original must read the resulting shared bytes.
            for required in [0,1]:
                segment=[0x6000,0x7fff,0xffff][vectors%3];selector_at=0x120 if vectors&1 else 0xfffc
                group_initial=bytearray(b'\xcc'*65536);group_initial[selector_at:selector_at+4]=selector
                uc.mem_write(segment*16,bytes(source));uc.mem_write(group*16,bytes(group_initial));uc.mem_write(ss*16+sp-64,b'\xa5'*64+struct.pack('<5H',0x100,0xa000,offset,segment,selector_at))
                entry=0x6e59 if required else 0x6e4e;preserved=[(UC_X86_REG_DS,caller_ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345)]
                for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
                active.update(fatal=False,instructions=0,comparisons=0);uc.emu_start(cs*16+entry,0xa0100,count=2000000)
                sb=(C.c_uint8*len(source)).from_buffer_copy(source);sel=(C.c_uint8*4).from_buffer_copy(selector);result=Result();native(sb,len(source),segment,offset,sel,required,40000,C.byref(result))
                label=f'{load:x}/{count}/{index}/{selector!r}/{offset:x}/{relative:x}/{required}'
                require(result.status==int(active['fatal']),'Status '+label);require(result.comparisons==active['comparisons'],f'Comparison count {result.comparisons} vs {active["comparisons"]} '+label)
                expected=bytearray(group_initial);expected[selector_at:selector_at+4]=bytes(sel);require(bytes(uc.mem_read(group*16,65536))==expected,'Full selector group '+label);require(bytes(uc.mem_read(segment*16,len(source)))==bytes(sb),'Source mutation '+label)
                if not active['fatal']:
                    require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Far return '+label)
                    require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label)
                    require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX))==(result.offset,result.segment),'Returned pointer '+label)
                    require(uc.reg_read(UC_X86_REG_ES)==group and uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'ES/DF '+label)
                require(bytes(uc.mem_read(ss*16+sp+4,6))==struct.pack('<3H',offset,segment,selector_at),'Caller arguments')
                coverage[category]+=1;coverage['found_'+str(result.found)+'_status_'+str(result.status)]+=1;instructions+=active['instructions'];vectors+=1
    diagnostics=0
    for bytes_available,budget in [(0,40000),(65537,0)]:
        source=(C.c_uint8*65537)();selector=(C.c_uint8*4)(65,66,67,68);r=Result();native(source,bytes_available,0,0,selector,0,budget,C.byref(r));require(r.status==2,'Native diagnostic');diagnostics+=1
    record={'schema':1,'function_id':'FN-EGA-000174','covered_original_local_helpers':['FN-EGA-000175'],'result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_directory.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'executed_module_range':{'offset':first,'length':length,'sha256':hashlib.sha256(image[first:first+length]).hexdigest()},'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Literal directory code contract with synthetic ordinary-memory source/selector views, two load bases, optional/required policy, signed count/near-wrap and32bit arithmetic. No archive format admission, actual resource decoding, source/pointer lifetime, IRQ, fatal cleanup or game/fidelity acceptance. Host bounds/work diagnostics remain outside original errors.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
