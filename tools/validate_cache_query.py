"""Compare compiled readonly cache query to original7273 plus7083.

All descriptor/name contents are synthetic. No real resources or DOS execute.
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
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Entry(ctypes.Structure):
    _fields_=[('name',ctypes.c_uint8*12),('paragraphs',ctypes.c_uint16),('segment',ctypes.c_uint16),('status',ctypes.c_uint16)]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();library=a.library.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    require(library.is_relative_to(ROOT/'analysis'),'Private library required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    cs,ds,ss,sp=0x16c9,0x5000,0x7000,0x8000;load=0x1000
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    starts=set();spans=[]
    for ip,length in [(0x7273,83),(0x7083,32)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code))
        starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    instructions=[0]
    def fetch(u,address,size,_):
        require(address in starts,'Execution escaped query/helper fence');instructions[0]+=1
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));query=dll.td2ega_cache_name_present
    query.argtypes=[ctypes.POINTER(Entry),ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32];query.restype=ctypes.c_uint16
    require(ctypes.sizeof(Entry)==18,'Validation-host metadata ABI changed; revise ctypes harness')
    total=0
    def compare(entries,first,end,raw,name_at=0x120):
        nonlocal total
        require(0<=first<=end<len(entries) and 0 in raw and name_at+len(raw)<=65536,'Unsupported fixture')
        descriptor_at=0x2000;packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        guard=bytes([0xa5])*8
        uc.mem_write(ds*16+descriptor_at-8,guard+packed+guard)
        uc.mem_write(ds*16+0x6c6a,struct.pack('<HH',descriptor_at+first*18,descriptor_at+end*18))
        uc.mem_write(ds*16+name_at-8,guard+raw+guard)
        uc.mem_write(ss*16+sp,struct.pack('<HHH',0x100,0x8000,name_at))
        for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7273),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                        (UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_BP,0x5678),
                        (UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        uc.emu_start(cs*16+0x7273,0x80100,count=4096)
        require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        expected=uc.reg_read(UC_X86_REG_AX)
        array=(Entry*len(entries)).from_buffer_copy(packed);before=bytes(array)
        namebuf=(ctypes.c_uint8*(len(raw)+16)).from_buffer_copy(guard+raw+guard)
        native=query(array,len(entries),first,end,ctypes.cast(ctypes.byref(namebuf,8),ctypes.POINTER(ctypes.c_uint8)),len(raw))
        require(native==expected and native in (0,1),'C/original query mismatch')
        require(bytes(array)==before and bytes(namebuf)==guard+raw+guard,'Native readonly contract')
        require(bytes(uc.mem_read(ds*16+descriptor_at-8,len(packed)+16))==guard+packed+guard,'Guest descriptors/guards changed')
        require(bytes(uc.mem_read(ds*16+name_at-8,len(raw)+16))==guard+raw+guard,'Guest name/guards changed')
        require(uc.reg_read(UC_X86_REG_DX)==(0x3456 if expected else 0),'Guest conditionalDX effect')
        require(all(uc.reg_read(reg)==val for reg,val in [(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss)]),'Guest preserved registers/segments')
        require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp+4,2)))[0]==name_at,'Outer argument copy changed')
        require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'CLD effect')
        total+=1
    def entry(name,status=1):return (name.ljust(12,b'\0')[:12],7,0x6000,status)
    fixed=[b'FILE\0',b'FILE.PES\0',b'C:\\DIR\\FILE.PES\0',b'file.pes\0',b'FILE.ESH\0',b'\0',b'C:\\\0',b'ABCDEFGHIJKL-extra\0',b'ABCDEFGHIJKL\0']
    variants=[entry(b'FILE.PES'),entry(b'file.pes'),entry(b'FILE.ESH'),entry(b'ABCDEFGHIJKL'),entry(b'')]
    for stored in variants:
        for raw in fixed:
            for status in [0,1,2,0xffff]:compare([(stored[0],7,0x6000,status)],0,0,raw)
    for raw in fixed:
        for first,end in [(0,2),(1,2),(2,2)]:
            compare([entry(b'OTHER'),entry(b'FILE.PES'),entry(b'FILE.ESH')],first,end,raw)
            compare([entry(b'OTHER',0),entry(b'FILE.PES'),entry(b'FILE.ESH')],first,end,raw)
    for byte in range(256):
        compare([entry(bytes([byte]))],0,0,bytes([byte,0]),0)
        compare([entry(b'.'),entry(bytes([byte]))],0,1,b'C:'+bytes([byte,0]),0xe000)
    rng=random.Random(0x7273)
    for case in range(512):
        entries=[entry(bytes(rng.randrange(1,128) for _ in range(rng.randrange(13))),rng.choice([0,1,2,3,0xffff])) for _ in range(8)]
        first=rng.randrange(8);end=rng.randrange(first,8)
        raw=(entries[rng.randrange(8)][0].split(b'\0',1)[0] if case&1 else bytes(rng.randrange(1,128) for _ in range(rng.randrange(20))))+b'\0'
        compare(entries,first,end,raw,0x120 if case&2 else 0xe000)
    array=(Entry*1)();raw=(ctypes.c_uint8*1)(0)
    require(query(array,0,0,0,raw,1)==0,'Native empty-array diagnostic')
    require(query(array,1,1,0,raw,1)==0,'Native reversed-range diagnostic')
    require(query(array,1,0,1,raw,1)==0,'Native out-of-range diagnostic')
    result={'schema':1,'function_id':'FN-EGA-000185','result':'pass','vectors':total,'native_only_diagnostic_cases':3,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_query.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions[0],
            'coverage':['Exactbyte/case and12byte prefix behavior','Optionalextension match onrequested terminator',
                        'Firstfree descriptor aborts search','first=end sentinel checkedonce, normalend excluded',
                        'All256 bytevalues inrequested/stored contexts','512 variedsynthetic descriptor/name snapshots',
                        'AXboolean, conditionalDX, farframe, preservedregisters/segments andreadonly guards'],
            'limits':'Readonly stable snapshots andterminatednonwrapping names only. Nativeinvalid-bound diagnostics areoutside original-equivalence domain. No cachemovement/lifetime, DOS, codec, realresource or gameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
