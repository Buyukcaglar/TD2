"""Compare metadata allocator70A3 to compiled C using synthetic arenas only.

Original failure paths stop before entering external fatal16A7:0002. Neither
cleanup nor termination is emulated or inferred. No payload/DOS/codec executes.
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
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Entry(ctypes.Structure):
    _fields_=[('name',ctypes.c_uint8*12),('paragraphs',ctypes.c_uint16),('segment',ctypes.c_uint16),('status',ctypes.c_uint16)]


class Arena(ctypes.Structure):
    _fields_=[('entries',Entry*50),('active_top',ctypes.c_uint16),('cached_first',ctypes.c_uint16)]


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
    starts=set();spans=[];fatal=(load+0x16a7)*16+2
    for ip,length in [(0x70a3,164),(0x7083,32)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code))
        starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    instructions=[0];event=[0];events=Counter();coverage=Counter()
    def fetch(u,address,size,_):
        if address==fatal:
            message=struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0]
            require(message in (0x6574,0x654a),'Unknown failure message')
            event[0]=1 if message==0x6574 else 2
            u.emu_stop();return
        require(address in starts,'Execution escaped allocator/helper fence');instructions[0]+=1
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));allocate=dll.td2ega_cache_allocate
    allocate.argtypes=[ctypes.POINTER(Arena),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.POINTER(ctypes.c_uint16)];allocate.restype=ctypes.c_int
    require(ctypes.sizeof(Entry)==18 and ctypes.sizeof(Arena)==904,'Validation-host metadata ABI changed')
    total=0;guard=b'\xa5'*8;table=0x68e2;name_at=0x120
    def compare(entries,active,cached,paragraphs,raw=b'C:\\DIR\\FILE.PES\0abcdefghijk',category='varied_arena'):
        nonlocal total
        require(0<=active<cached<=49 and len(entries)==50 and len(raw)<0x1000 and 0 in raw,'Unsupported fixture')
        packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        initial=bytearray(b'\xcc'*65536)
        initial[table-8:table+len(packed)+8]=guard+packed+guard
        globals=struct.pack('<HHHH',table,table+active*18,table+cached*18,table+49*18)
        initial[0x6c66:0x6c6e]=globals
        initial[name_at-8:name_at+len(raw)+8]=guard+raw+guard
        uc.mem_write(ds*16,bytes(initial))
        uc.mem_write(ss*16+sp,struct.pack('<HHHH',0x100,0x8000,name_at,paragraphs))
        for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x70a3),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                        (UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_BP,0x5678),
                        (UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        event[0]=0;uc.emu_start(cs*16+0x70a3,0x80100,count=4096)
        if event[0]==0:
            require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
            require(uc.reg_read(UC_X86_REG_AX)==0,'Normal AX result')
            require(all(uc.reg_read(reg)==val for reg,val in [(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss)]),'Normal preserved registers/segments')
            require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'CLD dependency effect')
        else:
            require(uc.reg_read(UC_X86_REG_CS)==load+0x16a7 and uc.reg_read(UC_X86_REG_IP)==2,'Failure boundary')
            require(struct.unpack('<H',bytes(uc.mem_read(ss*16+uc.reg_read(UC_X86_REG_SP)+6,2)))[0]==name_at,'Failure filename argument')
        arena=Arena.from_buffer_copy(packed+struct.pack('<HH',active,cached))
        namebuf=(ctypes.c_uint8*(len(raw)+16)).from_buffer_copy(guard+raw+guard)
        result=ctypes.c_uint16(0xdead)
        native=allocate(ctypes.byref(arena),ctypes.cast(ctypes.byref(namebuf,8),ctypes.POINTER(ctypes.c_uint8)),len(raw),paragraphs,ctypes.byref(result))
        require(native==event[0],f'C/original event mismatch vector{total}')
        if native==0:require(result.value==uc.reg_read(UC_X86_REG_DX),'Allocated segment mismatch')
        else:require(result.value==0xdead,'Failure native result changed')
        expected=bytearray(initial)
        expected[table:table+900]=bytes(arena.entries)
        expected[0x6c68:0x6c6c]=struct.pack('<HH',table+arena.active_top*18,table+arena.cached_first*18)
        require(bytes(uc.mem_read(ds*16,65536))==bytes(expected),f'Descriptor/global/fullDS mismatch vector{total}')
        require(bytes(namebuf)==guard+raw+guard,'Native name/guards changed')
        require(bytes(uc.mem_read(ss*16+sp+4,4))==struct.pack('<HH',name_at,paragraphs),'Outer argument copies changed')
        events[str(native)]+=1;coverage[category]+=1;total+=1
    rng=random.Random(0x70a3)
    def snapshot(active,cached,gap=8,origin=0x6000):
        entries=[(bytes(rng.randrange(256) for _ in range(12)),rng.randrange(65536),rng.randrange(65536),rng.randrange(65536)) for _ in range(50)]
        entries[0]=(b'LEFT'.ljust(12,b'\0'),0,origin,2)
        current=origin
        for index in range(1,active+1):
            size=rng.randrange(1,9);entries[index]=(f'A{index:02}'.encode().ljust(12,b'\0'),size,current,2);current=(current+size)&65535
        current=(current+gap)&65535
        for index in range(cached,49):
            size=rng.randrange(1,9);entries[index]=(f'C{index:02}'.encode().ljust(12,b'\0'),size,current,1);current=(current+size)&65535
        entries[49]=(b'RIGHT'.ljust(12,b'\0'),0,current,1)
        return entries
    # Every descriptor boundary, cache eviction, exact fit and arithmetic edge.
    for active in range(49):
        for cached in range(active+1,50):
            entries=snapshot(active,cached)
            for paragraphs in [0,1,8,9,0x7fff,0xffff]:compare(entries,active,cached,paragraphs,category='all_descriptor_boundaries')
    # Exhaustive request word on a fixed empty arena. This includes segment
    # wrap admitted as instruction arithmetic, without treating it as safe RAM.
    entries=snapshot(0,49,gap=0x100)
    for paragraphs in range(65536):compare(entries,0,49,paragraphs,category='all_request_words')
    for byte in range(256):
        raw=b'C:\\'+bytes([byte])+b'\0'+b'abcdefghijklmnop'
        compare(snapshot(0,49),0,49,1,raw,'all_name_bytes')
    for case in range(512):
        active=rng.randrange(49);cached=rng.randrange(active+1,50)
        entries=snapshot(active,cached,rng.randrange(33),rng.choice([0,0x6000,0xfff0,0xffff]))
        compare(entries,active,cached,rng.randrange(65536),category='varied_segment_edges')
    # Extra native diagnostics are deliberately outside original equivalence.
    arena=Arena();arena.cached_first=49;raw=(ctypes.c_uint8*1)(0);result=ctypes.c_uint16(0xdead)
    require(allocate(ctypes.byref(arena),raw,1,1,ctypes.byref(result))==3,'Short native basename storage')
    arena.active_top=49
    require(allocate(ctypes.byref(arena),raw,1,1,ctypes.byref(result))==3,'Invalid native active boundary')
    arena.active_top=0;arena.cached_first=0
    require(allocate(ctypes.byref(arena),raw,1,1,ctypes.byref(result))==3,'Invalid native overlapping boundaries')
    result={'schema':1,'function_id':'FN-EGA-000182','result':'pass','vectors':total,'native_only_diagnostic_cases':3,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_allocate.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions[0],
            'event_counts':dict(events),'fixture_coverage':dict(coverage),
            'coverage':['All admissible active/cache descriptor boundaries','Every uint16 request value on fixed empty arena',
                        'Success AX0/DXsegment and preserved far-frame/registers','Full synthetic DS64KiB including mutations preceding fatal call',
                        'Every filename byte value and fixed twelve-byte copy after NUL','512 segment-edge arenas with explicit uint16 wrap'],
            'limits':'Stable disjoint synthetic metadata and names. Failure stops before external fatal16A7:0002; no cleanup, termination, payload memory, DOS, codec, real resource, complete allocator lifetime or gameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
