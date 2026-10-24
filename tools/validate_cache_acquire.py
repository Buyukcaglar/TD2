"""Compare71B4 with its actual basename/move/compactor callees on synthetic data."""
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
sys.path.insert(0,str(ROOT/'tools'))
from validate_cache_allocate import Entry,Arena,require
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();library=a.library.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    require(library.is_relative_to(ROOT/'analysis'),'Private library required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    load=0x1000;cs,ds,ss,sp=0x16c9,0x5000,0x9000,0x8000;origin=0x6100;pool_bytes=0x20000
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    starts=set();spans=[];instructions=[0];moves=[];coverage=Counter();events=Counter();total=0
    for ip,length in [(0x71b4,191),(0x7083,32),(0x6fe8,72),(0x7147,109),(0x7030,83)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    def fetch(u,address,size,_):
        require(address in starts,'Acquire escaped instruction fence');instructions[0]+=1
        if address in (cs*16+0x7030,cs*16+0x6fe8):
            source,destination,paragraphs=struct.unpack('<HHH',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,6)))
            require(origin<=source and origin<=destination and max(source,destination)*16+paragraphs*16<=origin*16+pool_bytes,'Original move outside admitted pool')
            moves.append(('backward' if address==cs*16+0x7030 else 'forward',source,destination,paragraphs))
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));acquire=dll.td2ega_cache_acquire
    acquire.argtypes=[ctypes.POINTER(Arena),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint16)];acquire.restype=ctypes.c_int
    require(ctypes.sizeof(Entry)==18 and ctypes.sizeof(Arena)==904,'Validation-host metadata ABI')
    rng=random.Random(0x71b4);table=0x68e2;guard=b'\xa5'*8;initial_pool=rng.randbytes(pool_bytes);name_at=0x120
    def compare(entries,active,first,raw,category):
        nonlocal total
        require(0<=active<first<=49 and 0 in raw,'Unsupported fixture')
        packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed
        initial[0x6c66:0x6c6e]=struct.pack('<HHHH',table,table+active*18,table+first*18,table+49*18)
        initial[name_at-8:name_at+len(raw)+8]=guard+raw+guard
        uc.mem_write(ds*16,bytes(initial));uc.mem_write(origin*16-8,guard+initial_pool+guard)
        uc.mem_write(ss*16+sp,struct.pack('<HHH',0x100,0xa000,name_at))
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x71b4),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        moves.clear();uc.emu_start(cs*16+0x71b4,0xa0100,count=2000000)
        require(uc.reg_read(UC_X86_REG_CS)==0xa000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        require(all(uc.reg_read(reg)==val for reg,val in preserved) and uc.reg_read(UC_X86_REG_AX)==0,'Preserved acquire registers/AX')
        require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'Basename/copy clears DF')
        require(uc.reg_read(UC_X86_REG_ES)==((moves[-1][2]+(0x1000*((moves[-1][3]+0xfff)//0x1000) if moves[-1][0]=='forward' else 0))&65535 if moves else 0x6789),'Conditional ES')
        arena=Arena.from_buffer_copy(packed+struct.pack('<HH',active,first))
        buffer=(ctypes.c_uint8*(pool_bytes+16)).from_buffer_copy(guard+initial_pool+guard)
        namebuf=(ctypes.c_uint8*(len(raw)+16)).from_buffer_copy(guard+raw+guard);segment=ctypes.c_uint16(0xdead)
        native=acquire(ctypes.byref(arena),ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8)),pool_bytes,origin,
                       ctypes.cast(ctypes.byref(namebuf,8),ctypes.POINTER(ctypes.c_uint8)),len(raw),ctypes.byref(segment))
        require(native in (0,1),f'Native rejected admitted fixture{total}')
        require(native==int(bool(moves)),'Acquire event differs from executed move path')
        require((segment.value==uc.reg_read(UC_X86_REG_DX)) if native else (segment.value==0xdead and uc.reg_read(UC_X86_REG_DX)==0),'Conditional segment output')
        expected=bytearray(initial);expected[table:table+900]=bytes(arena.entries)
        expected[0x6c68:0x6c6c]=struct.pack('<HH',table+arena.active_top*18,table+arena.cached_first*18)
        require(bytes(uc.mem_read(ds*16,65536))==bytes(expected),f'FullDS metadata mismatch{total}')
        require(bytes(buffer)==bytes(uc.mem_read(origin*16-8,pool_bytes+16)),f'Wholepayload/guards mismatch{total}')
        require(bytes(namebuf)==guard+raw+guard and bytes(uc.mem_read(ss*16+sp+4,2))==struct.pack('<H',name_at),'Name/arguments changed')
        coverage[category]+=1;coverage['actual_forward_moves']+=sum(m[0]=='forward' for m in moves);coverage['actual_backward_moves']+=sum(m[0]=='backward' for m in moves);events[str(native)]+=1;total+=1
    def snapshot(active,first):
        entries=[(rng.randbytes(12),rng.randrange(65536),rng.randrange(65536),rng.randrange(65536)) for _ in range(50)]
        entries[0]=(b'\0'*12,0,origin,2);current=origin
        for index in range(1,active+1):
            size=rng.randrange(1,9);entries[index]=(f'A{index:02}'.encode().ljust(12,b'\0'),size,current,2);current+=size
        current+=rng.randrange(17)
        for index in range(first,49):
            size=rng.randrange(1,17);entries[index]=(f'N{index:02}.PES'.encode().ljust(12,b'\0'),size,current,1);current+=size
        entries[49]=(b'\0'*12,0,current,1)
        return entries
    for first in range(1,50):
        for active in range(first):
            entries=snapshot(active,first)
            compare(entries,active,first,f'C:\\N{first:02}\0'.encode(),'all_active_cached_boundaries')
            compare(entries,active,first,b'ABSENT\0','all_boundaries_miss')
    for target in range(1,49):
        entries=snapshot(0,1)
        for raw in [f'N{target:02}\0'.encode(),f'N{target:02}.PES\0'.encode(),f'n{target:02}.pes\0'.encode(),b'ABCDEFGHIJKL-extra\0',b'\0']:
            compare(entries,0,1,raw,'name_semantics_and_target_rows')
        entries[1]=(entries[1][0],entries[1][1],entries[1][2],0)
        compare(entries,0,1,f'N{target:02}\0'.encode(),'firstfree_aborts')
    for byte in range(256):
        entries=snapshot(0,48);entries[48]=(bytes([byte]).ljust(12,b'\0'),entries[48][1],entries[48][2],1)
        compare(entries,0,48,bytes([byte,0]),'every_name_byte')
    for raw in [b'ABCDEFGHIJKL\0',b'ABCDEFGHIJKL-extra\0',b'C:\\ABCDEFGHIJKL-other\0']:
        entries=snapshot(0,48);entries[48]=(b'ABCDEFGHIJKL',entries[48][1],entries[48][2],1)
        compare(entries,0,48,raw,'successful_twelvebyte_prefix')
    entries=snapshot(0,48);entries[48]=(entries[48][0],0,entries[48][2],1)
    compare(entries,0,48,b'N48\0','zero_sized_acquisition')
    for case in range(512):
        first=rng.randrange(1,49);active=rng.randrange(first);target=rng.randrange(first,49);entries=snapshot(active,first)
        for index in range(first,49):
            if rng.randrange(4)==0:entries[index]=(entries[index][0],entries[index][1],entries[index][2],rng.choice([0,2,3,0xffff]))
        compare(entries,active,first,f'N{target:02}\0'.encode(),'varied_cached_holes_statuses')
    # Native sentinel-match rejection is outside the admitted original caller
    # domain: actual original continuation may destroy the sentinel/boundary.
    arena=Arena();arena.cached_first=49;arena.entries[49].status=1;name=(ctypes.c_uint8*1)(0);pool=(ctypes.c_uint8*1)(0);segment=ctypes.c_uint16(0xdead)
    require(acquire(ctypes.byref(arena),pool,1,origin,name,1,ctypes.byref(segment))==2,'Native sentinel diagnostic')
    result={'schema':1,'function_id':'FN-EGA-000184','result':'pass','vectors':total,'native_only_diagnostic_cases':1,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_acquire.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'validator_dependency':{'path':'tools/validate_cache_allocate.py','sha256':hashlib.sha256((ROOT/'tools/validate_cache_allocate.py').read_bytes()).hexdigest()},
            'original_instructions_executed':instructions[0],'fixture_coverage':dict(coverage),'event_counts':dict(events),
            'coverage':['All active/cache boundary pairs withhit/miss','Every realcachedtarget row andname/case/extension/12byte semantics','Every bytevalue filename fixture',
                        'Firstfree abort and512 variedstatus/hole snapshots','Actual original basename/forwardcopy/compactor/backwardcopy instructions, no mocks',
                        'FullDS andsynthetic128KiB payload/guards, return/segments/registers, conditionalES andDF'],
            'limits':'Exclusive nonwrapping bounded synthetic arenas/pools with no matching endsentinel andsufficient realrow/segment space. Allactualcaller lifetime/preconditions remainopen. No realresource, DOS, codec, rendering/audio orgameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
