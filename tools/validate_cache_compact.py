"""Compare native cached-side compaction with original7147 plus7030.

Synthetic descriptors and payload bytes only; execute actual move instructions,
not mocked copy calls. Arena/pool/stack/code remain disjoint and nonwrapping.
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
    starts=set();spans=[];instructions=[0];moves=[];totals=Counter();total=0
    for ip,length in [(0x7147,109),(0x7030,83)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    def fetch(u,address,size,_):
        require(address in starts,'Compactor escaped instruction fence');instructions[0]+=1
        if address==cs*16+0x7030:
            source,destination,paragraphs=struct.unpack('<HHH',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,6)))
            require(origin<=source and origin<=destination and max(source,destination)*16+paragraphs*16<=origin*16+pool_bytes,'Original move outside admitted pool')
            moves.append((source,destination,paragraphs))
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));compact=dll.td2ega_cache_compact
    compact.argtypes=[ctypes.POINTER(Arena),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16];compact.restype=ctypes.c_int
    require(ctypes.sizeof(Entry)==18 and ctypes.sizeof(Arena)==904,'Validation-host metadata ABI')
    rng=random.Random(0x7147);table=0x68e2;guard=b'\xa5'*8;initial_pool=rng.randbytes(pool_bytes)
    def compare(entries,first,category):
        nonlocal total
        packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed
        initial[0x6c66:0x6c6e]=struct.pack('<HHHH',table,table,table+first*18,table+49*18)
        uc.mem_write(ds*16,bytes(initial));uc.mem_write(origin*16-8,guard+initial_pool+guard)
        uc.mem_write(ss*16+sp,struct.pack('<HH',0x100,0xa000))
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_DX,0x3456)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7147),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        moves.clear();uc.emu_start(cs*16+0x7147,0xa0100,count=2000000)
        require(uc.reg_read(UC_X86_REG_CS)==0xa000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved compactor registers/segments')
        require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==(0 if moves else 0x400),'Conditional DF effect')
        require(uc.reg_read(UC_X86_REG_ES)==(moves[-1][1] if moves else 0x6789),'Conditional ES effect')
        arena=Arena.from_buffer_copy(packed+struct.pack('<HH',0,first))
        buffer=(ctypes.c_uint8*(pool_bytes+16)).from_buffer_copy(guard+initial_pool+guard)
        require(compact(ctypes.byref(arena),ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8)),pool_bytes,origin)==1,'Native admitted compaction failed')
        expected=bytearray(initial);expected[table:table+900]=bytes(arena.entries)
        expected[0x6c6a:0x6c6c]=struct.pack('<H',table+arena.cached_first*18)
        require(arena.active_top==0 and bytes(uc.mem_read(ds*16,65536))==bytes(expected),f'FullDS metadata mismatch{total}')
        require(bytes(buffer)==bytes(uc.mem_read(origin*16-8,pool_bytes+16)),f'Wholepayload/guards mismatch{total}')
        totals[category]+=1;totals['actual_payload_moves']+=len(moves);total+=1
    def snapshot(first,sizes=None,statuses=None):
        entries=[(rng.randbytes(12),rng.randrange(65536),rng.randrange(65536),rng.randrange(65536)) for _ in range(50)]
        entries[0]=(b'LEFT'.ljust(12,b'\0'),0,origin,2);current=origin
        for index in range(first,49):
            size=sizes[index-first] if sizes is not None else rng.randrange(33)
            status=statuses[index-first] if statuses is not None else rng.choice([0,1,2,3,0xfffe,0xffff])
            entries[index]=(f'N{index:02}'.encode().ljust(12,b'\0'),size,current,status);current+=size
        entries[49]=(b'RIGHT'.ljust(12,b'\0'),0,current,1)
        return entries
    compare(snapshot(49),49,'empty_sentinel')
    for mask in range(1024):
        statuses=[(1+2*(index%3)) if mask&(1<<index) else 2*(index%2) for index in range(10)]
        compare(snapshot(39,[1+index%3 for index in range(10)],statuses),39,'all_tenrow_hole_masks')
    for first in range(1,50):
        for status in [0,1,2,3,0xfffe,0xffff]:compare(snapshot(first,statuses=[status]*(49-first)),first,'all_boundaries_status_bits')
    for case in range(512):
        first=rng.randrange(1,50);compare(snapshot(first),first,'varied_sizes_statuses')
    compare(snapshot(47,[0x1001,7],[1,0]),47,'move_crosses64KiB')
    compare(snapshot(47,[0,7],[1,0]),47,'zero_size_retained_move')
    extra=0;arena=Arena();buffer=(ctypes.c_uint8*1)(0)
    for first,active,status,size in [(0,0,1,0),(50,0,1,0),(49,49,1,0),(49,0,0,0),(49,0,1,1)]:
        arena.cached_first=first;arena.active_top=active;arena.entries[49].status=status;arena.entries[49].paragraphs=size
        before=bytes(arena);require(compact(ctypes.byref(arena),buffer,1,origin)==0 and bytes(arena)==before,'Native metadata diagnostic');extra+=1
    result={'schema':1,'function_id':'FN-EGA-000183','result':'pass','vectors':total,'native_only_diagnostic_cases':extra,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_compact.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'validator_dependency':{'path':'tools/validate_cache_allocate.py','sha256':hashlib.sha256((ROOT/'tools/validate_cache_allocate.py').read_bytes()).hexdigest()},
            'original_instructions_executed':instructions[0],'fixture_coverage':dict(totals),
            'coverage':['Actual original backward-copy instructions, no mocked moves','All1024 ten-row hole masks','Every cached boundary withsix status values',
                        '512 varied size/status snapshots, zero retainedsize and64KiB-crossing move','Whole DS64KiB and synthetic128KiB payload/guards',
                        'Farreturn, preserved registers/segments, conditionalES/DF effects'],
            'limits':'Stable exclusively owned nonwrapping synthetic arena/pool only. No real resource, completecaller lifetime/exclusion, DOS, codec, renderer/audio orgameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
