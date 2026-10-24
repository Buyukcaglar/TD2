"""Compare both original cache-release prefixes with actual payload-copy callees."""
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


class FarStorage(ctypes.Structure):
    _fields_=[('offset',ctypes.c_uint16),('segment',ctypes.c_uint16)]


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
    load=0x1000;cs,ds,ss,sp=0x16c9,0x5000,0x9000,0x8000;origin=0x6100;pool_bytes=0x20000;fatal=(load+0x16a7)*16+2
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    starts=set();spans=[];instructions=[0];moves=[];failure=[False];coverage=Counter();events=Counter();total=0
    for ip,length in [(0x72c6,165),(0x736b,293),(0x6fe8,72),(0x7030,83)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    def fetch(u,address,size,_):
        if address==fatal:
            require(struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0]==0x65a5,'Fatal message')
            failure[0]=True;u.emu_stop();return
        require(address in starts,'Release escaped instruction fence');instructions[0]+=1
        if address in (cs*16+0x7030,cs*16+0x6fe8):
            source,destination,paragraphs=struct.unpack('<HHH',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,6)))
            require(origin<=source and origin<=destination and max(source,destination)*16+paragraphs*16<=origin*16+pool_bytes,'Original move outside admitted pool')
            moves.append(('backward' if address==cs*16+0x7030 else 'forward',source,destination,paragraphs))
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));functions={}
    for policy in ['fast','shift']:
        function=getattr(dll,'td2ega_cache_release_'+policy)
        function.argtypes=[ctypes.POINTER(Arena),ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.POINTER(FarStorage)];function.restype=ctypes.c_int;functions[policy]=function
    require(ctypes.sizeof(Entry)==18 and ctypes.sizeof(Arena)==904 and ctypes.sizeof(FarStorage)==4,'Validation-host metadata ABI')
    rng=random.Random(0x72c6736b);table=0x68e2;guard=b'\xa5'*8;initial_pool=rng.randbytes(pool_bytes)
    def compare(policy,entries,active,first,segment,category):
        nonlocal total
        require(0<=active<first<=49,'Unsupported fixture')
        packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed
        initial[0x6c66:0x6c6e]=struct.pack('<HHHH',table,table+active*18,table+first*18,table+49*18)
        uc.mem_write(ds*16,bytes(initial));uc.mem_write(origin*16-8,guard+initial_pool+guard)
        offset=(total*257)&65535;uc.mem_write(ss*16+sp,struct.pack('<HHHH',0x100,0xa000,offset,segment))
        ip=0x72c6 if policy=='fast' else 0x736b
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        moves.clear();failure[0]=False;uc.emu_start(cs*16+ip,0xa0100,count=2000000)
        if not failure[0]:
            require(uc.reg_read(UC_X86_REG_CS)==0xa000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
            require(all(uc.reg_read(reg)==val for reg,val in preserved) and uc.reg_read(UC_X86_REG_AX)==offset,'Preserved release registers/AX')
            require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==(0 if moves else 0x400),'Conditional DF')
            require(uc.reg_read(UC_X86_REG_ES)==(moves[-1][2] if moves else 0x6789),'Conditional ES')
            if policy=='shift':require(uc.reg_read(UC_X86_REG_DX)==0,'Shift policy must returnDX0')
        else:
            require(struct.unpack('<H',bytes(uc.mem_read(ss*16+uc.reg_read(UC_X86_REG_SP)+6,2)))[0]==segment,'Fatal segment argument')
        arena=Arena.from_buffer_copy(packed+struct.pack('<HH',active,first))
        buffer=(ctypes.c_uint8*(pool_bytes+16)).from_buffer_copy(guard+initial_pool+guard);result=FarStorage(0xbeef,0xdead)
        native=functions[policy](ctypes.byref(arena),ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8)),pool_bytes,origin,offset,segment,ctypes.byref(result))
        require(native==int(failure[0]),f'Native event mismatch{total}/{policy}')
        if not failure[0]:
            require(result.offset==offset and result.segment==uc.reg_read(UC_X86_REG_DX),'Native returned far pair')
            require(bytes(uc.mem_read(ss*16+sp+4,4))==struct.pack('<HH',offset,result.segment),'Original updated argument copy')
        else:require(result.offset==0xbeef and result.segment==0xdead,'Failure native output mutation')
        expected=bytearray(initial);expected[table:table+900]=bytes(arena.entries)
        expected[0x6c68:0x6c6c]=struct.pack('<HH',table+arena.active_top*18,table+arena.cached_first*18)
        require(bytes(uc.mem_read(ds*16,65536))==bytes(expected),f'FullDS metadata mismatch{total}/{policy}')
        require(bytes(buffer)==bytes(uc.mem_read(origin*16-8,pool_bytes+16)),f'Wholepayload/guards mismatch{total}/{policy}')
        if category=='row48_source_destination_alias' and policy=='shift':
            require(len(moves)==1 and moves[0][1]==moves[0][2] and bytes(buffer)==guard+initial_pool+guard,'Original late-source identity move')
        coverage[policy+'_'+category]+=1;coverage['actual_forward_moves']+=sum(m[0]=='forward' for m in moves);coverage['actual_backward_moves']+=sum(m[0]=='backward' for m in moves);events[policy+('_unknown' if failure[0] else '_normal')]+=1;total+=1
    def snapshot(active,first,gap=None):
        entries=[(rng.randbytes(12),rng.randrange(65536),rng.randrange(65536),rng.randrange(65536)) for _ in range(50)]
        entries[0]=(b'\0'*12,0,origin,2);current=origin
        for index in range(1,active+1):
            size=rng.randrange(1,9);entries[index]=(f'A{index:02}'.encode().ljust(12,b'\0'),size,current,2);current+=size
        current+=rng.randrange(17) if gap is None else gap
        for index in range(first,49):
            size=rng.randrange(1,17);entries[index]=(f'N{index:02}'.encode().ljust(12,b'\0'),size,current,rng.choice([0,1,2,3,0xffff]));current+=size
        entries[49]=(b'\0'*12,0,current,1)
        return entries
    for policy in functions:
        compare(policy,snapshot(0,49),0,49,0xffff,'empty_unknown')
        for active in range(1,49):
            for first in range(active+1,50):
                entries=snapshot(active,first)
                for segment in [entries[active][2],entries[1][2],0xffff]:compare(policy,entries,active,first,segment,'all_boundaries_top_interior_unknown')
        for active in range(1,49):
            entries=snapshot(active,49)
            for index in range(1,active):entries[index]=(entries[index][0],entries[index][1],entries[index][2],0)
            compare(policy,entries,active,49,entries[active][2],'trim_free_predecessors')
        for case in range(512):
            active=rng.randrange(1,49);first=rng.randrange(active+1,50);entries=snapshot(active,first);target=rng.randrange(1,active+1)
            for index in range(1,active):
                if rng.randrange(3)==0:entries[index]=(entries[index][0],entries[index][1],entries[index][2],0)
            compare(policy,entries,active,first,entries[target][2],'varied_active_holes_targets')
        entries=snapshot(2,49);size=entries[1][1];end=entries[2][2]+entries[2][1]
        entries[49]=(entries[49][0],0,end+size,1)
        compare(policy,entries,2,49,entries[1][2],'exact_gap_equals_size')
        entries=snapshot(48,49,gap=7)
        compare(policy,entries,48,49,entries[48][2],'row48_source_destination_alias')
        entries=snapshot(3,49);entries[3]=(entries[3][0],entries[3][1],entries[1][2],2)
        compare(policy,entries,3,49,entries[1][2],'highest_duplicate_segment')
    arena=Arena();arena.cached_first=49;buffer=(ctypes.c_uint8*1)(0);result=FarStorage();extra=0
    for function in functions.values():require(function(ctypes.byref(arena),buffer,1,origin,0,0,ctypes.byref(result))==2,'Native sentinel diagnostic');extra+=1
    result={'schema':1,'function_ids':['FN-EGA-000186','FN-EGA-000187'],'result':'pass','vectors':total,'native_only_diagnostic_cases':extra,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_release.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'validator_dependency':{'path':'tools/validate_cache_allocate.py','sha256':hashlib.sha256((ROOT/'tools/validate_cache_allocate.py').read_bytes()).hexdigest()},
            'original_instructions_executed':instructions[0],'fixture_coverage':dict(coverage),'event_counts':dict(events),
            'coverage':['All active/cache boundary pairs withtop/interior/unknown requests','Free active rows, trimruns, duplicates andvariedoffsets',
                        'Gap equality distinguishesfast andshift policies','Row48 late-source alias preservesoriginal identitycopy',
                        'Actual original forward/backward instructions; wholeDS andsynthetic128KiB payload/guards',
                        'Return/frame/arguments/registers, conditionalES/DF; externalfatal stopsbeforeentry'],
            'limits':'Bounded exclusive synthetic arena/pool prefixes only. Descriptor-boundary aliases preserved ratherthan presumedvalidintegration. Fullcaller preconditions/lifetime/exclusion andexternalfatal cleanup remainopen. No realresource, DOS, codec, rendering/audio orgameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
