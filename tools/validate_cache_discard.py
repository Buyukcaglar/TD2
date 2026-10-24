"""Compare original7490 metadata prefix to native discard; synthetic data only."""
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
    load=0x1000;cs,ds,ss,sp=0x16c9,0x5000,0x7000,0x8000;fatal=(load+0x16a7)*16+2
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    offset,length=0x6c90+0x7490,68;code=bytearray(image[offset:offset+length])
    for r in relocs:
        if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
    uc.mem_write(cs*16+0x7490,bytes(code));starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x7490)}
    instructions=[0];event=[0];events=Counter();total=0
    def fetch(u,address,size,_):
        if address==fatal:
            require(struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0]==0x65a5,'Fatal message')
            event[0]=1;u.emu_stop();return
        require(address in starts,'Discard escaped instruction fence');instructions[0]+=1
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));discard=dll.td2ega_cache_discard
    discard.argtypes=[ctypes.POINTER(Arena),ctypes.c_uint16];discard.restype=ctypes.c_int
    require(ctypes.sizeof(Entry)==18 and ctypes.sizeof(Arena)==904,'Metadata validation ABI')
    rng=random.Random(0x7490);table=0x68e2
    def compare(entries,active,segment):
        nonlocal total
        packed=b''.join(struct.pack('<12sHHH',name,size,seg,status) for name,size,seg,status in entries)
        initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed
        initial[0x6c66:0x6c6e]=struct.pack('<HHHH',table,table+active*18,table+49*18,table+49*18)
        uc.mem_write(ds*16,bytes(initial));ignored_offset=(total*257)&65535
        uc.mem_write(ss*16+sp,struct.pack('<HHHH',0x100,0x8000,ignored_offset,segment))
        for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7490),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                        (UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_BP,0x5678),
                        (UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        event[0]=0;uc.emu_start(cs*16+0x7490,0x80100,count=1024)
        if event[0]==0:
            require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Normal far return')
            require(uc.reg_read(UC_X86_REG_AX)==segment,'Original AX segment')
            require(all(uc.reg_read(reg)==val for reg,val in [(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_ES,0x6789),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_DX,0x3456)]),'Normal preserved registers')
            require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0x400,'Discard does not clear DF')
        else:
            require(struct.unpack('<H',bytes(uc.mem_read(ss*16+uc.reg_read(UC_X86_REG_SP)+6,2)))[0]==segment,'Failure segment argument')
        arena=Arena.from_buffer_copy(packed+struct.pack('<HH',active,49))
        native=discard(ctypes.byref(arena),segment);require(native==event[0],f'Event mismatch{total}')
        expected=bytearray(initial);expected[table:table+900]=bytes(arena.entries)
        expected[0x6c68:0x6c6a]=struct.pack('<H',table+arena.active_top*18)
        require(arena.cached_first==49 and bytes(uc.mem_read(ds*16,65536))==bytes(expected),f'FullDS metadata mismatch{total}')
        require(bytes(uc.mem_read(ss*16+sp+4,4))==struct.pack('<HH',ignored_offset,segment),'Caller argument words changed')
        events[str(native)]+=1;total+=1
    def snapshot(active):
        entries=[(bytes(rng.randrange(256) for _ in range(12)),rng.randrange(65536),(0x6000+i*3)&65535,rng.choice([0,1,2,3,0xffff])) for i in range(50)]
        entries[0]=(entries[0][0],0,0x6000,2)
        if active:entries[active]=(entries[active][0],entries[active][1],entries[active][2],2)
        return entries
    for active in range(49):
        entries=snapshot(active)
        for target in range(50):compare(entries,active,entries[target][2])
        for holes in range(active):
            changed=list(entries)
            for index in range(holes+1,active):changed[index]=(changed[index][0],changed[index][1],changed[index][2],0)
            compare(changed,active,entries[active][2])
        if active>1:
            duplicate=list(entries);duplicate[active]=(duplicate[active][0],duplicate[active][1],duplicate[1][2],2)
            compare(duplicate,active,duplicate[1][2])
    entries=snapshot(3)
    for segment in range(65536):compare(entries,3,segment)
    arena=Arena();arena.entries[0].status=2;arena.active_top=49
    require(discard(ctypes.byref(arena),0)==2,'Native active boundary diagnostic')
    arena.active_top=0;arena.entries[0].status=0
    require(discard(ctypes.byref(arena),0)==2,'Native sentinel diagnostic')
    records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    fn=next(r['id'] for r in records if r['entries'][0]['segment']==0x6c9 and r['entries'][0]['segment_offset']==0x7490)
    result={'schema':1,'function_id':fn,'result':'pass','vectors':total,'native_only_diagnostic_cases':2,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_range':{'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()},
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_cache_discard.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'validator_dependency':{'path':'tools/validate_cache_allocate.py','sha256':hashlib.sha256((ROOT/'tools/validate_cache_allocate.py').read_bytes()).hexdigest()},
            'original_instructions_executed':instructions[0],'event_counts':dict(events),
            'coverage':['All active-boundary and target-row pairs','Trim over every run of free predecessors','Highest duplicate segment selected, free row still searchable',
                        'Every uint16 segment request on fixed three-row arena','Whole synthetic DS64KiB, ignoredoffset, arguments, AX, preserved registers and unchanged DF'],
            'limits':'Nonzero leftsentinel andbounded disjoint stable50row metadata arena. Externalfatal handler notexecuted. No payloadmove, cachelifetime, DOS, codec, real resource or gameplay acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
