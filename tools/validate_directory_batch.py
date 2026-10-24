"""Compare16EB directory-list callers and actual6E4E/6E59 on synthetic views."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_directory import require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','selector_offset','offset','segment','completed']]+[('comparisons',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_directory_batch;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint32,C.c_uint32,C.POINTER(Result)];native.restype=None
    cases=[]
    for count in [1,2,4,15,32]:
        for size in [0,1,2,7,31]:
            for kind in ['all_found','late_missing','first_missing','padded','repeat']:
                for out in ['separate','current_selector','next_selector','previous_selector','word_ffff','near_wrap','archive_table','archive_count']:
                    cases.append((count,size,kind,out))
    coverage=Counter();vectors=instructions=0;ss,sp=0x9000,0x8000
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x110000);group=load+0x178f;directory_cs=load+0x6c9;batch_cs=load+0x16eb;fatal=(load+0x16a7)*16+2;starts=set();active={}
        for segment,ip,length in [(0x16eb,0xa,132),(0x6c9,0x6e4e,207)]:
            first=segment*16+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write((load+segment)*16+ip,bytes(code));starts.update((load+segment)*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            if address==fatal:
                active['fatal']=True;require(struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0]==0x651a,'Fatal message');u.emu_stop();return
            require(address in starts,'Batch escaped instruction fence');active['instructions']+=1
            if address==directory_cs*16+0x6e88:active['comparisons']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for count,size,kind,out in cases:
            for shared in [False,True]:
                for required in [0,1]:
                    source_segment=group if shared else 0x6000;source_offset=0x5000 if shared else 0x120;selector=0x200
                    source=bytearray(b'\xcc'*65537);g=bytearray(b'\xcc'*65537);archive=g if shared else source
                    struct.pack_into('<H',archive,source_offset+4,count)
                    names=[f'{i:04X}'.encode() for i in range(count)]
                    if kind=='padded':names[0]=b'A\0ZZ'
                    for i,name in enumerate(names):archive[source_offset+6+i*4:source_offset+10+i*4]=name
                    for i in range(count):struct.pack_into('<I',archive,source_offset+6+count*4+i*4,0x100+i*0x11111)
                    for i in range(size):
                        name=names[0] if kind in ['repeat','padded'] else names[i%count]
                        if kind=='padded':name=b'A\0xy'
                        if kind=='first_missing' and i==0 or kind=='late_missing' and i==size-1:name=b'NOPE'
                        g[selector+4*i:selector+4*i+4]=name
                    g[selector+4*size]=0
                    output_at={'separate':0x7000,'current_selector':selector,'next_selector':selector+4,'previous_selector':selector-4,'word_ffff':0xffff,'near_wrap':0xfffe,'archive_table':source_offset+6+count*4,'archive_count':source_offset+4}[out]
                    # When source is separate, these latter output coordinates
                    # are ordinary group writes; shared mode retains aliases.
                    initial_source=bytes(g if shared else source);uc.mem_write(source_segment*16,initial_source);uc.mem_write(group*16,bytes(g));uc.mem_write(ss*16+sp-96,b'\xa5'*96+struct.pack('<6H',0x100,0xa000,source_offset,source_segment,selector,output_at))
                    entry=0xa if required else 0x4c;ax0,dx0=0xbeef,0x3456;df=0x400 if vectors&1 else 0
                    preserved=[(UC_X86_REG_DS,group),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x2345)]
                    for reg,val in preserved+[(UC_X86_REG_CS,batch_cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,ax0),(UC_X86_REG_DX,dx0),(UC_X86_REG_DI,0x1234),(UC_X86_REG_EFLAGS,0x203|df)]:uc.reg_write(reg,val)
                    active.update(fatal=False,instructions=0,comparisons=0);uc.emu_start(batch_cs*16+entry,0xa0100,count=2000000)
                    gb=(C.c_uint8*65537).from_buffer_copy(g);sb=gb if shared else (C.c_uint8*65537).from_buffer_copy(source);result=Result();native(sb,65537,source_segment,source_offset,gb,65537,selector,output_at,required,ax0,dx0,256,40000,C.byref(result))
                    label=f'{load:x}/{count}/{size}/{kind}/{out}/{shared}/{required}'
                    require(result.status==int(active['fatal']),'Status '+label);require(result.comparisons==active['comparisons'],'Comparison count '+label)
                    require(bytes(gb)==bytes(uc.mem_read(group*16,65537)),'Full group '+label);require(bytes(sb)==bytes(uc.mem_read(source_segment*16,65537)),'Full source '+label)
                    require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp+8,2)))[0]==result.selector_offset,'Modified caller selector argument '+label)
                    require(struct.unpack('<H',bytes(uc.mem_read(ss*16+sp-4,2)))[0]==result.completed,'Completed local count '+label)
                    if not active['fatal']:
                        require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Far return '+label)
                        require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label);require(uc.reg_read(UC_X86_REG_DI)==0x1234,'DI '+label)
                        require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX))==(result.offset,result.segment),'Last pair/empty preserved '+label)
                        require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==(df if size==0 else 0),'DF '+label)
                    expected_args=struct.pack('<4H',source_offset,source_segment,result.selector_offset,output_at);require(bytes(uc.mem_read(ss*16+sp+4,8))==expected_args,'Other caller arguments '+label)
                    coverage[out]+=1;coverage['shared_source_'+str(shared)]+=1;coverage['status_'+str(result.status)]+=1;coverage['completed_'+str(result.completed)]+=1;instructions+=active['instructions'];vectors+=1
    record={'schema':1,'function_id':'FN-EGA-000355','covered_original_local_helpers':['FN-EGA-000356'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_directory_batch.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_directory.py','sha256':hashlib.sha256((ROOT/'tools/validate_directory.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete16EB:000A/004C callers with actual directory callees and composed native helper. Serialized synthetic principalDS/group and independentSS, mutable selector/output/source aliases and near/word wrapping; each invoked selector nonwrapping4byte. No supplied archive, resource ownership/IRQ, fatal cleanup, rendering/game/fidelity acceptance. Native bounds/work diagnostics outside original.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
