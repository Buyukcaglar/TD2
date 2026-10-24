"""Compare native6B02 run/block stage to original code on synthetic RAM pools."""
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Result(ctypes.Structure):
    _fields_=[('offset',ctypes.c_uint16),('segment',ctypes.c_uint16),('source_argument_offset',ctypes.c_uint16),('source_argument_segment',ctypes.c_uint16),
              ('first_stage_reported_bytes',ctypes.c_uint32),('first_stage_writes',ctypes.c_uint32),('final_stage_writes',ctypes.c_uint32)]


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
    load=0x1000;cs,group,sp=0x16c9,0x5000,0xe000;origin=0x6000;destination_segment=0x6000;pool_bytes=0x40000
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    starts=set();spans=[];instructions=[0];phase=['header'];write_counts=Counter();first_reported=[0];coverage=Counter();total=0
    for ip,length in [(0x6b02,534),(0x7030,83)]:
        offset=0x6c90+ip;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        spans.append({'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(image[offset:offset+length]).hexdigest()})
    def fetch(u,address,size,_):
        require(address in starts,'Run stage escaped instruction fence');instructions[0]+=1
        if address==cs*16+0x6c6e:phase[0]='block'
        elif address==cs*16+0x7030:phase[0]='move'
        elif address==cs*16+0x6b97:phase[0]='run'
        elif address in (cs*16+0x6c74,cs*16+0x6cd7):first_reported[0]=(u.reg_read(UC_X86_REG_DX)<<16)|u.reg_read(UC_X86_REG_AX)
    def memory_write(u,access,address,size,value,_):
        if origin*16<=address and address+size<=origin*16+pool_bytes:write_counts[phase[0]]+=size
        else:require(group*16+sp-0x1000<=address and address+size<=group*16+sp+14,'Write outside pool or admitted stack frame')
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_MEM_WRITE,memory_write);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));stage=dll.td2ega_run_stage
    stage.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint16,ctypes.c_uint32,ctypes.POINTER(Result)];stage.restype=ctypes.c_int
    rng=random.Random(0x6b02);guard=b'\xa5'*8
    def compare(control,markers,body,declared,category,allocation=0x400,source_segment=0x8000,source_offset=0x120,encoded=None,zero_pool=False):
        nonlocal total
        encoded=len(body) if encoded is None else encoded
        raw=b'\x01'+declared.to_bytes(3,'little')+encoded.to_bytes(4,'little')+bytes([control])+bytes(markers)+bytes(body)
        at=source_segment*16+source_offset-origin*16
        require(0<=at and at+max(20,len(raw))<pool_bytes,'Synthetic source/pool bounds')
        initial=bytearray(bytes([0 if zero_pool else 0xcc])*pool_bytes);initial[at:at+len(raw)]=raw
        uc.mem_write(origin*16-8,guard+bytes(initial)+guard)
        uc.mem_write(group*16+sp-0x1000,b'\xa5'*0x100e)
        args=struct.pack('<HHHHHHH',0x100,0xc000,source_offset,source_segment,0x1234,destination_segment,allocation)
        uc.mem_write(group*16+sp,args)
        preserved=[(UC_X86_REG_DS,group),(UC_X86_REG_SS,group),(UC_X86_REG_BP,0x3333),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6b02),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        phase[0]='header';write_counts.clear();first_reported[0]=0
        uc.emu_start(cs*16+0x6b02,0xc0100,count=20000000)
        require(uc.reg_read(UC_X86_REG_CS)==0xc000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved run-stage registers/segments')
        require(uc.reg_read(UC_X86_REG_AX)==0 and uc.reg_read(UC_X86_REG_DX)==destination_segment and uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'Farpointer/DF return')
        buffer=(ctypes.c_uint8*(pool_bytes+16)).from_buffer_copy(guard+bytes(initial)+guard);result=Result()
        status=stage(ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8)),pool_bytes,origin,source_offset,source_segment,destination_segment,allocation,8000000,ctypes.byref(result))
        require(status==0,f'Native rejected bounded fixture{total}/{category},status{status}')
        require(bytes(buffer)==bytes(uc.mem_read(origin*16-8,pool_bytes+16)),f'Wholepool/guards mismatch{total}/{category}')
        original_source_offset,original_source_segment=struct.unpack('<HH',bytes(uc.mem_read(group*16+sp+4,4)))
        require((result.offset,result.segment)==(0,destination_segment) and (result.source_argument_offset,result.source_argument_segment)==(original_source_offset,original_source_segment),'Farpointer/argument-copy observations')
        require(bytes(uc.mem_read(group*16+sp+8,6))==args[8:],'Other argument words changed')
        require(result.first_stage_reported_bytes==first_reported[0] and result.first_stage_writes==write_counts['block'] and result.final_stage_writes==write_counts['run'],'Original byte-write/count observations')
        if category=='control1_early_return_count':require(result.first_stage_reported_bytes==65536 and result.first_stage_writes==0 and result.final_stage_writes==131072,'Control1 counter edge')
        if category=='run_wrap_rewrites_start':require(bytes(buffer[8:9])==b'R' and result.final_stage_writes==65537,'REP wrap identity')
        coverage[category]+=1;coverage['block_byte_writes']+=write_counts['block'];coverage['run_byte_writes']+=write_counts['run'];coverage['paragraph_move_bytes']+=write_counts['move'];total+=1
    for byte in range(256):
        marker=byte^255
        compare(0x81,[marker],bytes([byte])*7,7,'all_literal_bytes')
        compare(0x81,[marker],bytes([marker,5,byte]),5,'all_run_value_bytes')
    markers=[0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5]
    for count in range(1,12):
        for rank in range(1,count+1):
            marker=markers[rank-1]
            if rank==1:body=bytes([marker,9,0x41]);declared=9
            elif rank==3:body=bytes([marker,0x34,0x12,0x41]);declared=0x1234
            else:body=bytes([marker,0x41]);declared=rank-1
            compare(0x80|count,markers[:count],body,declared,'all_marker_ranks')
    compare(0x84,[0xff,0xfe,0xfd,0xff],b'\xffA',3,'duplicate_marker_last_rank')
    for repeat in [0,1,2,3,255]:
        compare(3,markers[:3],b'\xfeAB\xfe'+bytes([repeat]),2*(repeat if repeat>=2 else 256 if repeat==0 else 257),'block_repeat_counter_edges')
    compare(3,markers[:3],b'X\xfeAB\xfe\x03Y',8,'block_with_outer_literals')
    compare(0x83,markers[:3],b'\xfd\0\0A',0,'zero_length_run')
    compare(0x81,markers[:1],b'\xff\0A',0,'zero_length_short_run')
    compare(0x83,markers[:3],b'Z\xfd\xff\xffQR',65537,'run_wrap_rewrites_start')
    compare(0x83,markers[:3],b'\xfd\xff\xffQR',65536,'run_normalizes_after_large_copy')
    compare(0x81,markers[:1],b'A'*40,40,'source_32KiB_threshold',source_offset=0x7ff0)
    compare(0x81,markers[:1],b'A'*131072,65536,'literal_counter_lowword_zero',source_segment=0x7000,encoded=65536)
    compare(1,[0xff],b'',1,'control1_early_return_count',allocation=0x2000,source_segment=0x9000,zero_pool=True)
    for case in range(256):
        marker=rng.randrange(128,256);body=bytearray();decoded=0
        for token in range(rng.randrange(1,32)):
            if rng.randrange(3)==0:
                count=rng.randrange(256);value=rng.randrange(128);body.extend([marker,count,value]);decoded+=count
            else:body.append(rng.randrange(128));decoded+=1
        compare(0x81,[marker],body,decoded,'varied_literal_run_streams')
    # Native-only bounded diagnostics, not original malformed-input behavior.
    buffer=(ctypes.c_uint8*64)();result=Result();extra=0
    for source_segment,work,expected_status in [(origin,0,3),(origin-1,100,2),(origin,100,1)]:
        require(stage(buffer,64,origin,0,source_segment,origin,1,work,ctypes.byref(result))==expected_status,'Native bounds/profile/work diagnostic');extra+=1
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    fn=next(r['id'] for r in registry if r['entries'][0]['segment']==0x6c9 and r['entries'][0]['segment_offset']==0x6b02)
    result={'schema':1,'function_id':fn,'result':'pass','vectors':total,'native_only_diagnostic_cases':extra,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_run_stage.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions[0],
            'fixture_coverage':dict(coverage),
            'coverage':['All256 literal/runvalue bytes','Allmarker counts1..11/ranks andduplicate overwrite','Block repetition including0/1 do-while edges withactual7030 moves',
                        'Zero runs,65535-byte REP wrap and32KiB rebasing','Literalcounter lowwordzero andcontrol1 early-return count',
                        '256 varied streams','Whole synthetic256KiB pool/guards, byte-write counts, farframe/registers andupdatedsource argument copies'],
            'limits':'Bounded exclusive ordinary-memory synthetic profile withDS=SS andmarker counts1..11 only. Larger marker lists readpastcopiedheader intooriginalstack; nativeprofile diagnostic doesnotadmitthatbehavior. Nativebounds/work diagnostics outsideoriginalerror equivalence. No suppliedresource, fullformat/corpus, completecaller allocation, realDOS, renderer/audio orgameplay/fidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
