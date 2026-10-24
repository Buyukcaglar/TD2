"""Compare compiled7C16 stage with original instructions using synthetic codes."""
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


class Result(ctypes.Structure):
    _fields_=[('reported_bytes',ctypes.c_uint32),('written_bytes',ctypes.c_uint32),('consumed_bytes',ctypes.c_uint32)]


def packet(counts,symbols,indices,reported,delta):
    codes=[];code=0;cursor=0
    for depth,count in enumerate(counts,1):
        code*=2
        codes.extend((code+index,depth) for index in range(count))
        code+=count;cursor+=count
    require(cursor==len(symbols),'Synthetic symbol count')
    bits=[]
    for index in indices:
        value,depth=codes[index];bits.extend((value>>shift)&1 for shift in range(depth-1,-1,-1))
    encoded=bytearray((len(bits)+7)//8)
    for index,bit in enumerate(bits):encoded[index//8]|=bit<<(index%8)
    return b'\x02'+reported.to_bytes(3,'little')+bytes([len(counts)|(0x80 if delta else 0)])+bytes(counts)+bytes(symbols)+bytes(encoded)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();library=a.library.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    require(library.is_relative_to(ROOT/'analysis'),'Private library required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
    cs,ss,sp=0x2000,0xb000,0x8000;source_segment=0x5000;destination_segment=0x8000
    offset,length=0x6c90+0x7c16,328;code=image[offset:offset+length]
    uc.mem_write(cs*16+0x7c16,code);starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x7c16)}
    instructions=[0];last_read=[0];coverage=Counter();total=0;written_total=0
    def fetch(u,address,size,_):
        require(address in starts,'Prefix stage escaped instruction fence');instructions[0]+=1
        if address in (cs*16+0x7ce5,cs*16+0x7d49):last_read[0]=u.reg_read(UC_X86_REG_DS)*16+u.reg_read(UC_X86_REG_SI)
    def interrupt(*_):raise RuntimeError('Unexpected interrupt')
    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
    dll=ctypes.CDLL(str(library));stage=dll.td2ega_prefix_stage
    stage.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.POINTER(Result)];stage.restype=ctypes.c_int
    rng=random.Random(0x7c16);guard=b'\xa5'*8
    def compare(raw,category,source_offset=0x120,destination_offset=0,alias=False):
        nonlocal total,written_total
        reported=int.from_bytes(raw[1:4],'little');written=reported+(65536 if reported&65535==0 else 0)
        src_segment=destination_segment if alias else source_segment
        source_at=src_segment*16+source_offset;destination_at=destination_segment*16+destination_offset
        require(source_offset+5+(raw[4]&127)+sum(raw[5:5+(raw[4]&127)])<=65536,'Header/table prefix wraps')
        require(destination_at+written+8<ss*16+sp-0x100,'Destination/frame overlap')
        if alias:
            begin=min(source_at,destination_at);end=max(source_at+len(raw),destination_at+written)
            initial=bytearray(b'\xcc'*(end-begin));initial[source_at-begin:source_at-begin+len(raw)]=raw
            uc.mem_write(begin-8,guard+bytes(initial)+guard)
            buffer=(ctypes.c_uint8*(len(initial)+16)).from_buffer_copy(guard+bytes(initial)+guard)
            native_source=ctypes.cast(ctypes.byref(buffer,8+source_at-begin),ctypes.POINTER(ctypes.c_uint8));native_destination=ctypes.cast(ctypes.byref(buffer,8+destination_at-begin),ctypes.POINTER(ctypes.c_uint8))
        else:
            uc.mem_write(source_at-8,guard+raw+guard);uc.mem_write(destination_at-8,guard+b'\xcc'*written+guard)
            source=(ctypes.c_uint8*(len(raw)+16)).from_buffer_copy(guard+raw+guard)
            buffer=(ctypes.c_uint8*(written+16)).from_buffer_copy(guard+b'\xcc'*written+guard)
            native_source=ctypes.cast(ctypes.byref(source,8),ctypes.POINTER(ctypes.c_uint8));native_destination=ctypes.cast(ctypes.byref(buffer,8),ctypes.POINTER(ctypes.c_uint8))
        uc.mem_write(cs*16+0x7ad6-8,guard+b'\0'*0x140)
        args=struct.pack('<HHHHHHH',0x100,0xc000,source_offset,src_segment,destination_offset,destination_segment,0x1234)
        uc.mem_write(ss*16+sp,args)
        preserved=[(UC_X86_REG_DS,0x278f),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x3333),(UC_X86_REG_SI,0xbeef),(UC_X86_REG_DI,0xabcd)]
        for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7c16),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x3456),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
        last_read[0]=0;uc.emu_start(cs*16+0x7c16,0xc0100,count=written*180+65536)
        require(uc.reg_read(UC_X86_REG_CS)==0xc000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
        require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers/segments')
        require(uc.reg_read(UC_X86_REG_AX)==reported&65535 and uc.reg_read(UC_X86_REG_DX)==reported>>16,'Declared count return')
        require(uc.reg_read(UC_X86_REG_ES)==destination_segment+((destination_offset+written)//65536)*0x1000 and uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'Destination segment/DF effect')
        require(bytes(uc.mem_read(ss*16+sp+4,10))==args[4:],'Outer arguments changed')
        result=Result();status=stage(native_source,len(raw),native_destination,written,ctypes.byref(result))
        require(status==0 and result.reported_bytes==reported and result.written_bytes==written and result.consumed_bytes==last_read[0]-source_at+1,'Native count/consumption/status mismatch')
        if alias:require(bytes(buffer)==bytes(uc.mem_read(begin-8,len(initial)+16)),'Aliased whole storage mismatch')
        else:
            require(bytes(buffer)==bytes(uc.mem_read(destination_at-8,written+16)),'Whole destination/guards mismatch')
            require(bytes(source)==guard+raw+guard and bytes(uc.mem_read(source_at-8,len(raw)+16))==guard+raw+guard,'Input source/guards changed')
        require(bytes(uc.mem_read(cs*16+0x7ad6-8,8))==guard and bytes(uc.mem_read(cs*16+0x7c16,len(code)))==code,'Scratch boundary/code changed')
        total+=1;written_total+=written;coverage[category]+=1
    for byte in range(256):
        for delta in [False,True]:
            raw=packet([2],[byte,byte^255],[0,1,0,1,1,0,1,0,1],9,delta)
            compare(raw,'all_symbol_bytes_delta',0 if byte&1 else 0xff00,0x1234 if byte&2 else 0)
    for depth in list(range(1,9))+[16]:
        count=(1<<depth) if depth<8 else 255 if depth==8 else 1
        counts=[0]*(depth-1)+[count];symbols=list(range(count))
        for delta in [False,True]:
            indices=[rng.randrange(count) for _ in range(257)]
            compare(packet(counts,symbols,indices,257,delta),'fixed_depth_tables',0xfe00 if count==255 else 0xff00)
    for counts,allowed_symbols in [([1,1,1,1,1,1,1,2],9),([0]*7+[254,2],256),([1]*15+[2],15)]:
        symbols=list(range(sum(counts)))
        for delta in [False,True]:
            indices=[rng.randrange(allowed_symbols) for _ in range(513)]
            compare(packet(counts,symbols,indices,513,delta),'mixed_depth_and16bit_threshold',0xfe00)
    for case in range(256):
        depth=rng.randrange(1,8);count=1<<depth;counts=[0]*(depth-1)+[count];symbols=list(rng.randbytes(count));size=rng.randrange(1,1025)
        compare(packet(counts,symbols,[rng.randrange(count) for _ in range(size)],size,case&1),'varied_tables_streams',0x120,0xfff0 if case&2 else 0)
    for reported in [0,65536]:
        for delta in [False,True]:
            actual=reported+65536;indices=[index&1 for index in range(actual)]
            compare(packet([2],[1,255],indices,reported,delta),'zero_lowword_extra65536',0xff00,0xfff0)
    compare(packet([2],[0x41,0x42],[index&1 for index in range(128)],128,False),'inplace_unread_input_overlap',64,0,True)
    extra=0
    for raw,dst_bytes,expected_status in [(b'',1,2),(b'\2\1\0\0\0',1,1),(b'\2\1\0\0\x11',1,1),
      (b'\2\1\0\0\1',1,2),(b'\2\1\0\0\2\xff\xff',1,1),
      (b'\2\1\0\0\1\1A\0',0,3),(b'\2\1\0\0\1\1A',1,2),(b'\2\1\0\0\1\1A\1',1,1)]:
        source=(ctypes.c_uint8*max(1,len(raw))).from_buffer_copy(raw or b'\0');destination=(ctypes.c_uint8*1)(0xcc);result=Result()
        require(stage(source,len(raw),destination,dst_bytes,ctypes.byref(result))==expected_status,'Native diagnostic status');extra+=1
    result={'schema':1,'function_id':'FN-EGA-000205','result':'pass','vectors':total,'native_only_diagnostic_cases':extra,
            'image_sha256':hashlib.sha256(image).hexdigest(),'executed_range':{'module_offset':offset,'length':length,'unrelocated_sha256':hashlib.sha256(code).hexdigest()},
            'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_prefix_stage.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions[0],
            'synthetic_output_bytes_compared':written_total,'fixture_coverage':dict(coverage),
            'coverage':['All256 bytevalues withdelta on/off','Fixeddepth1..8/16 andmixedtables including256symbols/16bit thresholdwrap',
                        '256 varied tables/streams','Near-source streamwrap anddestination64KiB crossings',
                        'Declared lowword0 writesextra65536 while returningdeclaredcount','Aliased input/output preservesunread-input overwrite order',
                        'Wholebytes/guards, sourceconsumption, scratch/codebounds, farreturn/arguments/registers/ES/DF'],
            'limits':'Bounded synthetic valid-code streams only; nativeinvalid/short diagnostics areoutsideoriginalerror equivalence. No suppliedresource decoded, fullformat/corpus orloader acceptance, sharedscratch reentry, realDOS, renderer/audio orgameplay/fidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
