"""Check initial versus mutator-produced state-return tail bytes in isolation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_AX,UC_X86_REG_EFLAGS


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    trace_path=ROOT/'docs/recovery/evidence/td2ega-main-mutator-validation-v2.json';trace=json.loads(trace_path.read_text())
    require(trace['result']=='pass' and trace['vectors']==1920 and trace['image_sha256']==sha,'Mutator evidence missing')
    modes={'initial_or_rejected':trace['game_control_states']['high_drive_branch']['1BF7'],
           'both_queries_admitted':trace['game_control_states']['low_drive_branch']['1BF7']}
    require(modes=={'initial_or_rejected':0xf8,'both_queries_admitted':0xcb},'Tail-byte modes expanded')
    total=0;counts={};instructions=0
    for load in [0x1000,0x2345]:
        for mode,tail_byte in modes.items():
            uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
            cs=load+0x6c9;ds=load+0x178f;ss=0x7000;sp=0x8000
            code=bytearray(image[0x6c90+0x1bf0:0x6c90+0x1c02]);code[7]=tail_byte
            uc.mem_write(cs*16+0x1bf0,bytes(code));allowed={cs*16+v for v in [0x1bf0,0x1bf3,0x1bf4,0x1bf5,0x1bf6,0x1bf7,0x1bf8,0x1bfb,0x1bfd,0x1c01]}
            fetched=[0];writes=[]
            def fetch(u,address,size,_):require(address in allowed,'Tail escaped instruction fence');fetched[0]+=1
            def write(u,access,address,size,value,_):writes.append((address,size,value))
            def interrupt(*_):raise RuntimeError('Unexpected interrupt')
            uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_MEM_WRITE,write);uc.hook_add(UC_HOOK_INTR,interrupt)
            for state in range(256):
                for carry in [0,1]:
                    uc.mem_write(ds*16+0x5490,bytes([state]));uc.mem_write(0x80,b'\xa5'*6+struct.pack('<H',0xcafe)+b'\xa5'*8)
                    uc.mem_write(ss*16+sp,struct.pack('<HHHHH',0x1111,0x2222,0x3333,0x100,0x8000))
                    for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x1bf0),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),
                                    (UC_X86_REG_AX,0xbeef),(UC_X86_REG_ES,0x6789),(UC_X86_REG_BP,0xabcd),(UC_X86_REG_SI,0xabcd),(UC_X86_REG_DI,0xabcd),(UC_X86_REG_EFLAGS,0x202|carry)]:uc.reg_write(reg,val)
                    writes.clear();uc.emu_start(cs*16+0x1bf0,0x80100,count=32)
                    require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+10,'Tail farreturn/restore frame')
                    require((uc.reg_read(UC_X86_REG_DI),uc.reg_read(UC_X86_REG_SI),uc.reg_read(UC_X86_REG_BP))==(0xabcd,0x1111,0x3333),'SavedSI/BP anduntouchedDI')
                    early=tail_byte==0xcb;expected_ax=state if state<128 else state|0xff00
                    require(uc.reg_read(UC_X86_REG_AX)==(expected_ax if early else 2),'State versusliteralAX result')
                    require(uc.reg_read(UC_X86_REG_ES)==(0x6789 if early else 2) and uc.reg_read(UC_X86_REG_EFLAGS)&1==(carry if early else 0),'TailES/CF effects')
                    require(writes==([] if early else [(0x86,2,2)]),'Conditional low-memory write')
                    expected=b'\xa5'*6+struct.pack('<H',0xcafe if early else 2)+b'\xa5'*8
                    require(bytes(uc.mem_read(0x80,16))==expected and uc.reg_read(UC_X86_REG_DS)==0x2222 and uc.reg_read(UC_X86_REG_SS)==ss,'Lowmemoryguards/restoredDS/SS')
                    total+=1;counts[mode]=counts.get(mode,0)+1
            instructions+=fetched[0]
    result={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'source_mutator_trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),'vectors':total,'cases_by_mode':counts,'original_instructions_executed':instructions,
            'conclusion':'Mutator-admitted RETF at1BF7 returnssignextended5490 byte, preservesentryES/CF anddoesnotwritelow0086. Initial/rejected CLC pathreturnsAX2/ES2/CF0 andwritesword2 atphysical0086. SavedSI/DS/BP, untouchedDI andfarframe checked forall256states, twocarry inputs andtwoloadsegments.',
            'limits':'Isolated18byteepilogue withsyntheticframe/state only; notwhole1B2C, livecaller/BIOS/DOS profile, mutabletransition/interleaving, gameplay orfidelity acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
