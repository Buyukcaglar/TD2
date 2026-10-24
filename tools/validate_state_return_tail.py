"""Isolate only the EGA state-loop return tail, including its low-memory write.

No game loop, DOS/BIOS call, vector dispatch, port or resource is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh evidence path required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    image_hash=hashlib.sha256(image).hexdigest()
    require(image_hash=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    s,ip,length=0x6c9,0x1bf7,11
    offset=s*16+ip;code=image[offset:offset+length]
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted normalizedMZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    require(not any(offset<=v<offset+length for v in relocs),'Tail has relocations; revise fixture')
    rows=[]
    for load in [0x1000,0x2345]:
        for carry in [0,1]:
            for previous in [0,0x1234,0xffff]:
                uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
                cs,ss,sp=load+s,0x7000,0x8000;start=cs*16+ip
                uc.mem_write(start,code);uc.mem_write(0x86,struct.pack('<H',previous))
                uc.mem_write(ss*16+sp,struct.pack('<HH',0x100,0x8000))
                for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_DS,0x5555),
                                (UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_ES,0x1234),
                                (UC_X86_REG_AX,0xbeef),(UC_X86_REG_EFLAGS,0x202|carry)]:uc.reg_write(reg,val)
                starts={start+i.address-ip for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip)}
                writes=[];executed=[]
                def fetch(u,address,size,_):
                    require(address in starts and address+size<=start+length,'Execution escaped tail')
                    executed.append(address)
                def write(u,access,address,size,value,_):writes.append((address,size,value))
                def interrupt(*_):raise RuntimeError('Unexpected interrupt')
                uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_MEM_WRITE,write);uc.hook_add(UC_HOOK_INTR,interrupt)
                uc.emu_start(start,0x80100,count=8)
                require(writes==[(0x86,2,2)],'Unexpected write')
                require(bytes(uc.mem_read(0x86,2))==struct.pack('<H',2),'Low-memory result')
                require(uc.reg_read(UC_X86_REG_AX)==2 and uc.reg_read(UC_X86_REG_ES)==2,'Return AX/ES')
                require(uc.reg_read(UC_X86_REG_EFLAGS)==0x202,'Flag result')
                require(uc.reg_read(UC_X86_REG_DS)==0x5555 and uc.reg_read(UC_X86_REG_SS)==ss,'Segments')
                require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return')
                rows.append({'load_segment':load,'incoming_cf':carry,'previous_physical0086_word':previous,
                             'ax':2,'es':2,'physical_write':0x86,'write_value':2,'instructions':len(executed)})
    result={'schema':1,'result':'pass','image_sha256':image_hash,'module_offset':offset,'length':length,
            'tail_sha256':hashlib.sha256(code).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'relocations_within_tail':0,'vectors':len(rows),'cases':rows,
            'conclusion':'Tail literallywrites2 tophysical0086,returnsAX2/ES2,clearsCF andfarreturns. These constants are not loader-relocated.',
            'limits':'Only11byte tail executed inisolated memory. Cause, historical patch status, OS-level effect and complete state-loop behavior remain unestablished. No correction admitted.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
