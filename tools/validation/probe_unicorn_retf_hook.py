"""Synthetic reproduction of the read-hook/RETF fixture limitation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
import unicorn
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_MEM_READ
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_SS,UC_X86_REG_SP


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence path required')
    cases=[]
    for hook in ['none','low_memory_only','all_memory']:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
        cs,ip,ss,sp=0x16c9,0x0200,0x7000,0x8000
        # Independently authored fixture: MOV AX,1234h; RETF.
        uc.mem_write(cs*16+ip,bytes.fromhex('b83412cb'))
        uc.mem_write(ss*16+sp,struct.pack('<HH',0x100,0x8000))
        for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp)]:uc.reg_write(reg,value)
        seen=[]
        def read(u,access,address,size,value,_):seen.append({'address':address,'size':size})
        if hook=='low_memory_only':uc.hook_add(UC_HOOK_MEM_READ,read,begin=0,end=0xffff)
        if hook=='all_memory':uc.hook_add(UC_HOOK_MEM_READ,read)
        uc.emu_start(cs*16+ip,0x80100,count=2)
        actual={'cs':uc.reg_read(UC_X86_REG_CS),'ip':uc.reg_read(UC_X86_REG_IP),'sp':uc.reg_read(UC_X86_REG_SP)}
        correct=actual=={'cs':0x8000,'ip':0x100,'sp':sp+4}
        cases.append({'hook':hook,'correct_return':correct,'actual':actual,'callback_reads':seen})
    if not all(c['correct_return'] for c in cases[:2]):raise RuntimeError('Unhooked/restricted-hook fixture failed')
    result={'schema':1,'unicorn_version':unicorn.__version__,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'result':'tool_limitation_reproduced' if not cases[2]['correct_return'] else 'not_reproduced',
            'cases':cases,'scope':'SyntheticMOV/RETF only; no original instructions/data or DOS execution.',
            'workaround':'Accepted external-word fixture restricts read callbacks tolow64KiB and verifies finalCS/IP/SP. This does not validate unhooked full-system emulation.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
