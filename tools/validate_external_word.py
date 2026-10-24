"""Fence the two anomalous EGA word readers; no DOS/device/game execution."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def require(test, message):
    if not test:
        raise RuntimeError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    require(out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(), 'Fresh evidence path required')
    data = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(digest == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted normalizedMZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    reloc={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    require(not any(0x6c90+v in reloc for v in (0x5d84,0x5d8a,0x5d91,0x5d97)),'Reader constants are relocations; revise fixture')
    rows = []
    for load in [0x1000, 0x2345]:
        for ip, length, delta in [(0x5d83,10,False),(0x5d8d,17,True)]:
            code = data[0x6c9*16+ip:0x6c9*16+ip+length]
            cs, ss, sp = load+0x6c9, 0x7000, 0x8000
            start, stop = cs*16+ip, cs*16+ip+length
            return_cs, return_ip = 0x8000, 0x0100
            boundaries = {start+i.address-ip for i in Cs(CS_ARCH_X86, CS_MODE_16).disasm(code, ip)}
            for observed in [0,1,0x7fff,0x8000,0xffff]:
                for argument in ([0,1,0x7fff,0x8000,0xffff] if delta else [0]):
                    uc = Uc(UC_ARCH_X86,UC_MODE_16)
                    uc.mem_map(0,0x100000)
                    uc.mem_write(start,code)
                    # Distinct sentinels ensure the conventional physical 046Ch
                    # cannot accidentally satisfy the anomalous read result.
                    uc.mem_write(0x46c,struct.pack('<H', observed ^ 0x5a5a))
                    uc.mem_write(0x86c,struct.pack('<H', observed))
                    uc.mem_write(ss*16+sp,struct.pack('<HHH',return_ip,return_cs,argument))
                    for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_DS,0x5555),
                                    (UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0xbeef),
                                    (UC_X86_REG_ES,0x1234),(UC_X86_REG_EFLAGS,0x202)]:
                        uc.reg_write(reg,val)
                    reads, writes, executed = [], [], []
                    def fetch(u,a,n,_):
                        require(a in boundaries and a+n<=stop,f'Instruction escaped fence: {a:x}+{n}, expected {start:x}..{stop:x}, case={load:x},{ip:x},{observed:x},{argument:x}, reads={reads}')
                        executed.append(a)
                    def read(u,access,a,n,value,_): reads.append((a,n))
                    def write(u,access,a,n,value,_): writes.append((a,n))
                    def intr(*_): raise RuntimeError('Unexpected interrupt')
                    uc.hook_add(UC_HOOK_CODE,fetch)
                    # Unicorn2.1.4's read callback on RETF stack reads changes
                    # observed IP in this fixture. Observe only low external
                    # memory; verify the far frame through final CS/IP/SP.
                    uc.hook_add(UC_HOOK_MEM_READ,read,begin=0,end=0xffff)
                    uc.hook_add(UC_HOOK_MEM_WRITE,write)
                    uc.hook_add(UC_HOOK_INTR,intr)
                    uc.emu_start(start,return_cs*16+return_ip,count=16)
                    expected = (observed-argument)&65535 if delta else observed
                    require(uc.reg_read(UC_X86_REG_AX)==expected,'AX mismatch')
                    require((0x86c,2) in reads and not any(a==0x46c for a,n in reads),'Wrong external read')
                    require(reads==[(0x86c,2)],'Unexpected low-memory read')
                    require(writes==([(ss*16+sp-2,2)] if delta else []),'Unexpected write')
                    require(uc.reg_read(UC_X86_REG_ES)==0x40,'ES postcondition')
                    require(uc.reg_read(UC_X86_REG_DS)==0x5555 and uc.reg_read(UC_X86_REG_SS)==ss,'Segment preservation')
                    require(uc.reg_read(UC_X86_REG_BP)==0xbeef,'BP preservation')
                    require(uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/caller argument cleanup')
                    require(uc.reg_read(UC_X86_REG_CS)==return_cs and uc.reg_read(UC_X86_REG_IP)==return_ip,'Return target')
                    rows.append({'load_segment':load,'entry':f'06C9:{ip:04X}','external_word':observed,
                                 'argument':argument,'ax':expected,'external_read_physical':0x86c,
                                 'instructions':len(executed)})
    result={'schema':1,'result':'pass','method':'Fenced isolated Unicorn16 instruction execution with distinct physical046C/086C sentinels',
            'image_sha256':digest,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'vectors':len(rows),'cases':rows,
            'segment_and_displacement_fields_are_nonrelocated_literals':True,
            'conclusion':'Both supplied readers access0040:046C, physical086C, independently of application load segment. Difference reader subtracts caller word modulo65536.',
            'return_fixture':'Distinct8000:0100 sentinel; execution stops before sentinel instructions. Read hooks restricted to low64KiB; finalCS/IP/SP verify return. Unrestricted Unicorn2.1.4 read callbacks on RETF stack reads disturbed observedIP in the initial fixture.',
            'limits':'No DOS/BIOS session, firmware contents, timebase, timer cadence or original historical defect cause established. No offset correction admitted.'}
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':
    main()
