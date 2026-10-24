"""Disambiguate98/99 widths from raw bytes and full-register microfixtures."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
import capstone
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
import unicorn
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16
from unicorn.x86_const import *

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';assert image[0x16aa0+0x15:0x16aa0+0x1b]==bytes.fromhex('8a4606985dcb');md=Cs(CS_ARCH_X86,CS_MODE_16);decodes=[];vectors=[]
    for code in [bytes.fromhex(x) for x in ['98','6698','99','6699']]:
        i=next(md.disasm(code,0x100));assert i.size==len(code);decodes.append({'encoding':code.hex(),'mnemonic':i.mnemonic,'instruction_bytes':i.size})
    for original,encoding,eax,flags in itertools.product([False,True],['98','6698','99','6699'],[0xa5a51280,0x8123807f,0x7fff0080,0x1234007f],[2,0x8d7,0x603]):
        if original and encoding!='98':continue
        code=bytes.fromhex(encoding);edx=0xb6b61234;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000)
        if original:
            load=0x1000;segment=load+0x16aa;ip=0x18;u.mem_write(load*16,image)
        else:segment=0x1000;ip=0x100;u.mem_write(segment*16+ip,code)
        u.reg_write(UC_X86_REG_CS,segment);u.reg_write(UC_X86_REG_IP,ip);u.reg_write(UC_X86_REG_EAX,eax);u.reg_write(UC_X86_REG_EDX,edx);u.reg_write(UC_X86_REG_EFLAGS,flags);initial_flags=u.reg_read(UC_X86_REG_EFLAGS);u.emu_start(segment*16+ip,segment*16+ip+len(code),count=1)
        expected_eax,expected_edx=eax,edx
        if encoding=='98':al=eax&255;expected_eax=(eax&0xffff0000)|(al if al<128 else 0xff00|al)
        elif encoding=='6698':ax=eax&65535;expected_eax=ax if ax<0x8000 else 0xffff0000|ax
        elif encoding=='99':expected_edx=(edx&0xffff0000)|(0xffff if eax&0x8000 else 0)
        else:expected_edx=0xffffffff if eax&0x80000000 else 0
        observed=(u.reg_read(UC_X86_REG_EAX),u.reg_read(UC_X86_REG_EDX),u.reg_read(UC_X86_REG_EFLAGS));assert observed==(expected_eax,expected_edx,initial_flags),(original,encoding,hex(eax),observed)
        vectors.append({'source':'originalFN42198' if original else 'syntheticISAbytes','encoding':encoding,'initial_EAX':eax,'initial_EDX':edx,'EAX':observed[0],'EDX':observed[1],'flags_unchanged':True})
    assert len(vectors)==60
    reference='docs/recovery/evidence/intel-sign-extension-reference-v1.json';record={'schema':1,'result':'pass','vectors':len(vectors),'image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':reference,'sha256':hashlib.sha256((ROOT/reference).read_bytes()).hexdigest()}],'tools':{'capstone':capstone.__version__,'unicorn':unicorn.__version__},'capstone_16bit_decodes':decodes,'original_site':{'entry':'16AA:0002','instruction':'16AA:0018','module_offset':0x16aa0+0x18,'unprefixed_opcode':'98','operand_size':16,'effect':'AXsignextendsAL, upperEAXpreserved; noflagsmodified.'},'microfixture_results':vectors,'limits':'48synthetic98/6698/99/6699 single-instruction fixtures and12executions oforiginalFN421unprefixed98 withfullEAX/EDX/FLAGSchecked. Originalbyteimage copiedtoasynthload withoutrelocation-dependentoperands forpure98. Capstonemnemonic alone insufficientforwidth; primaryIntelreference separatelyread. NotphysicalCPU/historicaltiming/DOS/game/fidelity acceptance, notanativehelper-suite orwholeFN421contract. Allotheroperands/callers needtheirown byte/semanticreview.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':len(vectors),'original98_operand_size':16,'decodes':decodes}))

if __name__=='__main__':main()
