"""Audit operand/address prefix widths in the four selected EGA snapshots."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True
    assert 0x66 in next(md.disasm(bytes.fromhex('6698'),0)).prefix and 0x67 in next(md.disasm(bytes.fromhex('678b00'),0)).prefix
    mutable_path='docs/recovery/evidence/td2ega-mutable-control-map-v3.json';mutable=json.loads((ROOT/mutable_path).read_text());assert mutable['result']=='pass';states=[]
    for state in mutable['states']:
        ledger_path=ROOT/state['ledger'];assert hashlib.sha256(ledger_path.read_bytes()).hexdigest()==state['ledger_sha256'];g=json.loads(ledger_path.read_text());data=(ROOT/g['image']).read_bytes();assert hashlib.sha256(data).hexdigest()==g['image_sha256'];seen=set();prefixes=[];wide=[];sign_extensions=[]
        for f in g['functions']:
            segment=int(f['entry'][:4],16)
            for ip in f['instructions']:
                if (segment,ip) in seen:continue
                seen.add((segment,ip));at=segment*16+ip;i=next(md.disasm(data[at:at+15],ip,count=1));site=f'{segment:04X}:{ip:04X}'
                if 0x66 in i.prefix or 0x67 in i.prefix:prefixes.append({'site':site,'encoding':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
                if any(name in i.op_str for name in ['eax','ebx','ecx','edx','esi','edi','ebp','esp']):wide.append({'site':site,'mnemonic':i.mnemonic,'operands':i.op_str})
                if i.mnemonic in ['cwde','cbw','cdq','cwd']:
                    assert len(i.bytes)==1 and i.bytes[0] in [0x98,0x99];sign_extensions.append({'site':site,'opcode':f'{i.bytes[0]:02X}','mnemonic_text':i.mnemonic,'operand_size':16})
        assert not prefixes and not wide
        states.append({'name':state['name'],'ledger':state['ledger'],'ledger_sha256':state['ledger_sha256'],'image_sha256':g['image_sha256'],'instruction_locations':len(seen),'operand_or_address_override_prefixes':prefixes,'explicit_32bit_GPR_operands':wide,'unprefixed_word_sign_extension_sites':sign_extensions})
    image_sha=hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest();deps=['docs/recovery/evidence/td2ega-sign-extension-context-v1.json',mutable_path];record={'schema':1,'result':'pass','image_sha256':image_sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'states':states,'limits':'Fourselectedsyntacticinitial/preparedsnapshot ledgers only. No66/67prefix or explicit32bitGPRoperand observed; unprefixed98/99 decodedunder16bitcontext despiteCapstonesynonymtext. Rawprefixdetector checkedonsyntheticoverrideexamples andsignextensionmicrofixtures separatelypinned. Notallunclassified/unresolvedindirect/mutabletransition code, noGhidraglobalcontext/wholeFLAGS/core/runtime/device/game/fidelity closure. Upperregistereffects outsideadmittedcode stillrequireownreview.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','states':[(s['name'],s['instruction_locations'],len(s['unprefixed_word_sign_extension_sites'])) for s in states]}))

if __name__=='__main__':main()
