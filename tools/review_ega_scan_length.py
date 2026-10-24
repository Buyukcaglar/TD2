"""Pin raw REP scan operands and direct caller candidates."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';raw=image[0x13a80+0x29b4:0x13a80+0x29cf];assert raw.hex()=='558bec8bd78cd88ec08b7e0633c0b9fffff2aef7d149918bfa5dcb'.replace(' ','');md=Cs(CS_ARCH_X86,CS_MODE_16);observations=[{'site':f'13A8:{i.address:04X}','instruction_text':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()} for i in md.disasm(raw,0x29b4)];assert len(observations)==15;graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target']=='13A8:29B4'];record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'flow_ledger':graph,'flow_ledger_sha256':hashlib.sha256((ROOT/graph).read_bytes()).hexdigest(),'facts':['One SS near offset uses current DS through ES=DS. No CLD; incoming DF controls byte scan and word DI wrap.','REPNE SCASB starts CXFFFF/AL0; NOT CX then DEC CX/XCHG yields AX, CX0. Last comparison CF survives NOT/DEC/XCHG.','DX receives incoming DI and restores DI. BP saved in SS; plain far RET consumes four bytes and caller retains argument.','Missing terminator within FFFF scans and last eligible NUL both return AXFFFE, distinguished by CF1/CF0. No host strlen or invented error.'],'limits':'Static byte/operand and direct caller candidate inventory only. Actual caller NUL/bounds/DF/other FLAGS/DS-SS correspondence/writers/lifetime/core and device/session/game/fidelity remain open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers)}))

if __name__=='__main__':main()
