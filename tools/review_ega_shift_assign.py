"""Check near-pointer load/store order and literal RETF-immediate cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';md=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x2fd3:'mov bx, word ptr [bp + 6]',0x2fd6:'mov ax, word ptr [bx]',0x2fd8:'mov dx, word ptr [bx + 2]',0x2fdb:'mov cx, word ptr [bp + 8]',0x2fde:'lcall 0x13a8, 0x2fc4',0x2fe3:'mov bx, word ptr [bp + 6]',0x2fe6:'mov word ptr [bx], ax',0x2fe8:'mov word ptr [bx + 2], dx',0x2feb:'mov sp, bp',0x2fee:'retf 4',0x2fc4:'xor ch, ch',0x2fc6:'jcxz 0x2fce',0x2fc8:'shl ax, 1',0x2fca:'rcl dx, 1',0x2fcc:'loop 0x2fc8',0x2fce:'retf '};observations=[]
    for ip,text in expected.items():
        at=0x13a80+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'13A8:{ip:04X}','instruction':text.strip()})
    assert image[0x13a80+0x2fee:0x13a80+0x2fee+3]==bytes([0xca,4,0])
    graph_path='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph_path).read_text());callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target']=='13A8:2FD0'];record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'flow_ledger':graph_path,'flow_ledger_sha256':hashlib.sha256((ROOT/graph_path).read_bytes()).hexdigest(),'calling_convention':'TwoSSwords[currentDSnearPointer,countWord]. Child2FC4plainfarRET consumes4framebytes; rootRETF imm4 consumes4frame+4argumentbytes, rootSP+8 withoutarithmeticflagchange.','facts':['ClearCH meansCLbytecount, notfullCX ormaskedhost32bitshiftcount. RepeatedsinglebitSHLAX/RCLDX retains16bitcarry andzeroresultafter32steps.','CurrentDSnearwordpair reads andSSpointer/count reads distinct; pointerrereadafteractualfarhelper thenAX/DXstoresinorder.','MOVSPBP/POPBP/RETFimm4 preservechildCF; cleanupisnotADDSP4 arithmetic.','RawAX/DX/registerobservations do notestablishoriginalCreturntype orsigned32bitsourcetype.'],'limits':'Staticinstruction/byte/callerinventory only. Actualcaller/otherFLAGSconsumers/nearfieldbounds/lifetime/IRQ/fullstate/core/resource-fedP2/P3/device/session/game/fidelity remainopen. Originaldata/media external; nooriginalpayloadexported.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers)}))

if __name__=='__main__':main()
