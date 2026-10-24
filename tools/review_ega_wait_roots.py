"""Verify raw input/counter call order and distinct unsigned bound branches."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';md=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x69fe:'lcall [0x64dc]',0x6a02:'retf ',0x6a30:'lcall 0x6c9, 0x69fe',0x6a35:'cmp ax, 0',0x6a38:'je 0x6a30',0x6a4a:'lcall 0x6c9, 0x69fe',0x6a54:'lcall 0x6c9, 0x79c8',0x6a59:'cmp dx, word ptr [0x681a]',0x6a5f:'ja 0x6a67',0x6a61:'cmp ax, word ptr [0x6818]',0x7a3b:'lcall 0x6c9, 0x79c8',0x7a40:'cmp dx, word ptr [0x681a]',0x7a46:'ja 0x7a4e',0x7a48:'cmp ax, word ptr [0x6818]',0xc63e:'lcall 0x6c9, 0x69fe',0xc648:'lcall 0x6c9, 0xc692',0xc64d:'cmp dx, word ptr [0x68d8]',0xc651:'jb 0xc63e',0xc653:'cmp ax, word ptr [0x68d6]',0xc657:'jb 0xc63e',0x79c9:'mov ax, word ptr [0x5e8c]',0x79cc:'mov dx, word ptr [0x5e8e]',0xc693:'mov ax, word ptr [0x5e90]',0xc696:'mov dx, word ptr [0x5e92]'};observations=[]
    for ip,text in expected.items():
        at=0x6c90+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'06C9:{ip:04X}','instruction':text.strip()})
    graph_path='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph_path).read_text());targets={'06C9:6A30','06C9:6A4A','06C9:7A3B','06C9:C63E'};callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'flow_ledger':graph_path,'flow_ledger_sha256':hashlib.sha256((ROOT/graph_path).read_bytes()).hexdigest(),'facts':['Inputcondition comparesfullAX with0; AH-onlynonzero values areaccepted, noAL-onlynormalization.','6A4A/7A3B unsignedhighgreater branches skip lowcompare; C63E requiresbothDX>=high andAX>=low evenwhenDXgreater.','79C8rawDS5E8C/5E8E andC692rawDS5E90/5E92 aredistinctownedpairs, bothCLI/read/STI/RETF andIF1; nouints/frequency inferred.','69FE currentDS64DCfarptr rereadperinputcall, dynamicfarreturn6A02 thenouterRETF4; actualinputtargetbody remainsexplicitservice.'],'limits':'Staticinstruction/callerinventory only. Actualinput/counterwriters/lifetime/IRQ/reentry/exclusion/fullstate/core andresource-fedP2/P3/device/session/game/fidelity remainopen. Physical086C literalreader isunrelated; nohardwaretimebase/frequency. Syntheticcounterobservations arefixtureupdates, notdeliveredIRQs.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers)}))

if __name__=='__main__':main()
