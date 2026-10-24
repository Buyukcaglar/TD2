"""Verify CS bound-store order and near-output configuration snapshot ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';md=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x5dfe:'mov ax, word ptr [bp + 6]',0x5e01:'mov word ptr cs:[0xaf46], ax',0x5e05:'mov ax, word ptr [bp + 8]',0x5e08:'mov word ptr cs:[0xaf48], ax',0x5e0c:'mov ax, word ptr [bp + 0xa]',0x5e0f:'mov word ptr cs:[0xaf4a], ax',0x5e13:'mov ax, word ptr [bp + 0xc]',0x5e16:'mov word ptr cs:[0xaf4c], ax',0x78fe:'lea si, [0xaf3a]',0x7902:'mov di, word ptr [bp + 6]',0x7905:'mov ax, ds',0x7907:'mov es, ax',0x7909:'mov ax, cs',0x790b:'mov ds, ax',0x790d:'cld ',0x790e:'mov cx, 0x1a',0x7911:'rep movsw word ptr es:[di], word ptr [si]'};observations=[]
    for ip,text in expected.items():
        at=0x6c90+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'06C9:{ip:04X}','instruction':text.strip()})
    graph_path='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph_path).read_text());targets={'06C9:5DFB','06C9:78F8'};callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'flow_ledger':graph_path,'flow_ledger_sha256':hashlib.sha256((ROOT/graph_path).read_bytes()).hexdigest(),'bound_writer_order':['SS[BP+6]->CSAF46','SS[BP+8]->CSAF48','SS[BP+A]->CSAF4A','SS[BP+C]->CSAF4C'],'snapshot_span':{'segment':'currentCS','offset':0xaf3a,'length':52,'destination':'OneSSnearoffset/currentincomingDS; DSestablishedtoCSafterEScapturesincomingDS.'},'limits':'Staticword-width/read-writeorder/segment/CLD/callerinventory only. BoundsetterdoesnotCLD ornormalizewordvalues. FullSS=CS argument/outputaliases andsnapshotreturnframealiases have scopedcomparisons; allactualcaller/writer/capacity/lifetime/IRQ/fullstate/core/device/resource-fed/game/fidelity remainopen. Nooriginalconfiguration/media payloadexported.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers)}))

if __name__=='__main__':main()
