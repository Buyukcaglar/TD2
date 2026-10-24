"""Review the actual copy ABIs and raw CS configuration writer spans."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';md=Cs(CS_ARCH_X86,CS_MODE_16)
    expected={0x5d08:'mov ds, word ptr [bp + 8]',0x5d0b:'mov si, word ptr [bp + 6]',0x5d0e:'mov es, word ptr [bp + 0xc]',0x5d11:'mov di, word ptr [bp + 0xa]',0x5d14:'mov cx, word ptr [bp + 0xe]',0x5d17:'rep movsb byte ptr es:[di], byte ptr [si]',0x7d65:'mov ds, word ptr [bp + 8]',0x7d68:'mov si, word ptr [bp + 6]',0x7d6b:'mov cx, 0xd',0x7d6e:'mov ax, cs',0x7d70:'mov es, ax',0x7d72:'mov di, 0xaf3a',0x7d75:'rep movsw word ptr es:[di], word ptr [si]',0x791e:'mov si, word ptr [bp + 6]',0x7921:'mov ax, cs',0x7923:'mov es, ax',0x7925:'lea di, [0xaf3a]',0x792a:'mov cx, 0x1a',0x792d:'rep movsw word ptr es:[di], word ptr [si]'};observations=[]
    for ip,text in expected.items():
        at=0x6c90+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'06C9:{ip:04X}','instruction':text})
    graph_path='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph_path).read_text());targets={'06C9:5D01','06C9:7D5E','06C9:7918'};callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];code=set()
    for f in g['functions']:
        segment=int(f['entry'][:4],16)
        for ip in f['instructions']:
            at=16*segment+ip;i=next(md.disasm(image[at:at+15],ip,count=1));code.update(range(at,at+i.size))
    assert not code.intersection(range(0x6c90+0xaf3a,0x6c90+0xaf6e))
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'flow_ledger':graph_path,'flow_ledger_sha256':hashlib.sha256((ROOT/graph_path).read_bytes()).hexdigest(),'instruction_observations':observations,'raw_writer_spans':[{'entry':'06C9:7D5E','segment':'currentCS','offset':0xaf3a,'length':26,'source':'TwoSSwords[sourceOffset,sourceSegment], thirteenforwardwords.'},{'entry':'06C9:7918','segment':'currentCS','offset':0xaf3a,'length':52,'source':'OneSSnearoffset/currentDS, twenty-sixforwardwords.'}],'direct_caller_candidates':callers,'selected_initial_graph_destination_bytes_not_syntactic_code':True,'shared_consumed_fields':{'AF3C..AF43':'Fourplane segmentwords','AF44':'Lineoffset-table nearbase','AF46/AF48':'Rawhorizontal boundwords','AF4A/AF4C':'Rawvertical bounds','AF4E':'Destinationrowstrideword'},'limits':'Instruction-provenwriter spans/ABIs anddirectcallerinventory only; noall-writer/dispatchedcallerclosure, sourceownership/capacity/lifetime/IRQexclusion or resourceformat/frequency/units inference. Initialsyntacticnoncode check isnotallmutable-state/data acceptance. Destinationcontrolbytes/media remainexternal; noactualdevice/render/session/core/game/fidelity admission.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'direct_caller_candidates':len(callers)}))

if __name__=='__main__':main()
