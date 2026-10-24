"""Check bytecase and raw signed/indexed state operands with width proof."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';md=Cs(CS_ARCH_X86,CS_MODE_16);expected={(0x16aa,5):'cmp byte ptr [bp + 6], 0x61',(0x16aa,9):'jl 0x15',(0x16aa,0xb):'cmp byte ptr [bp + 6], 0x7a',(0x16aa,0xf):'jg 0x15',(0x16aa,0x11):'sub byte ptr [bp + 6], 0x20',(0x16aa,0x15):'mov al, byte ptr [bp + 6]',(0x16aa,0x18):'cwde ',(0x13a8,0x2a1b):'mov bx, word ptr [bp + 6]',(0x13a8,0x2a1e):'cmp bx, word ptr [0x6da2]',(0x13a8,0x2a22):'jge 0x2a35',(0x13a8,0x2a24):'cmp bx, 0',(0x13a8,0x2a27):'jl 0x2a35',(0x13a8,0x2a29):'test byte ptr [bx + 0x6da4], 0x40',(0x13a8,0x190e):'cmp word ptr [0x83e4], 0',(0x13a8,0x191a):'cmp word ptr [0x83da], 0',(0x13a8,0x191f):'jle 0x1928',(0x13a8,0x1921):'dec word ptr [0x83da]',(0x432,0x1d25):'mov bx, word ptr [0x8a22]',(0x432,0x1d29):'shl bx, 1',(0x432,0x1d2b):'mov word ptr [bx + 0x40], 0',(0x432,0x1d31):'mov word ptr [0x8a22], 0',(0x432,0x1d37):'mov word ptr [0x8a8c], 0',(0x432,0x1d3d):'mov ax, word ptr [0x8c9e]',(0x432,0x1d40):'mov word ptr [0x8a1c], ax'};observations=[]
    for (segment,ip),text in expected.items():
        at=16*segment+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'{segment:04X}:{ip:04X}','instruction_text':text.strip()})
    deps=['docs/recovery/evidence/td2ega-sign-extension-context-v1.json','docs/recovery/evidence/td2ega-operand-width-context-v1.json']
    for path in deps:assert json.loads((ROOT/path).read_text())['result']=='pass'
    assert image[0x16aa0+0x18]==0x98
    graph_path='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph_path).read_text());targets={'16AA:0002','13A8:2A18','13A8:190E','0432:1D25'};callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'instruction_observations':observations,'direct_caller_candidates':callers,'flow_ledger':graph_path,'flow_ledger_sha256':hashlib.sha256((ROOT/graph_path).read_bytes()).hexdigest(),'facts':['Bytecaseuses signedbytecomparisons butonly61..7A ismodified; argumenthighbytepreserved, unprefixed98meansAXsignextension underverified16bitcontext. Capstonesynonymtext not32bitsemanticproof.','2A18 uses signedindex/limit/nonnegative guards beforebit40 in currentDSbyte table, CF0; tableformat/type unassigned.','190E returnsAX1whenDS83E4zero, otherwise decrementsDS83DAonlyifsignedpositive; negative/zero returnsAX0, CF0.','1D25 SHLBX preservesitscarryacrossorderedindexedzero/8A22zero/8A8Czero, thenreads8C9Eandwrites8A1C; postwritealiases notnormalized.'],'limits':'Staticoperands/width/branch/callerinventory only. Actualcaller/otherFLAGS/bounds/DS-SSview/writers/lifetime/IRQ/fullstate/core/resource-fed/device/session/game/fidelity remainopen. Allstatesraw, noCreturntype/globalunits/resourceformat inferred; data/media external.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers)}))

if __name__=='__main__':main()
