"""Review06C3 ordered INC/DEC self-modification and near RET6 interface."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence required')
    data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    expected={0x6f9:'mov byte ptr cs:[0x71f], 0x40',0x6ff:'mov byte ptr cs:[0x735], 0x40',0x709:'mov byte ptr cs:[0x71f], 0x48',0x70f:'mov byte ptr cs:[0x735], 0x48',0x6c9:'mov ax, word ptr [bp + 8]',0x6cc:'mov bx, word ptr [bp + 6]',0x6cf:'mov di, word ptr [bp + 4]',0x743:'ret 6'}
    md=Cs(CS_ARCH_X86,CS_MODE_16);observations=[]
    for ip,text in expected.items():
        i=next(md.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'06C9:{ip:04X}','instruction':text})
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in graph['functions'] if f['entry']=='06C9:06C3');initial={ip:next(md.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in f['instructions']};assert data[0x6c90+0x71f]==data[0x6c90+0x735]==0x40;forms=[]
    for name,first,second in [('positive_or_initial',0x40,0x40),('negative',0x48,0x48),('positive_first_write_prefix',0x40,0x48),('negative_first_write_prefix',0x48,0x40)]:
        shadow=bytearray(data);shadow[0x6c90+0x71f]=first;shadow[0x6c90+0x735]=second;changes=[]
        for ip,i in initial.items():
            other=next(md.disasm(shadow[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert other.size==i.size
            if (other.mnemonic,other.op_str)!=(i.mnemonic,i.op_str):assert ip in [0x71f,0x735] and other.mnemonic=='dec' and other.op_str=='ax';changes.append(f'06C9:{ip:04X}')
        forms.append({'name':name,'opcode_071F':first,'opcode_0735':second,'changed_instruction_sites':changes,'same_instruction_boundaries':True})
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'function_id':'FN-EGA-000069','family':'06C3_INC_DEC_PAIR','instruction_observations':observations,'local_forms':forms,'function_instruction_locations':len(initial),'ordered_writes':{'positive':['06C9:06F9 ->071F=40','06C9:06FF ->0735=40'],'negative':['06C9:0709 ->071F=48','06C9:070F ->0735=48']},'calling_convention':'Plainnearcall frame2 plus3wordarguments: BP+4destination, BP+6second endpoint, BP+8first endpoint. RET6 popsreturnIP and6argumentbytes; total8bytes fromentrySP. Five2477calls consume15words withoutADDSP30.','limits':'Staticcode-state/interface review only, not completefunction/native/dynamic acceptance. Bothpatches precede patched arithmetic onnormaldirect-entry interpolation; uniform/delta-zero exits canretainpriorforms. Mixedforms areorderedwrite-prefix states, not deliveredIRQ/reentrancy proof. Four localforms do notreplaceorcomplete fourplatform-mutator ledgers orwholeprogramtransitiongraph. Actual06C3body/2477SS-DS/callerbounds/lifetimes/core/game/fidelity stillpending.'}
    out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','local_forms':len(forms),'same_boundaries':True,'callee_argument_cleanup':6}))


if __name__=='__main__':main()
