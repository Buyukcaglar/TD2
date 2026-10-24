"""Record palette/SS-mask candidates and their original address selection."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_MEM,X86_REG_BP,X86_REG_INVALID
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';m=Cs(CS_ARCH_X86,CS_MODE_16);m.detail=True;expected={0xc27:'mov word ptr [0x9c0], ax',0xc2a:'and bx, 0xf',0xc2d:'mov cl, byte ptr [bx + 0x5428]',0xc35:'mov cl, byte ptr [bx + 0x5438]',0xc3d:'mov cl, byte ptr [bx + 0x5448]',0xc45:'mov cl, byte ptr [bx + 0x5458]',0xc56:'and bx, 7',0xc5e:'mov bp, word ptr [0x9be]',0xc62:'mov al, byte ptr [bp + 0x5468]',0xcde:'mov word ptr [0x9be], si',0xce9:'mov word ptr [0x9be], si',0xcfa:'add sp, 2',0xcfd:'jmp word ptr [0x702]',0x2865:'mov word ptr [0x9be], dx',0x2869:'mov word ptr [0x9c0], dx',0x1f9c:'mov word ptr [0x702], 0x28bd'};observations=[]
 for ip,text in expected.items():
  i=next(m.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text,(hex(ip),i.mnemonic,i.op_str)
  if ip==0xc62:
   operand=i.operands[1];assert operand.type==X86_OP_MEM and operand.mem.base==X86_REG_BP and operand.mem.segment==X86_REG_INVALID
  observations.append({'site':f'06C9:{ip:04X}','instruction':text})
 offset,length=0x5428,72;blob=data[0x178f0+offset:0x178f0+offset+length];assert len(blob)==length;span={'id':'RS-DOS-000255','segment':0x178f,'offset':offset,'length':length,'sha256':hashlib.sha256(blob).hexdigest(),'consumers':['FN-EGA-000076','FN-EGA-000094'],'observation':'Four16byte currentDS palette rows5428/5438/5448/5458 with BX&15; SS-default mask bytes at BP+5468. Initializedprincipal-group72byte span is candidate only for matching DS/SS views; BP/domain/allwriters/aliases remainopen.'};record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spans':[span],'instruction_observations':observations,'serialized_row_index_argument':'284FclearsDS9BE; C17recordsindex((AX-1)&7)+1 andresets8to0, preserving bounded0..7 acrossordinary/nonlocal28BDrowcalls absentotherwriters. Actualalias/IRQ/allwriter/SSview proof remainsopen. StandaloneC17incomingBPsource9BE isnotuniversallybounded.','limits':'Static72bytecandidate/operand/defaultsegment review only; palettes currentDS, BPmaskdefaultsSS. Principalimagecandidate notproofactualDS=SS/tableownership/lifetime/IRQexclusion. No originalvaluesexported/fullresourcedecode/actualEGAdevice/renderer/session/core/game/fidelity. LaterresourcefedchecksP2-01/06/09 andP3-05 remainseparate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','spans':1,'sites':len(observations)}))
if __name__=='__main__':main()
