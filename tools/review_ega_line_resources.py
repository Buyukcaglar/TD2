"""Record the external eight-byte line mask candidate without payload export."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';m=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x858d:'mov ds, ax',0x87d7:'and bx, 7',0x87da:'mov al, byte ptr cs:[bx - 0x7a86]',0x8865:'and bx, 7',0x8868:'mov bl, byte ptr cs:[bx - 0x7a86]',0x88d0:'and bx, 7',0x88d3:'mov al, byte ptr cs:[bx - 0x7a86]',0x8961:'and bx, 7',0x8964:'mov bl, byte ptr cs:[bx - 0x7a86]'};observations=[]
 for ip,text in expected.items():
  i=next(m.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text,(hex(ip),i.mnemonic,i.op_str);observations.append({'site':f'06C9:{ip:04X}','instruction':text})
 offset=(-0x7a86)&65535;assert offset==0x857a;blob=data[0x6c90+offset:0x6c90+offset+8];assert len(blob)==8;span={'id':'RS-DOS-000256','segment':0x6c9,'offset':offset,'length':8,'sha256':hashlib.sha256(blob).hexdigest(),'consumers':['FN-EGA-000217'],'observation':'Eight externalinitializedbytes atCS857A..8581 selectedby BX&7 andwordwrappednegative displacement. UsedasrawmaskedRAMbitinputs orbyteOUTvalues; no originalvaluesembedded/exported. Writers/actualdevice/resourcefedprofile pending.'};record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spans':[span],'instruction_observations':observations,'limits':'Staticspan/address/index/instructionreview only, no originalbytepayload. CodeusesCSsegmentoverride forallfourreads; DS=CSassignment doesnotreplaceexplicitSSBPcaller/local addresses. Actualwriters/capacity/device/renderer/resourcefedP2-01/06/09/P3-05/core/session/game/fidelity checks separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','spans':1,'sites':len(observations)}))
if __name__=='__main__':main()
