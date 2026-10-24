"""Record external DS rectangle-edge masks without exporting their values."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';m=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x8a36:'and bx, 7',0x8a39:'mov dh, byte ptr [bx + 0x6838]',0x8a43:'and bx, 7',0x8a46:'mov dl, byte ptr [bx + 0x6840]',0x89bc:'mov word ptr [bp + 6], dx',0x89ec:'mov word ptr [bp + 8], bx',0x8b38:'shr byte ptr [bp + 0xe], 1'};observations=[]
 for ip,text in expected.items():
  i=next(m.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text,(hex(ip),i.mnemonic,i.op_str);observations.append({'site':f'06C9:{ip:04X}','instruction':text})
 blob=data[0x178f0+0x6838:0x178f0+0x6848];assert len(blob)==16;span={'id':'RS-DOS-000257','segment':0x178f,'offset':0x6838,'length':16,'sha256':hashlib.sha256(blob).hexdigest(),'consumers':['FN-EGA-000218','FN-EGA-000219'],'observation':'Two externalcurrentDS8byteedge-mask candidates6838/6840, eachindexBX&7. Principalinitializedspan isconditionalonactualDSview; SSargumentmutations areseparate. Nooriginalbytevaluesexported.'};record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spans':[span],'instruction_observations':observations,'limits':'Staticinitialized16bytecandidate/operand/indexreview only; DSedge-maskreads versusSSBPcallerargumentwrites distinguished. Allwriters/DSview/sourceownership/device/renderer/resourcefedP2-01/06/09/P3-05/core/session/game/fidelity remainseparate. No fullresourcedecode/originalpayloadexport.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','spans':1,'sites':len(observations)}))
if __name__=='__main__':main()
