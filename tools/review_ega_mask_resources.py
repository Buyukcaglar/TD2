"""Record two external CS mask candidates and conditional caller alignment."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();receipt_path=a.output.resolve();assert not receipt_path.exists() and receipt_path.is_relative_to(ROOT/'docs/recovery/evidence');data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';m=Cs(CS_ARCH_X86,CS_MODE_16);expected={0x82e3:'mov ah, byte ptr cs:[bx - 0x7d38]',0x8349:'mov ah, byte ptr cs:[bx - 0x7d38]',0x83b3:'mov ah, byte ptr cs:[bx - 0x7d38]',0xad39:'mov ah, byte ptr cs:[bx - 0x52e6]',0xada2:'mov ah, byte ptr cs:[bx - 0x52e6]',0xae0d:'mov ah, byte ptr cs:[bx - 0x52e6]',0x9262:'and ax, 7',0x9265:'mov word ptr [bp - 0x34], ax',0x938e:'mov bx, word ptr [bp - 0x34]',0x94ca:'mov bx, word ptr [bp - 0x34]'};observations=[]
 for ip,text in expected.items():
  i=next(m.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text,(hex(ip),i.mnemonic,i.op_str);observations.append({'site':f'06C9:{ip:04X}','instruction':text})
 spans=[]
 for id,offset,consumers in [('RS-DOS-000258',(-0x7d38)&65535,['FN-EGA-000212','FN-EGA-000213','FN-EGA-000214']),('RS-DOS-000259',(-0x52e6)&65535,['FN-EGA-000238','FN-EGA-000239','FN-EGA-000240'])]:
  blob=data[0x6c90+offset:0x6c90+offset+8];assert len(blob)==8;spans.append({'id':id,'segment':0x6c9,'offset':offset,'length':8,'sha256':hashlib.sha256(blob).hexdigest(),'consumers':consumers,'observation':'Eight externalinitializedCSmask candidates beforehelperentry; rawBXnotmaskedinsidehelper. Known916C/91A4setupderivesalignment&7 butallcaller/frame/alias/writer proofopen. No originalvaluesexported.'})
 record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spans':spans,'instruction_observations':observations,'limits':'StaticinitializedCSspans/instruction/defaultsegment/index-producer observations only. Caller/frame/allwriter/IRQ/sourceownership notclosed; rawstandaloneBXmayselectoutsidecandidate8bytes. No originalpayload/fullresourcecodec/actualdevice/renderer/session/core/game/fidelity acceptance. LaterresourcefedP2-01/06/09/P3-05 separately.'};receipt_path.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','spans':2,'sites':len(observations)}))
if __name__=='__main__':main()
