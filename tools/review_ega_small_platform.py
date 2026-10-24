"""Check raw wrapper service sites and pinned historical DOS API identifiers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve();assert output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists()
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    reference_path='docs/recovery/evidence/msdos-api-reference-v1.json';reference=json.loads((ROOT/reference_path).read_text());source=(ROOT/reference['private_path']).read_bytes();assert hashlib.sha256(source).hexdigest()==reference['sha256'] and len(source)==59136
    codes={'SET_DEFAULT_DRIVE':14,'GET_DEFAULT_DRIVE':25,'CHMOD':67}
    for name,code in codes.items():assert int(re.search(rb'^'+name.encode()+rb' +EQU (\d+)',source,re.MULTILINE).group(1))==code
    assert b'1  Set the attributes of the file to those in CX' in source
    md=Cs(CS_ARCH_X86,CS_MODE_16);expected={(0x6c9,0x5d50):'int 0x21',(0x6c9,0x5d56):'int 0x21',(0x6c9,0x5d74):'int 0x11',(0x13a8,0x2e33):'int 0x21',(0x6c9,0x5d67):'int 0x21',(0x6c9,0x5d61):'mov ax, 0x4301',(0x6c9,0x5d64):'mov cx, 2',(0x6c9,0x5d30):'int 0x1a',(0x6c9,0x5d42):'mov word ptr [0x52c2], cx',(0x6c9,0x5d46):'mov word ptr [0x52c4], dx'};observations=[]
    for (segment,ip),text in expected.items():
        at=16*segment+ip;i=next(md.disasm(image[at:at+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;observations.append({'site':f'{segment:04X}:{ip:04X}','instruction':text})
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'api_reference':{'path':reference_path,'sha256':hashlib.sha256((ROOT/reference_path).read_bytes()).hexdigest(),'source_path':reference['private_path'],'source_sha256':reference['sha256'],'source_bytes':len(source),'url':reference['url'],'service_identifiers':codes,'relevant_line_ranges':[[814,843],[1557,1557],[1567,1567],[1620,1620]]},'claims':['AH19 andAH0E historicalget/set-default-drive identities; gamewrapper forwardsreturnedAL throughDL thenreturnssecondAL withAH0.','AX4301/CX2 historicalset-attributes identity; gamewrapper convertsCFerror toAX1 andsuccess toAX0, noactualfilechanges.','RawBIOS11 and1AAH00 responseoperands/codeeffects documented; noBIOSversion/timebase/frequency orrealdevicebehavior inferred.','DS52C2/52C4 publications overlapknownDATcopy destination; actualwriter/lifetime ownership remainsopen.'],'limits':'Staticinstruction/APIidentifier corroborationonly. NoMicrosoft implementationcode copiedintoC; noactualDOS/BIOS/IRQ/session/device/render/audio/core/game/fidelity admission. Physical086C remainsa separate rawanomaly.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'DOS_identifiers':len(codes)}))

if __name__=='__main__':main()
