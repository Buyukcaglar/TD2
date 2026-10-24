"""Record projection lookup/weight spans and instruction bounds without payload export."""
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
    expected={0x6c9:{0x21dd:'and al, 0x7f',0x21eb:'mov ax, word ptr [bx + 0x347e]',0x2205:'mov ax, word ptr [bx + 0x3480]',0x221e:'lcall 0x13a3, 0x38',0x222e:'mul word ptr [si + 0x2728]',0x2236:'mul word ptr [si + 0x2728]',0x2275:'lcall 0x13a3, 0x38',0x2285:'mul word ptr [si + 0x26f6]',0x2297:'mul word ptr [si + 0x26f6]',0x22a2:'mov cx, word ptr [si + 0x275a]',0x23d0:'cmp word ptr [bx + 0x37a6], 0',0x23fa:'idiv bp',0x23fe:'mul word ptr [si + 0x275a]',0x2468:'cmp si, 0x32'},0x13a3:{0x3a:'cwde ',0x43:'neg bx',0x45:'shl bx, 1',0x47:'mov ax, word ptr [bx + 0x5560]'}}
    md=Cs(CS_ARCH_X86,CS_MODE_16);sites=[]
    for segment,rows in expected.items():
        for ip,text in rows.items():
            i=next(md.disasm(data[segment*16+ip:segment*16+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;sites.append({'site':f'{segment:04X}:{ip:04X}','instruction':text.rstrip()})
    spans=[]
    for id,offset,length,consumers,description in [('RS-DOS-000253',0x5560,258,['FN-EGA-000254','FN-EGA-000089'],'129 little-endian words selected by abs(signedAL), including index128; meanings/units/writers open.'),('RS-DOS-000254',0x26f6,150,['FN-EGA-000089'],'Three contiguous25-word arrays at26F6/2728/275A; SI0..48 step2, rawunsignedMUL/shift inputs, meanings/units/writers open.')]:
        blob=data[0x178f0+offset:0x178f0+offset+length];assert len(blob)==length;spans.append({'id':id,'segment':0x178f,'offset':offset,'length':length,'sha256':hashlib.sha256(blob).hexdigest(),'consumers':consumers,'observation':description})
    result={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'spans':spans,'instruction_observations':sites,'conditional_DAT_contract':'CurrentDS rawroute pointer2C26,128maskeddescriptor records347E..367D and37A6 sentinel/interpolation nodes fallwithin7774 DATcopy346A..52C7 whenactualDS/source/caller relation holds. No actualfile schema/bounds/lifetime admission.','limits':'Static initializedspans/instruction consumer bounds only; original tablevalues/payload notexported, no trigonometric/physicalmeaning assigned. Actualwriters/caller/listvalidity/DS-SS ownership andresourcefedgraphics pendingP1 plusP2-01/05/09/P3-05. No full resource decode, renderer/IRQ/session/core/game/fidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':'pass','spans':len(spans),'sites':len(sites)}))


if __name__=='__main__':main()
