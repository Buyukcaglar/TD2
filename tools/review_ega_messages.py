"""Audit embedded message span and near-pointer caller contexts without text export."""
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
    data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest()
    assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    lengths=[(0x2e2a,27),(0x2e45,23),(0x2e5c,25),(0x2e75,28),(0x2e91,29),(0x2eae,30),(0x2ecc,28),(0x2ee8,28),(0x2f04,15),(0x2f13,17),(0x2f24,3),(0x2f27,30)]
    for i,(at,n) in enumerate(lengths):
        span=data[0x178f0+at:0x178f0+at+n]
        assert span[-1]==0 and 0 not in span[:-1]
        if i+1<len(lengths):assert at+n==lengths[i+1][0]
    assert lengths[-1][0]+lengths[-1][1]==0x2f45
    expected={0x6c9:{0x36e6:'mov ax, 0x2e2a',0x3700:'mov ax, 0x2e45',0x36f3:'mov ax, 0x2e5c',0x3716:'mov ax, 0x2e75',0x3722:'mov ax, 0x2e91',0x372e:'mov ax, 0x2eae',0x373a:'mov ax, 0x2ecc',0x3746:'mov ax, 0x2ee8',0x3759:'mov ax, 0x2f04',0x377d:'mov ax, 0x2f13',0x3782:'mov ax, 0x2f27',0x3769:'mov bx, 0x2f24',0x376c:'mov cx, 0x2f20'},0x16ab:{0x12:'push word ptr [bp + 6]',0x15:'lcall 0x13a8, 0x29b4'},0x13a8:{0x2a44:'lea ax, [bp - 0xc]',0x2a49:'lea ax, [bp + 0xa]',0x2a4c:'mov word ptr [bp - 2], ax',0x2a4f:'mov byte ptr [di + 6], 0x42',0x2a53:'mov ax, word ptr [bp + 6]',0x2a56:'mov word ptr [di + 4], ax',0x2a60:'lea ax, [bp + 0xa]',0x2a64:'push word ptr [bp + 8]',0x2a68:'lcall 0x13a8, 0x192c'}}
    md=Cs(CS_ARCH_X86,CS_MODE_16);sites=[]
    for segment,rows in expected.items():
        for ip,text in rows.items():
            i=next(md.disasm(data[segment*16+ip:segment*16+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text
            sites.append({'site':f'{segment:04X}:{ip:04X}','instruction':text})
    span=data[0x178f0+0x2e2a:0x178f0+0x2f45]
    result={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'span':{'segment':0x178f,'offset':0x2e2a,'length':len(span),'sha256':hashlib.sha256(span).hexdigest()},'initial_nul_spans':[{'offset':at,'length_including_nul':n} for at,n in lengths],'instruction_observations':sites,'consumer_ids':['FN-EGA-'+f'{i:06}' for i in range(100,108)],'callee_ids':{'text_wrapper':'FN-EGA-000349','format_wrapper':'FN-EGA-000334','near_length_candidate':'FN-EGA-000329'},'open_obligations':['Near captions use currentDS; actual caller segment/lifetime domains not closed.','2A3C constructs near BP frame/variadic offsets; BP defaultsSS but DI defaultsDS. Actual body needs DS=SS or proved corresponding views, not universal Ghidra context.','2F20 destination overlaps initialized caption span; 7FFF descriptor literal is not a safe four-byte output bound. Actual formatter semantics/counter range/output extent are P1-11.','Caption encoding/glyph rendering and resource corpus remain P2-01/P2-06/P2-09/P3-05.'],'limits':'Static byte-span/NUL positions and instruction context only. No original text bytes exported, no full resource decoding, output bounds, actual formatter/body integration, rendering, IRQ, game or fidelity acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':'pass','span_bytes':len(span),'sites':len(sites)},indent=2))


if __name__=='__main__':main()
