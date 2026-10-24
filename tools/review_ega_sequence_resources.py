"""Review embedded sequence tables and raw BIOS10 block interface, without payload export."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence required')
    data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    rows=[];end=0x2cac
    for index in range(7):
        pointer=struct.unpack_from('<H',data,0x178f0+0x2c9e+2*index)[0];count=data[0x178f0+0x2e22+index];assert pointer==end and count!=0;end=pointer+4*count;rows.append({'index':index,'near_offset':pointer,'initial_count':count,'four_byte_record_extent':4*count})
    assert end==0x2e08
    expected={0x3596:'mov dl, byte ptr [bp + 0x2e22]',0x35a0:'mov bp, word ptr [bp + 0x2c9e]',0x35a9:'mov bx, word ptr [bp + si + 2]',0x35b0:'cwde ',0x35b8:'mov bx, word ptr [bp + si]',0x35bc:'sub al, 0x13',0x35be:'mov bh, ah',0x35db:'mov ax, 0x2e08',0x35e0:'mov ax, 0x2e10',0xabfd:'mov ax, ds',0xabff:'mov es, ax',0xac01:'mov ah, 0x10',0xac03:'mov al, 2',0xac05:'mov dx, word ptr [bp + 6]',0xac08:'int 0x10'}
    md=Cs(CS_ARCH_X86,CS_MODE_16);sites=[]
    for ip,text in expected.items():
        i=next(md.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1));assert i.mnemonic+' '+i.op_str==text;sites.append({'site':f'06C9:{ip:04X}','instruction':text.rstrip()})
    g=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];bios=next(r['id'] for r in g if r['entries'][0].get('segment')==0x6c9 and r['entries'][0].get('segment_offset')==0xabfa)
    span=data[0x178f0+0x2c9e:0x178f0+0x2e2a]
    result={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'span':{'segment':0x178f,'offset':0x2c9e,'length':len(span),'sha256':hashlib.sha256(span).hexdigest()},'initial_indexed_extents':rows,'instruction_observations':sites,'consumer_ids':['FN-EGA-000098',bios],'bios10_entry':bios,'correction':'3532 near2E08/2E10 arguments are raw BIOS10 AX1002 blocks throughABFA, not established text strings. Original source/control comparison unaffected.','open_obligations':['Initialprincipalgroup indexedextents are conditional on actualSS/caller/lifetime provenance; not allruntime pointervalues/bounds.','2E08/2E10 are near blocks passed asES:DX withESincomingDS toBIOS10 AX1002. BIOSreadextent/meaning/platformresponse require separate platform evidence; no encoding/text interpretation.','2E22 sevenbytecounts and2E29 scratch shareinitializedspan; zero-count256/pointAH asymmetry andwrites mustretain originalorder.','Pointword meanings/graphics effects, resource fed rendering andcompleteownership remainP1-05/09/11 plusP2-01/03/09 andP3-05.'],'limits':'Static pointer/count extents and BIOS instruction context only. No original point/block payload exported; no full resource decode, renderer/device/session/state-machine/game/fidelity acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':'pass','span_bytes':len(span),'initial_rows':len(rows),'bios10_function':bios}))


if __name__=='__main__':main()
