"""Verify logic prologues, dispatch identities and byte operand conventions."""
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve()
    assert not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence')
    data=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    sha=hashlib.sha256(data).hexdigest()
    assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    md=Cs(CS_ARCH_X86,CS_MODE_16)
    observations=[]
    for start,ram,hardware,mode,flags in [(0x7dbc,0x7ddc,0x9572,8,1),(0xa718,0xa738,0x9572,16,2),(0xbb08,0xbb28,0xbb38,24,4)]:
        expected=['push bp','mov bp, sp','push ds','push si','push di','sub sp, 0x44',f'mov ax, 0x{ram:x}','mov word ptr [bp - 0x40], ax',f'mov ax, 0x{hardware:x}','mov word ptr [bp - 0x4a], ax',f'mov byte ptr [bp - 0x42], {mode}' if mode<10 else f'mov byte ptr [bp - 0x42], 0x{mode:x}',f'mov byte ptr [bp - 0x41], {flags}','jmp 0x91f3']
        instructions=list(md.disasm(data[0x6c90+start:0x6c90+start+32],start))
        assert [i.mnemonic+' '+i.op_str for i in instructions]==expected
        observations += [{'site':f'06C9:{i.address:04X}','instruction':i.mnemonic+' '+i.op_str} for i in instructions]
    expected={0x91f3:'mov ds, word ptr [bp + 8]',0x91f6:'mov si, word ptr [bp + 6]',0x91f9:'mov ax, word ptr [si + 8]',0x91fc:'mov word ptr [bp - 8], ax',0x91ff:'mov ax, word ptr [si + 0xa]',0x9202:'mov word ptr [bp - 0xa], ax',0x7e02:'and byte ptr es:[di], al',0x7e05:'inc di',0xa75e:'or byte ptr es:[di], al',0xa761:'inc di',0xbb5e:'xor byte ptr es:[di], al',0xbb61:'inc di',0xbbb6:'xor byte ptr es:[di], ah',0xbdb9:'xor byte ptr es:[di], dh',0xbdf4:'mov al, byte ptr es:[di]',0xbe19:'stosb byte ptr es:[di], al',0xbe1a:'mov ah, byte ptr es:[di]',0xbe24:'mov byte ptr es:[di], dh'}
    for ip,text in expected.items():
        i=next(md.disasm(data[0x6c90+ip:0x6c90+ip+15],ip,count=1))
        assert i.mnemonic+' '+i.op_str==text,(hex(ip),i.mnemonic,i.op_str,text)
        observations.append({'site':f'06C9:{ip:04X}','instruction':text})
    tables={0x7ddc:[0x7dec,0x7e21,0x7e74,0x7ecc,0x7f28,0x7f85,0x7fe0,0x8037],0xa738:[0xa748,0xa77d,0xa7cd,0xa822,0xa87b,0xa8d5,0xa92d,0xa981],0xbb28:[0xbb48,0xbb7d,0xbbcd,0xbc22,0xbc7b,0xbcd5,0xbd2d,0xbd81],0xbb38:[0x9835,0xbdd1,0xbe55,0xbece,0xbf4b,0xbfc9,0xc045,0xc0bd]}
    table_records=[]
    for offset,targets in tables.items():
        blob=data[0x6c90+offset:0x6c90+offset+16]
        assert list(struct.unpack('<8H',blob))==targets
        table_records.append({'segment':0x6c9,'offset':offset,'length':16,'entries':8,'sha256':hashlib.sha256(blob).hexdigest(),'targets':[f'06C9:{ip:04X}' for ip in targets]})
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'dispatch_tables':table_records,'shared_source_args':'TwoSSwords[sourceOffset,segment]; coordinates fromsource+8/+A. Sourcefarptr independent ofcallerDS; SSsaved/localframe andactualplainfarreturn.','RAM_direction':'LODSB followsDF; logicmemoryoperation thenexplicitINCDI+1 regardlessDF. Alignment0 LOOP0 means65536, noREP0 substitution.','XOR_tail':'Alignmentone usesAH atBBB6; alignments2..7 useDH. Hardwareunaligned initialALread, STOSBAL andsubsequentAHread/newDI, tailMOVDH withoutcopymerge retained.','selector_dependency':'ExternalRS-DOS-000260 selection span andCS82C8/AD1A mask spans. Priorinitializedselectionpredicate receipt remainsseparate. Rawdispatch table payload notembedded; code target addresses document provenance.','limits':'Staticprologue/operand/tableidentity only. Actualcaller/reachability forBB08 remainsunproven; alltablewriters/sourcebounds/lifetime/frame-output/exclusion, realdevice/renderer/fullstate/core/gameplay/fidelity andCGA gates remainopen.'}
    output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'result':'pass','sites':len(observations),'tables':len(table_records)}))

if __name__=='__main__':main()
