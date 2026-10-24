"""Verify selected session-resource ownership and packed-caller obligations."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh evidence required')
    flow=json.loads(a.flow.read_text());image=(ROOT/flow['image']).read_bytes()
    require(hashlib.sha256(image).hexdigest()==flow['image_sha256'],'Image mismatch')
    by={f['entry']:f for f in flow['functions']};md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True
    def instruction(segment,offset,mnemonic,operands=None):
        i=next(md.disasm(image[segment*16+offset:segment*16+offset+15],offset,count=1))
        require(i.mnemonic==mnemonic and (operands is None or i.op_str==operands),f'Instruction mismatch{segment:04x}:{offset:04x}')
        return i
    clear_words={0x8a78:0x1659,0x8a76:0x165c,0x8a7e:0x165f,0x8a7c:0x1662,0x8a86:0x1665,0x8a84:0x1668,
                 0x8a90:0x166b,0x8a8e:0x166e,0x8a98:0x1671,0x8a96:0x1674,0x922a:0x1677,0x9228:0x167a,
                 0x8a94:0x167d,0x8a92:0x1680,0x9262:0x1683,0x9260:0x1686,0x8430:0x1689,0x842e:0x168c,0x940e:0x168f,0x940c:0x1692}
    instruction(0x267,0x1657,'sub','ax, ax')
    for word,site in clear_words.items():instruction(0x267,site,'mov',f'word ptr [0x{word:x}], ax')
    release_pairs=[(0x16f1,0x842e),(0x170a,0x940c),(0x1723,0x9260),(0x173c,0x8a84),(0x1755,0x8a7c),
                   (0x176e,0x8a76),(0x1787,0x9228),(0x17a0,0x8a92),(0x17b9,0x8a96),(0x17d2,0x8a8e)]
    for site,pair in release_pairs:
        instruction(0x267,site-8,'push',f'word ptr [0x{pair+2:x}]')
        instruction(0x267,site-4,'push',f'word ptr [0x{pair:x}]')
        instruction(0x267,site,'lcall','0x6c9, 0x736b')
    for site,mnemonic,operands in [(0x1a4e,'mov','ax, 0x1e5e'),(0x1a52,'mov','ax, 0x346a'),(0x1a5b,'lcall','0x6c9, 0x5d01'),
      (0x1bd3,'je','0x1c32'),(0x1c32,'lcall','0x6c9, 0x1b2c'),(0x1c56,'jmp','0x16e0'),(0x1cae,'jmp','0x1657'),
      (0x1809,'cmp','word ptr [bp - 0x1a], -1'),(0x180d,'je','0x1812')]:instruction(0x267,site,mnemonic,operands)
    packed_sites=sorted({c['site'] for f in by.values() for c in f['calls'] if c['target']=='06C9:6D50'})
    require(packed_sites==['0267:1A40','1748:010F'],'Packed caller scope expanded')
    register_observations=[]
    for entry in ['0000:07B3','019E:06C5','0267:15E4','1748:000E']:
        f=by[entry];segment=int(entry[:4],16);accesses=[]
        for ip in f['instructions']:
            i=next(md.disasm(image[segment*16+ip:segment*16+ip+15],ip,count=1));reads,writes=i.regs_access()
            r=[i.reg_name(v) for v in reads if i.reg_name(v) in ('si','di')];w=[i.reg_name(v) for v in writes if i.reg_name(v) in ('si','di')]
            if r or w:accesses.append({'site':f'{segment:04X}:{ip:04X}','mnemonic':i.mnemonic,'operands':i.op_str,'reads':r,'writes':w})
        register_observations.append({'entry':entry,'explicit_si_di_accesses':accesses,'limit':'Doesnotinfer registerinputs/liveness insidecallees or completeinterproceduralpreservation.'})
    require(all(not r['explicit_si_di_accesses'] for r in register_observations[:3]),'New explicit SI/DI owner use needsreview')
    instruction(0x1748,0x14,'push','si');instruction(0x1748,0x91,'pop','si')
    seed_writes=[]
    for site in [0x5d42,0x5d46]:
        i=instruction(0x6c9,site,'mov');seed_writes.append({'site':f'06C9:{site:04X}','operands':i.op_str})
    report={'schema':1,'result':'pass','image_sha256':flow['image_sha256'],'ledger_sha256':hashlib.sha256(a.flow.read_bytes()).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'session_entry':'0267:15E4',
            'cleared_pointer_words':[{'group_offset':word,'site':f'0267:{site:04X}'} for word,site in clear_words.items()],
            'cleanup_release_order':[{'site':f'0267:{site:04X}','offset_word':pair,'segment_word':pair+2} for site,pair in release_pairs],
            'packed_direct_call_sites':packed_sites,'register_observations':register_observations,
            'section_copy':{'site':'0267:1A5B','destination_group_offset':0x346a,'length':0x1e5e,'end_exclusive':0x52c8,
                            'overlaps_query_written_words':[0x52c2,0x52c4],'query_writer_sites':seed_writes},
            'observations':['Ten farpointer pairs zeroedat1657..1692 beforeloads, soinitial missingSGN skipsFNT withzero fontpair. Normalnextiteration alsojumps1657.',
                            'Cleanup16E0 tests/releasesten pairs inlistedorder; sourceglobalpairs arenotrewritten with736B DX0. Theyremainstaleuntilnextzero pass orfunctionexit.',
                            'Normal1B2C returnvalue storedlocally, timer/music reinstalled, thenjump16E0 withoutsetting-1; errorsenter16DB set-1. Cleanuprecreatesworkingsurface andrestarts song1 beforebranching.',
                            '7774byteDAT copyinto346A..52C7 overlaps52C2/52C4 wordswrittenby5D2E. Directabsolute-writer scansalone cannotdeclarethosewordsindependent.',
                            '1748 restoresown savedSI butnotDI;0267/019E/main havenoexplicitSI/DIuses. Packedloaderclobberpropagation/intendedcalleeABI stillrequiresinterproceduralreview.'],
            'limits':'Selectedstatic ownership/copy/register facts only. No completecaller lifetime, allocationbound, callbackexclusion, semantics ofallcopiedfields, statevalidation, resourceformat, runtime orgameplay/fidelity acceptance.'}
    out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['cleared_pointer_words','cleanup_release_order','register_observations']},indent=2))


if __name__=='__main__':main()
