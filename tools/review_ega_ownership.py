"""Persist scoped raw-family ownership and state-writer observations."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_MEM,X86_OP_IMM


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True)
    ap.add_argument('--consumers',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence output required')
    flow=json.loads(a.flow.read_text());consumers=json.loads(a.consumers.read_text())
    image=(ROOT/flow['image']).read_bytes()
    if not hashlib.sha256(image).hexdigest()==flow['image_sha256']==consumers['image_sha256']:raise ValueError('Image mismatch')
    families={
        '.bin':{'id':'DOS-BIN','expected':26,'producers':['0000:083B','0000:084E','0267:189F','0267:195F'],
                'interfaces':['06C9:6D18','06C9:75C8','06C9:758A'],
                'scope':'Voices/songs and selected car/opponent raw binary family; field semantics/full input bounds pending.'},
        '.pes':{'id':'DOS-PES','expected':82,'producers':['1748:005C','1748:00A6','1748:010F'],
                'interfaces':['1748:000E','06C9:6D50','06C9:C838'],
                'scope':'EGA implicit/explicit graphics extension path; perasset producer and pixel/format semantics pending.'},
        '.pcs':{'id':'DOS-PCS','expected':82,'producers':['0432:0CB6'],
                'interfaces':[],
                'scope':'PCS name table referenced by EGA media-management code; graphics semantics deferred to ordered CGA recovery afterP1-11.'},
        '.ss':{'id':'DOS-SS','expected':12,'producers':['0143:00C2','0143:01F4','019E:0BAC'],
               'interfaces':['0000:0297','13A8:0A6E'],
               'scope':'Selected car text-family filename builders; stream parsing/display contracts pending.'},
        '.dat':{'id':'DOS-DAT','expected':26,'producers':['0267:1A03','0432:00BA','0432:01C3','0432:02CF','0432:038D','0432:03A5','0645:001B','0645:022D'],
                'interfaces':['0000:0297','13A8:0A6E','06C9:6D50','06C9:6D18'],
                'scope':'Catalog/selection/diskid/highscore and19 numbered route files have distinct raw producers; no shared format inferred.'},
        '.sgn':{'id':'DOS-SGN','expected':14,'producers':['0267:1B7C','0267:1BD9'],
                'interfaces':['06C9:7273','06C9:5EF4','06C9:6D18'],
                'scope':'Persection sign filename; cache/existence path; absent-sign branch1BD3 skips to1C32. Field decoding and exact persection path pending.'},
        '.fnt':{'id':'DOS-FNT','expected':3,'producers':['0267:1BE8','0267:1C23'],
                'interfaces':['06C9:6D18'],
                'scope':'Selected route font filename built inside sign-present path; header/glyph schema pending.'},
        '.exe':{'id':'DOS-EXECUTABLE','expected':4,'producers':[],
                'interfaces':[],
                'scope':'Executable/embedded-container identities. EGA admitted now; CGA remains afterEGA closure; TDY supporting and DUEL launcher context. No original instructions in final native core.'}
    }
    counts=Counter(Path(r['logical_path']).suffix.lower() for r in consumers['resources'])
    if counts!={ext:v['expected'] for ext,v in families.items()}:raise RuntimeError('DOSfamily counts changed; review additions')
    resources=[]
    for r in consumers['resources']:
        family=families[Path(r['logical_path']).suffix.lower()]
        resources.append({'logical_path':r['logical_path'],'sha256':r['sha256'],'family_id':family['id'],
                          'claim':'Scoped family interface/producer map only; exact perfile consumer/lifetime/schema acceptance pending'})
    md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True
    seen=set();writes=[]
    for f in flow['functions']:
        s=int(f['entry'].split(':')[0],16)
        for ip in f['instructions']:
            if (s,ip) in seen:continue
            seen.add((s,ip));i=next(md.disasm(image[s*16+ip:s*16+ip+15],ip,count=1))
            for op in i.operands:
                if op.type==X86_OP_MEM and op.mem.disp==0x5490 and not op.mem.base and not op.mem.index and op.access&2:
                    source=i.operands[-1]
                    writes.append({'site':f'{s:04X}:{ip:04X}','mnemonic':i.mnemonic,'width':op.size,
                                   'immediate_value':source.imm if source.type==X86_OP_IMM else None,
                                   'source_operand':i.op_str,'segment_assumption':'Principal DSgroup; indexed/aliased writers not excluded'})
    offset=0x178f0+0x66e6;span=image[offset:offset+258]
    embedded={'id':'RS-DOS-000250','container':'reference/dos/TD2EGA.EXE','transform':'TD2EGA-UNPACK-V1',
              'module_offset':offset,'length':258,'span_sha256':hashlib.sha256(span).hexdigest(),
              'initial_cursor':int.from_bytes(span[:2],'little'),'table_offset':offset+2,'table_length':256,
              'publication':'Original initialized byte-source state stays external; no table bytes in source.',
              'ownership':'Group66E6/66E8 shared by application and timer callback consumers; reset/alias/masking proof still open.'}
    result={'schema':1,'image_sha256':flow['image_sha256'],'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'families':families,'dos_file_count':len(resources),'resources':resources,
            'state5490_direct_writes':sorted(writes,key=lambda r:r['site']),
            'state5490_observed_immediate_domain':sorted({r['immediate_value']&255 for r in writes if r['immediate_value'] is not None}),
            'embedded_byte_source':embedded,
            'limits':'Family mapping/direct writes/initial-span provenance only. No complete perfile coverage, indexed alias proof, state-machine acceptance, format decoder, gameplay or fidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'dos_files':len(resources),'families':len(families),'direct_state_writes':len(writes),'immediate_domain':result['state5490_observed_immediate_domain'],'byte_source_provenance':embedded},indent=2))


if __name__=='__main__':main()
