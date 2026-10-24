"""Register discovered candidates without promoting their semantic gates.

Existing IDs, reviewed ranges and portable source records are preserved.
This mutates only the public metadata registry, never original/private bytes.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True)
    args=ap.parse_args()
    flow_path=args.flow.resolve()
    if not flow_path.is_relative_to(ROOT/'analysis/flow'):
        raise ValueError('Private discovery ledger required')
    flow=json.loads(flow_path.read_text())
    image=(ROOT/flow['image']).read_bytes()
    if hashlib.sha256(image).hexdigest()!=flow['image_sha256']:
        raise ValueError('Image identity mismatch')
    registry_path=ROOT/'docs/recovery/functions.json'
    registry=json.loads(registry_path.read_text())
    records=registry['records']
    known={(r['entries'][0]['segment'],r['entries'][0]['segment_offset']):r for r in records}
    next_id=max(int(r['id'].rsplit('-',1)[1]) for r in records)+1
    md=Cs(CS_ARCH_X86,CS_MODE_16)
    contracts=json.loads((ROOT/'docs/recovery/schemas/function-record.schema.json').read_text())['properties']['contract']['required']
    template=copy.deepcopy(records[0]['gates'])
    for gate in template.values():
        gate.update(status='pending',evidence_ids=[],scope='Not admitted by candidate discovery.')
    template['static_bytes'].update(status='passed',evidence_ids=['TD2EGA-UNPACK-V1'],scope='Image identity and candidate instruction coordinates only; code meaning/boundaries remain provisional.')
    def locator(s,o,n=1):
        return {'coordinate':'unpacked_module','path':flow['image'],'sha256':flow['image_sha256'],
                'offset':s*16+o,'length':n,'segment':s,'segment_offset':o,
                'relocation_state':'unrelocated','transform_id':'TD2EGA-UNPACK-V1'}
    for f in flow['functions']:
        s,o=(int(v,16) for v in f['entry'].split(':'))
        if (s,o) in known:
            continue
        spans=[]
        for ip in f['instructions']:
            ins=next(md.disasm(image[s*16+ip:s*16+ip+15],ip,count=1))
            if spans and spans[-1][1]==ip:spans[-1][1]=ip+ins.size
            else:spans.append([ip,ip+ins.size])
        contract={k:[] for k in contracts}
        contract.update(calling_convention='Unreviewed candidate; retain instruction-level RET/RETF/IRET distinctions until reviewed.',
                        stack_effect='Unreviewed; candidate flow does not infer a source signature.',
                        unresolved_indirect_edges=sorted({c['site'] for c in f['indirect']}))
        record={'schema_version':1,'record_type':'function','id':f'FN-EGA-{next_id:06d}',
                'edition_id':'DOS-EGA-SUPPLIED-EB4F8E88','status':'candidate','confidence':'tentative',
                'claim':'Syntactic direct/explicit-indirect discovery candidate; not recovered portable behavior.',
                'evidence':[{'method':'instruction_analysis','locator':locator(s,o),
                             'result':'Candidate traversal recorded in '+flow_path.relative_to(ROOT).as_posix(),
                             'scope':'Conservative flow; shared tails and indirect bounds may remain open.'}],
                'dependencies':['TD2EGA-UNPACK-V1'],'gates':copy.deepcopy(template),
                'unknowns':[{'description':'Source boundary, ABI, state ownership and semantics require instruction review.',
                             'blocking':True,'resolution':'Review private flow/listing, callers, segment changes and indirect writers before translation.'}],
                'names':[f'candidate_{s:04x}_{o:04x}'],'classification':'unknown',
                'entries':[locator(s,o)],'ranges':[locator(s,lo,hi-lo) for lo,hi in spans],
                'contract':contract,'callers':[],'callees':[],'data_dependencies':[],
                'portable_source':[],'validation_records':[],
                'notes':['Discovery only; a range can share instructions with another candidate.'],
                'updated_on':'2026-10-13'}
        records.append(record);known[(s,o)]=record;next_id+=1
    # Preserve established call relationships while adding syntactic discoveries.
    for f in flow['functions']:
        pair=tuple(int(v,16) for v in f['entry'].split(':'))
        owner=known[pair]
        targets={c['target'] for c in f['calls']}
        for c in f['indirect']:
            if c['kind'] in ('call','lcall'):targets.update(c.get('review',{}).get('targets',[]))
        for target in targets:
            callee=known.get(tuple(int(v,16) for v in target.split(':')))
            if not callee:continue
            owner['callees']=sorted(set(owner['callees']+[callee['id']]))
            callee['callers']=sorted(set(callee['callers']+[owner['id']]))
    registry['discovery_ledger']=flow_path.relative_to(ROOT).as_posix()
    registry['discovery_ledger_sha256']=hashlib.sha256(flow_path.read_bytes()).hexdigest()
    registry['candidate_policy']='Candidate entries retain pending semantic/build/differential gates. Counts are not code recovery or graph closure.'
    registry_path.write_text(json.dumps(registry,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'records':len(records),'new_next_id':next_id,'ledger':registry['discovery_ledger']},indent=2))


if __name__=='__main__':
    main()
