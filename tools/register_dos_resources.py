"""Register immutable DOS identities and tentative family consumers.

Does not decode, copy or publish original resource bytes. Existing IDs must
agree with path identity; format and per-file behavioral gates stay pending.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ownership',type=Path,required=True)
    a=ap.parse_args();ownership=json.loads(a.ownership.read_text())
    manifest_path=ROOT/'docs/planning/evidence/reference-manifest.json'
    manifest=json.loads(manifest_path.read_text());manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    functions=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    ids={f"{r['entries'][0]['segment']:04X}:{r['entries'][0]['segment_offset']:04X}":r['id'] for r in functions}
    template=copy.deepcopy(functions[0]['gates'])
    for g in template.values():g.update(status='pending',evidence_ids=[],scope='No resource format/perfile behavioral acceptance from identity/family mapping.')
    template['static_bytes'].update(status='passed',evidence_ids=['DOS-REFERENCE-MANIFEST'],scope='Supplied file identity verified separately by custody audit.')
    template['compilation'].update(status='not_applicable',scope='Metadata registry is not compiled code; future readers require their own build evidence.')
    rows=[]
    files=sorted((r for r in manifest['files'] if r['path'].startswith('reference/dos/')),key=lambda r:r['path'].casefold())
    for index,r in enumerate(files,1):
        ext=Path(r['path']).suffix.lower();family=ownership['families'][ext]
        name=Path(r['path']).name.lower()
        role='unknown'
        if ext=='.exe':role='executable_container'
        if ext=='.pes':role='graphics'
        if ext=='.fnt':role='font'
        if ext=='.sgn':role='route_data'
        if ext=='.ss':role='game_text'
        if ext=='.bin':role='audio' if name in ('voices.bin','songs.bin') else 'car_data'
        if ext=='.dat':
            role='catalog' if name in ('cars.dat','scenes.dat') else 'mutable_metadata' if name=='select.dat' or name.endswith('hisc.dat') else 'route_data' if name!='diskid.dat' else 'unknown'
        loc={'coordinate':'packed_file' if ext=='.exe' else 'resource_file','path':r['path'],'sha256':r['sha256'],'offset':0,'length':r['bytes']}
        rows.append({'schema_version':1,'record_type':'resource','id':f'RS-DOS-{index:06d}',
                     'edition_id':'DOS-SUPPLIED-'+manifest_hash[:8].upper(),'status':'consumer_candidate','confidence':'tentative',
                     'claim':'Immutable file identity; tentative family consumer role only. Perfile semantic/format admission remains pending.',
                     'evidence':[{'method':'raw_bytes','locator':loc,'result':'Size/hash from supplied baseline; family '+family['id'],
                                  'scope':'Identity and scoped family mapping, not format or liveness proof.'}],
                     'dependencies':['DOS-REFERENCE-MANIFEST'],'gates':copy.deepcopy(template),
                     'unknowns':[{'description':'Exact consumer, ownership/lifetime, field schema, bounds and exceptions need perfile evidence.',
                                  'blocking':True,'resolution':'Close raw EGA/CGA consumer contracts and phase2 full-corpus schema validation.'}],
                     'logical_path':r['path'],'locations':[loc],'role':role,'media_custody':'original_media_external',
                     'consumers':sorted({ids[entry] for entry in family['interfaces'] if entry in ids}),
                     'writers':[],
                     'format_contract':{'byte_order':'unknown','fields_and_units':[],'compression':[],
                                        'bounds':[],'termination':'Unknown; no schema admitted.',
                                        'error_behavior':'Pending consumer review.','unexplained_ranges':[loc]},
                     'disposition':family['scope']+' Consumer IDs are family candidates, not perfile acceptance; absence from writers is not proof of no writes.',
                     'validation_records':[a.ownership.resolve().relative_to(ROOT).as_posix()]})
    e=ownership['embedded_byte_source'];image_path='analysis/derived/td2ega-v1/TD2EGA.image.bin'
    loc={'coordinate':'unpacked_module','path':image_path,'sha256':ownership['image_sha256'],'offset':e['module_offset'],
         'length':e['length'],'segment':0x178f,'segment_offset':0x66e6,'relocation_state':'unrelocated','transform_id':'TD2EGA-UNPACK-V1'}
    embedded=copy.deepcopy(rows[0]);embedded.update(id=e['id'],edition_id='DOS-EGA-SUPPLIED-EB4F8E88',status='schema_partial',confidence='supported',
        claim='External initialized cursor+256byte source state, shared by application and timer consumers; reset/alias/scheduling obligations remain.',
        logical_path='reference/dos/TD2EGA.EXE#byte-source-initial-state',locations=[loc],role='other',
        consumers=['FN-EGA-000003'],writers=['FN-EGA-000003'],
        dependencies=['TD2EGA-UNPACK-V1'],evidence=[{'method':'raw_bytes','locator':loc,
        'result':'Initialcursor0;spanSHA256 '+e['span_sha256'],'scope':'Initialized state provenance; no original table bytes copied.'}],
        format_contract={'byte_order':'little','fields_and_units':['Offset0:length2 cursor initialvalue0;offset2:length256 mutable byte state'],
                         'compression':[],'bounds':['258byte initialized span; cursor andtable disjoint.'],
                         'termination':'Fixedlength state, not a terminated stream.',
                         'error_behavior':'Initialization requires admitted externalimage/span; implementation pending.',
                         'unexplained_ranges':[]},
        disposition=e['publication']+' '+e['ownership'])
    embedded['unknowns']=[{'description':'Full reset/indexed alias ownership, main/IRQ masking and consumption order not closed.',
                          'blocking':True,'resolution':'P1-05/06/07 writer and scheduling review before core integration.'}]
    rows.append(embedded)
    path=ROOT/'docs/recovery/resources.json'
    if path.exists():
        previous=json.loads(path.read_text())['records']
        if {r['id']:r['logical_path'] for r in previous}!={r['id']:r['logical_path'] for r in rows}:raise RuntimeError('Existing resource IDs/path identity differ')
        raise FileExistsError('Registry exists; merge reviewed updates explicitly rather than replacing it')
    path.write_text(json.dumps({'schema':1,'records':rows,'policy':'Family candidate consumers androles do not pass perfile contract/schema/runtime gates.'},indent=2)+'\n')
    print(json.dumps({'resource_records':len(rows),'external_files':len(files),'embedded_states':1},indent=2))


if __name__=='__main__':main()
