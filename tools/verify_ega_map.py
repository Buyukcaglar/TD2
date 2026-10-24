"""Verify EGA mapping identities and specific reviewed control-flow invariants.

These are static bookkeeping/byte checks, not proof of all code semantics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
ROOT=Path(__file__).resolve().parents[1]


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True)
    ap.add_argument('--review',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    out=args.output.resolve()
    require(out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh evidence path required')
    flow=json.loads(args.flow.read_text());review=json.loads(args.review.read_text())
    data=(ROOT/flow['image']).read_bytes()
    require(hashlib.sha256(data).hexdigest()==flow['image_sha256']==review['image_sha256'],'Image mismatch')
    require(flow['script_sha256']==hashlib.sha256((ROOT/'tools/map_ega_flow.py').read_bytes()).hexdigest(),'Discovery script drift')
    require(flow['resolutions_sha256']==hashlib.sha256(args.review.read_bytes()).hexdigest(),'Review drift')
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())
    by={f['entry']:f for f in flow['functions']}
    ids={r['id'] for r in registry['records']}
    pairs={(r['entries'][0]['segment'],r['entries'][0]['segment_offset']) for r in registry['records']}
    require(len(ids)==len(registry['records'])==len(pairs),'Duplicate registry entry/ID')
    require(all(tuple(int(v,16) for v in address.split(':')) in pairs for address in by),'Unregistered graph entry')
    require(flow['overlap_byte_count']==0 and not any(f['issues'] for f in by.values()),'Instruction boundary/flow issues')
    sites={c['site']:c for f in by.values() for c in f['indirect']}
    require(all(c.get('review')==review['sites'].get(site) for site,c in sites.items()),'Missing/stale site review')
    def addr(s):
        a,b=(int(v,16) for v in s.split(':'));return a*16+b
    checked=[]
    def table(site,segment,offset,indices,far=False):
        expected=set()
        for i in indices:
            at=segment*16+offset+i*(4 if far else 2)
            if far:
                ip,cs=struct.unpack_from('<HH',data,at)
            else:
                ip=struct.unpack_from('<H',data,at)[0];cs=int(site.split(':')[0],16)
            expected.add(f'{cs:04X}:{ip:04X}')
        require(set(review['sites'][site]['targets'])==expected,'Table mismatch '+site)
        checked.append(site)
    table('06C9:6DE9',0x6c9,0x6e2e,range(2),True)
    table('0432:206A',0x432,0x211a,range(7))
    table('06C9:1432',0x178f,0x12da,range(1,21))
    table('06C9:2F90',0x178f,0x2c36,range(1,21))
    table('13A8:1319',0x13a8,0x13fe,range(22))
    table('13A8:1AB3',0x13a8,0x1bac,range(22))
    table('13A8:2C5F',0x13a8,0x2c10,range(6))
    if '06C9:7667' in review['sites']:table('06C9:7667',0x6c9,0x766c,range(1,6))
    if '06C9:632F' in review['sites']:table('06C9:632F',0x6c9,0x6334,range(12))
    if '06C9:44BA' in review['sites']:table('06C9:44BA',0x178f,0x33dc,range(5))
    main=by['0000:07B3'];near=[c for c in main['calls'] if c['kind']=='call']
    require(len(main['instructions'])==360 and len(main['calls'])==56 and len(near)==8,'Main traversal discrepancy')
    require(all(data[addr(c['site'])-1]==0x0e for c in near),'Missing pushed-CS far frame')
    ring=sorted({c['site'] for f in by.values() for c in f['calls'] if c['target']=='06C9:780E'})
    require(set(ring)=={'019E:000A','0267:0A59','0267:19D8','06C9:1E79',
                        '06C9:46F4','06C9:4713','06C9:475B','06C9:4A41'},'Caller inventory changed; review new context')
    require(all(data[addr(s)]==0x9a and struct.unpack_from('<HH',data,addr(s)+1)==(0x780e,0x6c9) for s in ring),'Ring caller encoding mismatch')
    for s in ['06C9:5D88','06C9:5D95']:
        require(data[addr(s)]==0x26 and data[addr(s)+1]==0xa1 and struct.unpack_from('<H',data,addr(s)+2)[0]==0x46c,'External read offset drift')
    # Check normalized MZ relocations at segment-bearing callback table words.
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted normalized MZ')
    n,tableoff=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    reloc={struct.unpack_from('<H',mz,tableoff+i*4)[0]+16*struct.unpack_from('<H',mz,tableoff+i*4+2)[0] for i in range(n)}
    required=[0x6c90+0x6e30,0x6c90+0x6e34,0x178f0+0x64de,0x178f0+0x7084]
    require(all(v in reloc for v in required),'Missing farpointer relocation')
    literal_fields=[0x6c90+v for v in (0x5d84,0x5d8a,0x5d91,0x5d97,0x1bf9,0x1bff)]
    require(not any(v in reloc for v in literal_fields),'Anomalous segment/displacement fields are relocations; revise contracts')
    context=json.loads((ROOT/'docs/recovery/evidence/td2ega-context-v1.json').read_text())
    require(context['result']=='pass' and context['image_bytes_unchanged'] and len(context['fixed_context_ranges'])==17,'Context reconciliation incomplete')
    anomaly=json.loads((ROOT/'docs/recovery/evidence/td2ega-external-word-validation-v2.json').read_text())
    require(anomaly['result']=='pass' and anomaly['vectors']==60,'External reader validation missing')
    require(anomaly['script_sha256']==hashlib.sha256((ROOT/'tools/validate_external_word.py').read_bytes()).hexdigest(),'External harness drift')
    result={'schema':1,'result':'pass','scope':'Static map identity, registry/edge coverage and selected raw-byte/relocation invariants only.',
            'image_sha256':flow['image_sha256'],'verification_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'function_candidates':len(by),'registered_records':len(registry['records']),
            'indirect_sites':len(sites),'sites_with_reviewed_mechanism':len(sites),
            'sites_with_open_bounds_or_writers':sum(not c['review']['complete'] for c in sites.values()),
            'bounded_table_sets_checked':checked,'main_near_calls_with_cs_frames':len(near),
            'ring_direct_call_sites':ring,'callback_segment_relocations_checked':len(required),
            'separate_gates':'Complete portable EGA/CGA recovery, runtime, rendering, audio and fidelity remain pending.'}
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
