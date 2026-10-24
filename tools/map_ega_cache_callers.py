"""Inventory actual moving-cache call sites without admitting caller lifetimes."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence required')
    flow=json.loads(a.flow.read_text());image=(ROOT/flow['image']).read_bytes()
    if hashlib.sha256(image).hexdigest()!=flow['image_sha256']:raise ValueError('Image mismatch')
    records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    by={f"{r['entries'][0]['segment']:04X}:{r['entries'][0]['segment_offset']:04X}":r['id'] for r in records}
    targets={'06C9:70A3':4,'06C9:71B4':2,'06C9:72C6':4,'06C9:736B':4,'06C9:7490':4}
    md=Cs(CS_ARCH_X86,CS_MODE_16);sites={}
    for owner in flow['functions']:
        segment=int(owner['entry'].split(':')[0],16)
        for call in owner['calls']:
            if call['target'] not in targets:continue
            ip=int(call['site'].split(':')[1],16);at=segment*16+ip
            target_segment,target_ip=(int(v,16) for v in call['target'].split(':'))
            if image[at]!=0x9a or struct.unpack_from('<HH',image,at+1)!=(target_ip,target_segment):raise ValueError('Call encoding mismatch')
            following=next(md.disasm(image[at+5:at+20],ip+5,count=1))
            cleanup='immediate_ADD_SP' if following.mnemonic=='add' and following.op_str==f'sp, {targets[call["target"]]}' else 'caller_epilogue_or_other_path_requires_review'
            preceding=[]
            for earlier in owner['instructions']:
                if ip-24<=earlier<ip:
                    ins=next(md.disasm(image[segment*16+earlier:segment*16+earlier+15],earlier,count=1))
                    if ins.mnemonic=='push':preceding.append({'site':f'{segment:04X}:{earlier:04X}','operand':ins.op_str})
            row=sites.setdefault(call['site'],{'site':call['site'],'target_id':by[call['target']],'target':call['target'],
                 'owners':[],'argument_bytes':targets[call['target']],'cleanup_disposition':cleanup,
                 'following_instruction':{'site':f'{segment:04X}:{following.address:04X}','mnemonic':following.mnemonic,'operands':following.op_str},
                 'nearby_syntactic_pushes':preceding,
                 'caller_contract':'pending: allocation identity, actual buffer bounds, lifetimes and exclusion require perpath review'})
            row['owners'].append(by[owner['entry']])
    counts=Counter(r['target'] for r in sites.values())
    expected={'06C9:70A3':4,'06C9:71B4':4,'06C9:72C6':9,'06C9:736B':38,'06C9:7490':5}
    if dict(counts)!=expected:raise ValueError('Caller inventory expanded; review new scope before changing expectations')
    report={'schema':1,'result':'pass','image_sha256':flow['image_sha256'],
            'ledger_sha256':hashlib.sha256(a.flow.read_bytes()).hexdigest(),
            'function_registry_sha256':hashlib.sha256((ROOT/'docs/recovery/functions.json').read_bytes()).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'unique_call_sites':len(sites),
            'counts_by_target':dict(counts),'sites':sorted(sites.values(),key=lambda r:r['site']),
            'verified_scope':'Raw direct call encodings, stable IDs, argument byte contracts and nextinstruction cleanup disposition only.',
            'limits':['Nearby pushes are syntactic context, not dataflow proof or a complete argument reconstruction.',
                      'Shared tails retain all owners without multiplying call-site counts.',
                      'No caller lifetime, fullstate graph, resourceformat, completecore, DOS orgameplay acceptance.']}
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='sites'},indent=2))


if __name__=='__main__':main()
