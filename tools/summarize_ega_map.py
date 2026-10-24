"""Export payload-free candidate/edge/data dispositions from a private ledger."""
import argparse
from collections import Counter
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
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    output=a.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'docs/recovery/evidence'):
        raise ValueError('Fresh metadata evidence output required')
    g=json.loads(a.flow.read_text());data=(ROOT/g['image']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=g['image_sha256']:raise ValueError('Image mismatch')
    records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    by={(r['entries'][0]['segment'],r['entries'][0]['segment_offset']):r['id'] for r in records}
    md=Cs(CS_ARCH_X86,CS_MODE_16)
    code=set();starts=set(); sites={};functions=[];edges=[]
    for f in g['functions']:
        s,o=tuple(int(v,16) for v in f['entry'].split(':'))
        role='compiler_runtime_candidate' if s==0x13a8 else 'application_or_adapter_candidate'
        if f['entry'] in ('06C9:6907','06C9:69B7','06C9:61BF','13A8:049B'):role='installed_interrupt_handler'
        if f['entry'] in ('13A8:002E','13A8:007E','13A8:0163','13A8:03D3'):role='reviewed_mutable_platform_family_or_supplied_stub'
        owner=by[(s,o)]
        functions.append({'id':owner,'entry':f['entry'],'module_offset':f['module_offset'],
                          'instruction_locations':len(f['instructions']),'role':role,
                          'boundary_disposition':'Conservative candidate; shared tails allowed',
                          'contract_status':next(r['status'] for r in records if r['id']==owner),
                          'exits':f['exits'],'issues':f['issues']})
        for ip in f['instructions']:
            at=s*16+ip;ins=next(md.disasm(data[at:at+15],ip,count=1))
            starts.add(at);code.update(range(at,at+ins.size))
        for e in f['calls']:
            target=by[tuple(int(v,16) for v in e['target'].split(':'))]
            edges.append({'owner':owner,'target_id':target,**e})
        for e in f['indirect']:
            row=sites.setdefault(e['site'],{**e,'owners':[]})
            row['owners'].append(owner)
    auto=json.loads((ROOT/'analysis/exports/td2ega-v1/program-analysis.json').read_text())
    discovered_entries={f['module_offset'] for f in g['functions']}
    auto_only=[]
    for f in auto['functions']:
        off=f['entry_flat']-0x10000
        if off in discovered_entries:continue
        if off in starts:disposition='Interior/shared-body instruction; automatic function entry not independently admitted'
        elif off>=0x178f0:disposition='Principal-data-group automatic hypothesis; no admitted code entry'
        else:disposition='Unreached automatic candidate; not proven dead or admitted reachable'
        auto_only.append({'tool_entry':f['entry'],'module_offset':off,'disposition':disposition})
    # Mutually exclusive byte dispositions, with uncertainty explicitly retained.
    categories=Counter('syntactic_code' if i in code else 'principal_initialized_data_candidate' if i>=0x178f0 else 'unclassified_prefix_byte' for i in range(len(data)))
    # A literal two-word near unwind is a return convention, not a new
    # explicit indexed/indirect site or the saved-CS002C/PUSH/RET mechanism.
    unwind_context='docs/recovery/evidence/td2ega-record-dispatch-context-v1.json'
    unwind_path=ROOT/unwind_context
    unwind=json.loads(unwind_path.read_text())
    if unwind['result']!='pass' or data[0x6c90+0x585a:0x6c90+0x585c]!=bytes.fromhex('58c3'):
        raise ValueError('Two-word near unwind evidence mismatch')
    nonlocal_returns=[{'owner':'FN-EGA-000397','entry':'06C9:56ED',
        'sites':['06C9:585A','06C9:585B'],'operations':['POP AX','near RET'],
        'SS_words_consumed':2,'CS_effect':'preserved','AX_effect':'actual first SS word',
        'caller_owner':'FN-EGA-000395','caller_sites':['06C9:54F4','06C9:5581'],
        'caller_integration':'bounded53A6fullSScompositionpassed;whole403Bstate-open','composition':{'context':'docs/recovery/evidence/td2ega-mode-controller-context-v1.json','comparison':'docs/recovery/evidence/td2ega-mode-controller-validation-v3.json'},'scope':'Literal source return convention; no new explicit indirect-site/domain closure.',
        'context':{'path':unwind_context,'sha256':hashlib.sha256(unwind_path.read_bytes()).hexdigest()}}]
    write_context='docs/recovery/evidence/td2ega-write-span-context-v1.json'
    write_path=ROOT/write_context
    write_review=json.loads(write_path.read_text())
    if write_review['result']!='pass' or data[0x13a80+0x261f:0x13a80+0x2622]!=bytes.fromhex('83c408') or data[0x13a80+0x943]!=0xcb:
        raise ValueError('Inherited write-helper nonlocal far return evidence mismatch')
    nonlocal_returns.append({'owner':'FN-EGA-000316','entry':'13A8:2600',
        'sites':['13A8:261F','13A8:2646','13A8:2649','13A8:264A','13A8:0940','13A8:0942','13A8:0943'],
        'operations':['ADD SP,8','MOV SP,SS:[actual BP-8]','POP SI','POP DI','MOV SP,actual BP','POP BP','far RET'],
        'discarded_near_context_bytes':8,'shared_SS_restores':['SI','DI'],
        'far_frame_from_actual_BP':True,'CS_effect':'actual far-return segment word',
        'AX_effect':'path-dependent actual service or mapped FFFF; stack ADD replaces service CF',
        'caller_owner':'FN-EGA-000315','caller_sites':['13A8:25DA','13A8:25E5','13A8:25F0'],
        'caller_integration':'bounded2600near-and-nonlocal-farpaths passed; whole2558/fatalcallbacks open',
        'composition':{'context':write_context,'comparison':'docs/recovery/evidence/td2ega-write-span-validation-v1.json'},
        'scope':'Literal near helper can bypass enclosing parent through shared far epilogue; explicit indexed/indirect-site totals unchanged.',
        'context':{'path':write_context,'sha256':hashlib.sha256(write_path.read_bytes()).hexdigest()}})
    report={'schema':1,'image_sha256':g['image_sha256'],'ledger_sha256':hashlib.sha256(a.flow.read_bytes()).hexdigest(),
            'function_registry_sha256':hashlib.sha256((ROOT/'docs/recovery/functions.json').read_bytes()).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'function_candidates':len(functions),'functions':functions,'direct_calls':edges,
            'nonlocal_return_conventions':nonlocal_returns,
            'indirect_site_count':len(sites),'indirect_sites':sorted(sites.values(),key=lambda r:r['site']),
            'automatic_only_dispositions':auto_only,'byte_dispositions':dict(categories),
            'semantic_gate':'Pending for candidates; reviewed indirect mechanisms do not admit their surrounding function semantics.',
            'limits':['No complete graph, unreachable-code, resource-codec or game-state acceptance.',
                      'Byte categories are conservative: untraversed prefix retains code/data/padding ambiguity.',
                      'Principal initialized-data classification is a candidate group ownership, not an embedded-resource format.',
                      'Module offsets compare automatic candidates without equating differently segmented near-control semantics.']}
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('functions','direct_calls','indirect_sites','automatic_only_dispositions')},indent=2))


if __name__=='__main__':main()
