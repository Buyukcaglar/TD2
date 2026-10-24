"""Audit actualSS timer startup and the complete published-caller corpus."""
import argparse,ast,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def digest(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def corpus(p):
    tree=ast.parse((ROOT/p).read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    first=next(i for i,n in enumerate(main.body) if isinstance(n,ast.FunctionDef) and n.name=='case')
    last=next(i for i,n in enumerate(main.body[first:],first) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='vectors' for t in n.targets for x in ast.walk(t)))
    return '\n'.join(ast.dump(n,include_attributes=False) for n in main.body[first:last])

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();out=args.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());md=Cs(CS_ARCH_X86,CS_MODE_16)
    entries=['06C9:601C','06C9:6059','06C9:610A'];fence={ip for f in graph['functions'] if f['entry'] in entries for ip in f['instructions']};assert len(fence)==91
    rows={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    for ip,expected in {0x601c:'55',0x6059:'55',0x6061:'f77e06',0x6064:'a3985e',0x6067:'a39a5e',0x606a:'8b5606',0x6108:'5d',0x6109:'cb',0x6118:'cb',0x6122:'cb',0x614b:'cb'}.items():assert rows[ip].bytes.hex()==expected,(hex(ip),rows[ip].bytes.hex())
    callers=[dict(owner=f['entry'],**e) for f in graph['functions'] for e in f['calls'] if e['target'] in entries];assert len(callers)==7 and all(e['kind']=='lcall' for e in callers)
    faults=[]
    for raw in range(65536):
        d=raw if raw<32768 else raw-65536;q=None if d==0 else (65536//abs(d))*(1 if d>0 else -1)
        if q is None or not -32768<=q<=32767:faults.append(raw)
    assert faults==[0,1,2,65535]
    original=corpus('tools/validate_state_tick_bus.py');extended=corpus('tools/validate_timer_full_state_tick.py');assert original==extended
    comparison=json.loads((ROOT/'docs/recovery/evidence/td2ega-timer-full-state-tick-v2.json').read_text());c=comparison['fixture_coverage'];assert comparison['result']=='pass' and comparison['vectors']==25024 and comparison['root_instruction_sites_exercised']==80
    assert sum(c.get(k,0) for k in ['root_far_RETF','raw_child_return','prefix_3','prefix_6'])==25024 and c['actual6269_callbacks']==c['actual403B_callbacks']==25024
    assert c['PUSHF_words']==448 and c['mode_nonlocal_exits']==256 and c['actual_780E_entries']==192 and c['root_CALLs']==97472
    assert len([v for k,v in c.items() if k.startswith('form_') and v==3128])==8
    deps=['analysis/flow/indirect-v8/direct-flow.json','analysis/reviews/timer-startup-bus-frontier-v1.json','analysis/history/timer-control-bus-build-setup-v1.json','src/recovered/td2ega_timer_control_bus.c','src/recovered/td2ega_timer_control_bus.h','tools/validate_timer_control_bus.py','tools/validate_state_tick_bus.py','tools/validate_timer_full_state_tick.py','docs/recovery/evidence/td2ega-timer-full-state-tick-v2.json','docs/recovery/evidence/intel-idiv-reference-v1.json']
    record={'schema':1,'result':'pass','image_sha256':hashlib.sha256(image).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'function_ids':['FN-EGA-000147','FN-EGA-000148','FN-EGA-000149'],'instruction_sites_in_fence':91,'direct_callers':callers,'all_word_IDIV_words':65536,'faulting_words':faults,'published_caller_case_corpus_ast_sha256':hashlib.sha256(original.encode()).hexdigest(),'complete_previous_case_corpus_retained':True,'validator_dependencies':[{'path':p,'sha256':digest(p)} for p in deps],'facts':[
        '601C/6059 save actual BP, then POP the actual word and plain farRET; no argument cleanup. 610A has no save and three farRET sites. CurrentDS and inheritedSS are independent; writes can alter later argument/IVT/root reads.',
        '6059 literal signed DX:AX=0001:0000 division faults for0/1/2/FFFF only. Successful IDIV leaves arithmetic flags unexposed: F72A, including unknownCF. 6064/6067 publish quotient before606A rereads actualSS:[BP+6]. Later port40 uses the reread word, including aliases.',
        'Offset and segment IVT comparisons are independent. Matching segment can skip installation even for a different offset. Cleanup requires both exact currentCS and61BF. Do not normalize these guards into an interchangeable whole-pointer test.',
        'Entry and 40 histogram-head budgets and byte-port budgets are analysis boundaries. Port adapter writes are distinct from CPU writes; full RAM is compared, with no stack exclusion. Qualified preIDIV/preRET stops do not claim historical exception/wrap behavior.',
        'Full published61BF->6269->403B corpus retains the exact nine AST case-generation nodes of accepted whole403B, all25024 cases/all8 stable forms/two loads. Parent SP is clamped68..FFE0 and actual403B SP is parentSP-22, preserving admitted aliases while adjusting endpoint fixtures.',
        'Caller receipt covers all80 root sites/11rootCALLs/97472calls/448PUSHF/192actual780E/256nonlocal exits. 1309 of3024 union sites exercised; separate callee-unit coverage does not become whole-caller coverage. 2304 keycallback ABI-effects/genericRETF operations remain separate from actual callback bodies.',
        'Original3FD9 producer16executions/3376instructions/78sites only seeds actual6269-403B publication. Native producer and614C liveSS publication lifetime/IRQ exclusion still need recovery. 614C unmasked6176-before6179 window is retained as a potential static window, not a proved historical failure.',
        'No clock units/physical086C semantics, actual IRQ/delivery/nesting/allwriters/reset/lifetime/core/P1-GATE or game/fidelity acceptance. CGA remains behind EGA closure.'
    ],'limits':'Static ABI/arithmetic/caller-corpus preservation review. Original/native comparison and native diagnostics retain their independent scopes; no native startup-producer acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','sites':91,'direct_callers':len(callers),'corpus_cases':25024}))
if __name__=='__main__':main()
