"""Review actual SS, near/far/INT frames and FLAGS liveness for61BF/6230."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    gp='analysis/flow/indirect-v8/direct-flow.json';graph=json.loads((ROOT/gp).read_text());byentry={f['entry']:f for f in graph['functions']};md=Cs(CS_ARCH_X86,CS_MODE_16)
    def row(ip):
        v=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1));return {'site':f'06C9:{ip:04X}','bytes':v.bytes.hex(),'text':v.mnemonic+' '+v.op_str}
    roots=[byentry[v] for v in ['06C9:61BF','06C9:6230']];sites={ip for f in roots for ip in f['instructions']};assert len(sites)==71 and len(roots[0]['instructions'])==53 and len(roots[1]['instructions'])==18
    required={0x61bf:'fa',0x61c0:'1e',0x61c1:'06',0x61c2:'50',0x61c3:'53',0x61c4:'51',0x61c5:'52',0x61c6:'56',0x61c7:'57',0x61c8:'55',0x61d2:'fb',0x61f0:'e83d00',0x6216:'fa',0x6217:'ff9d125f',0x621b:'83c704',0x6226:'5d',0x6227:'5f',0x6228:'5e',0x6229:'5a',0x622a:'59',0x622b:'5b',0x622c:'58',0x622d:'07',0x622e:'1f',0x622f:'cf',0x6259:'cd08',0x6268:'c3'}
    for ip,raw in required.items():assert row(ip)['bytes']==raw,(hex(ip),row(ip))
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)};assert 0x6c90+0x61ce in relocs
    reference=json.loads((ROOT/'docs/recovery/evidence/intel-int-real-mode-reference-v1.json').read_text());assert reference['result']=='pass'
    deps=['analysis/history/timer-handler-bus-build-setup-v3.json','analysis/history/timer-handler-bus-build-repair-v2.json','analysis/history/timer-handler-bus-refinement-v3.json','docs/recovery/evidence/intel-int-real-mode-reference-v1.json','docs/recovery/evidence/td2ega-state-tick-bus-context-v2.json','docs/recovery/evidence/td2ega-state-tick-bus-validation-v5.json','docs/recovery/evidence/td2ega-timer-callback-lifetime-v1.json']
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'flow_ledger':gp,'flow_ledger_sha256':hashlib.sha256((ROOT/gp).read_bytes()).hexdigest(),'instruction_sites_in_fence':71,'instruction_observations':[row(ip) for ip in sorted(sites)],'root_site_counts':{'61BF':53,'6230':18},'source_stack':{'handler_saved_words':9,'handler_saved_bytes':18,'far_callback_frame_bytes':4,'403B_minimum_SP':46,'proposed_handler_minimum_SP':68,'bridge_INT_frame_bytes':6,'handler_entry_return':'existing IP-CS-FLAGS six-byte IRET frame','bridge_entry_return':'existing near IP word'},'facts':[
        'CLI precedes PUSH DS/ES/AX/BX/CX/DX/SI/DI/BP; EOI occurs with IF0, then relocated DS becomes load+178F and STI opens an interrupt window. SS is inherited.',
        'JG after DEC5E9A/5E96 uses SF/OF/ZF. Old values2..7FFF alone are positive;8000 wraps7FFF with OF1 and still takes rollover. Counter pairs5E90/92 and5E8C/E have no assigned units.',
        '61F0 near CALL pushes61F3. 6230 edits IVT20/22 through ES0, executes INT08, then writes61BF/currentCS through returned ES and nearRET. DS/ES/BP are not implicitly restored by the foreign adapter.',
        'Named real-address INT profile pushes FLAGS-CS-IP before reading vector. WholeSS/IVT aliases must use post-frame bytes. Explicit AF0/1 storage profile follows6247XOR; flags remain arithmetically unmodified before6259INT.',
        '6217 far target comes from currentDS:[DI+5F12] and is captured before the far frame. Segment0 sentinel is tested by MOVAX/ORAX beforeCLI. Each retired child CS-IP-SP is checked before continuation.',
        'No five-row clamp or local reentry guard. Returned DI andDS select the next callback pair after actual ADDDI4. Unbounded cycles require a diagnostic budget, not invented source termination.',
        '621BADDDI4 defines arithmetic flags before the next callback ORAXAX. A403B adapter need not invent unexposed child arithmetic flags; CF/IF/DF and actual SS remain explicit.',
        '6226..622E restore actual SS words;622F IRET restores actual IP/CS/FLAGS and reports raw root coordinates without following. Saved-word/root-frame corruption is not discarded by a live-stack exclusion.',
        'Callback/oldIRQ generic RETF/IRET ABI profiles are separate from actual403B/6269 body composition, real IRQ delivery, nested scheduling, allwriters/reset/source-storage lifetime/exclusion and complete-core acceptance.',
        'SP68 derives18+4+46 to permit later403B composition; current handler-only body evidence does not itself execute403B. Standalone6230 minimum6 covers explicit INT frame. Incoming/systemFLAGS and backend return boundaries remain qualified.'
    ],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Static71-site actualSS/near-far-INT-IRET/FLAGS-liveness/context review only; pending original comparison and actualcallback composition. No realIRQ/device/historicalCPU/core/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','sites':71,'saved_words':9,'proposed_handler_SP_min':68}))
if __name__=='__main__':main()
