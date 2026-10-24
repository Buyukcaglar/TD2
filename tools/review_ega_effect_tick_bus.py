"""6269 actual SS, literal command words, flags liveness and raw word envelope."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
    gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());f=next(v for v in g['functions'] if v['entry']=='06C9:6269');md=Cs(CS_ARCH_X86,CS_MODE_16)
    def row(ip):
        i=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1));return {'site':f'06C9:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}
    observations=[row(ip) for ip in f['instructions']];assert len(observations)==140 and not f['calls']
    assert all(row(ip)['bytes']=='cb' for ip in [0x6287,0x62a2,0x62fc,0x6323])
    assert not any(v['text'].split()[0] in ['push','pop','pushf','popf','cli','sti','cld','std'] for v in observations)
    targets=[0x62fd,0x634c,0x635b,0x6370,0x6385,0x639a,0x63b4,0x63ce,0x63e8,0x63ff,0x6416]
    words=list(struct.unpack_from('<11H',image,0x6c90+0x6336));assert words==targets
    assert row(0x632f)['bytes']=='2effa73463' and row(0x62e3)['bytes']=='d3e8' and row(0x62e8)['bytes']=='32ff'
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    offset,length=0x178f0+0x5f2e,256;assert offset+length<=len(image)
    relocation_hits=[v for v in relocs if v<offset+length and v+2>offset];assert not relocation_hits
    code={int(v['entry'][:4],16)*16+ip+delta for v in g['functions'] for ip in v['instructions'] for delta in range(next(md.disasm(image[int(v['entry'][:4],16)*16+ip:int(v['entry'][:4],16)*16+ip+15],ip,count=1)).size)}
    assert not code.intersection(range(offset,offset+length))
    deps=['analysis/history/effect-tick-bus-build-setup-v2.json','analysis/history/effect-tick-bus-refinement-v2.json','analysis/history/effect-tick-bus-validation-preparation-v2.json','analysis/reviews/effect-tick-bus-frontier-v1.json','docs/recovery/evidence/td2ega-effect-tick-validation-v1.json','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json']
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'flow_ledger':gp,'flow_ledger_sha256':hashlib.sha256((ROOT/gp).read_bytes()).hexdigest(),'instruction_sites_in_fence':140,'instruction_observations':observations,'near_command_words':[{'slot':i+1,'CS_offset':0x6336+2*i,'initial_target':targets[i]} for i in range(11)],'external_span_candidates':[{'group_offset':0x5f2e,'module_offset':offset,'length':length,'sha256':hashlib.sha256(image[offset:offset+length]).hexdigest(),'relocation_intersections':relocation_hits,'syntactic_code_intersections':0,'scope':'Initialized128-word raw index envelope. Positive note1..127 reads words1..127; note0 is a rest and does not read word0. No pitch/frequency/format/ownership/lifetime claim.'}],'facts':[
        '6269 is far/noargs with four plain RETF exits and no own stack saves/CALLs/IF-DF changes. Actual SS far words are read after body effects; changed words reported without following raw control. SP>FFFC qualifies before RET after prior effects.',
        'CurrentDS selects fields/source pointer/table and may differ from principalDS in explicit profiles; ES is loaded from current5EEE. BP/DX/DI/DS are preserved by source; raw ports preserve IF/DF.',
        'TEST5EFB,1 then CMP5EF6,0; active countdown MOVAX old5EF6, DEC/store, CMPAX current5EF8. That final CMP can returnCF1 when oldAX<threshold. Other normal returns follow AND/OR byte logic and CF0; no blanketCF0 contract.',
        'JS after loop-counter DEC tests the stored result sign, including8000->7FFF; it does not testSFxorOF. DEC/INC preserve incomingCF, ADDpointer redefines arithmetic flags.',
        '62E3 SHRAX,CL uses a named masked-five-bit count profile; its flags have no consumer before62E8 XORBH,BH. The intervening store does not read FLAGS. Native prefixes occur at loop/ports/RET boundaries, outside that dead interval. No historicalCPU/async IRQ qualification.',
        'Negative byte NEG then unsignedBX<=11 bound; currentCS:6334+BX*2 is read literally. Recognized target words dispatch by current offset even if swapped; unknown targets stop before632FJMP/native6 and are never followed. Initialelevenwords alone do not prove allwriters/domain.',
        'Positive note1..127 indexes currentDS5F30..602C word starts; containing initialized5F2E..602D raw envelope is256bytes. Note0 bypasses table. Ordinaryword adjacent-byte20bit wrap and effective-offset wrap remain distinct.',
        'Raw256byte view is outside known7774 DAT copy346A..52C7. Initialized identity/no code or relocation overlap does not prove runtimeDS binding, allwriters, actual note corpus, duration/pitch units, storage capacity/lifetime or sound output.',
        'Port service may mutate bus memory in explicit profiles; ownCPUwrites remain independently counted, service mutations separate. Source/code/CS table executing instruction integrity and absence of async writes remain explicit profile assumptions.',
        'Actual3F40 registers6269/currentCS before403B/currentCS. Whole6269-then403B composition, realIRQ/nesting/sharedsource-reset-lifetime-exclusion/core/P1-GATE remainopen. Physical086Cunassigned/CGAbehindEGAclosure.'
    ],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Static140-site farABI/currentDS-SS/FLAGS-liveness/literalCSwords/raw256byteview review only. Whole original comparison/native diagnostics/registration and actual callback-order composition required. No DOSsession/realdevices/audio/fullresources/complete-state-machine/gameplay/fidelity.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','sites':140,'literal_command_words':11,'raw_word_envelope':256}))
if __name__=='__main__':main()
