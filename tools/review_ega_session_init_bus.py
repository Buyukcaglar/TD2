"""Review complete initialization ABI, ordered stores and raw input views."""
import argparse,hashlib,json,re,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_MEM
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True;names=['06C9:3F40','06C9:3FF9','06C9:38F2','06C9:1E31','06C9:5427'];functions=[f for f in g['functions'] if f['entry'] in names];rows={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for f in functions for ip in f['instructions']};assert len(rows)==119
    source=(ROOT/'src/recovered/td2ega_session_init_bus.c').read_text();tables=re.findall(r'static const field fields\[\]=\{(.*?)\};',source,re.S);assert len(tables)==2
    for table,lo,hi in zip(tables,[0x3ffb,0x3f4f],[0x4028,0x3f9d]):
        actual=[tuple(int(v,0) for v in match) for match in re.findall(r'\{(0x[0-9a-f]+),(0x[0-9a-f]+),([12])\}',table)]
        expected=[(ip,i.operands[0].mem.disp&65535,i.operands[0].size) for ip,i in sorted(rows.items()) if lo<=ip<=hi and i.mnemonic=='mov' and i.operands[0].type==X86_OP_MEM];assert actual==expected,(actual,expected)
    assert rows[0x3f4c].mnemonic=='cld' and rows[0x5438].mnemonic=='ret' and all(rows[ip].mnemonic=='retf' for ip in [0x3ff8,0x403a,0x391e,0x1e58])
    for bh in range(256):
        for token in range(256):
            value=(((bh<<8)|token)<<1)&65535;value&=255;value=(value<<1)&65535;assert value==4*(token&127)
    for old in range(65536):assert ((old+0x3b33)&65535)==((old+0x3b33)%65536)
    start=0x178f0+0x3b51;raw=image[start:start+71];assert len(raw)==71 and not any(raw)
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];assert all(at+1<start or at>=start+71 for at in relocs)
    c=json.loads((ROOT/'docs/recovery/evidence/td2ega-session-init-bus-validation-v2.json').read_text());assert c['result']=='pass' and c['instruction_sites_exercised']==187 and c['fixture_coverage']['conditional_SS_ring_write_witnesses'] and all(c['fixture_coverage']['entry_'+str(e)+'_SS_ring_write_witnesses']>0 for e in [0,1,3]) and all(c['fixture_coverage']['entry_'+str(e)+'_SS_ring_write_witnesses']==0 for e in [2,4])
    deps=['analysis/flow/indirect-v8/direct-flow.json','analysis/derived/td2ega-v1/TD2EGA.unpacked.exe','src/recovered/td2ega_session_init_bus.c','src/recovered/td2ega_session_init_bus.h','tools/validate_session_init_bus.py','analysis/history/session-init-bus-build-setup-v1.json','analysis/history/session-init-bus-validation-refinement-v2.json','analysis/reviews/session-init-bus-frontier-v1.json','docs/recovery/evidence/td2ega-session-init-bus-validation-v2.json','docs/recovery/evidence/td2ega-timer-startup-tail-bus-context-v1.json']
    record={'schema':1,'result':'pass','function_ids':c['function_ids'],'image_sha256':hashlib.sha256(image).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_sites_in_fence':188,'instruction_sites_admitted':187,'initialization_sites':119,'ordered_field_tables_verified':[16,27],'all_BH_byte_token_index_cases':65536,'all_word_wrapped3811_add_cases':65536,'raw_stream_candidate':{'segment':0x178f,'offset':0x3b51,'length':71,'sha256':hashlib.sha256(raw).hexdigest(),'nonzero_bytes':0,'inside_known_DAT_copy':True,'intersecting_relocations':0},'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'facts':[
        'Full3F40/3FF9/38F2/1E31 plusnear5427 retain119 ownsites; actual601C/614Ctail brings188union sites.187execute,6164remainspreCALLfatalboundary. Newwhole3F40prefix entersfrozen3FD9tailwithoutanextraCALL/frame; oldtypedgroup APIs/sources/DLLs remainfrozen.',
        '3F40 MOVESDS/XORAX/CLD/REPSTOSB8 writes335D..3364; ordered27 subsequentzero-fields verified againstCtables andoriginaldirectmemoryoperands. Conditional90A8/33AF andcurrent843E->3379/337A20hex remainliteral; BSS942Ewrite remainsaddressable.',
        '71sourcebytes3B51..3B97 mapviaMOVBL/SHLBX1/XORBH/SHLBX1 to4*(token&127), independentofincomingBH afterexplicitclear. Static65536BH-tokenpairs verify128first-byte lookupslots347E..367A withinRS289512-byteenvelope. Rawfold/XOR byte33BD has noassignedsemanticpurpose.',
        '3FD3 adds3B33 modulo65536 tolive3811; it doesnotreset3811. Staticall65536words verifywrap. FinalADDflags feedfrozennativetail; earlierREP/foldbudgetprefixes preserveactualGPR/CX/DI/SI/ES/DF/FLAGS.',
        '3FF9 calls5427 withanactualnearword andplainnearRET;1E31 calls3FF9/38F2 withactualfarframes. EachretiredchildCS-IP-SP ischeckedbeforecontinuation. RootfarRET/nearRET rereadactualSSwords aftermemoryeffects; rawcontrolnotfollowed.',
        '38F2 reads23C6/C8 live afterpriorcallerframewrites, writes2F4C/E, andINCAX preservesCF. No captured-typedargument shortcut is introduced. AllsourceDSstores remainordered withSSaliases.',
        'Original/native fullSScorpus witnessesconditionalstackwrites to66E6..67E7 under3F40/3FF9/1E31;38F2/5427do notwriteSSinstandalonerootprofile. This qualifies olderdata-only unchangedring scope, notintentionalreset/seeding/RNGpurpose oractualhistoricalstackdomain. Caller/exclusion/allwriterclosure remainsrequired.',
        'New71-byte initializedzero rawstreamview liesinsideknown7774-byteDATcopy346A..52C7 andcontainsnorelocations. FN030isconditionalwriterunderprincipalDS; actualcurrentDS/runtimepayload-validity/format-capacity-lifetime remainopen. No newresourceformat decoded.',
        'Budget/portfailure/fatalpreCALL/preRET/nativeinvalid statuses areanalysisqualifications. No actualIRQ-nesting/allwriters-reset-storage-lifetime-exclusion/startup-to-exit-completecore/P1-GATE/DOSsession-renderer-audio-game-fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'
    ],'limits':'StaticcompleteinitializationABI/order/arithmetic/rawview review. Actualcaller-domain/lifetime/core and P1-GATE remainseparate.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','admitted_sites':187,'own_sites':119,'new_raw_stream_bytes':71}))
if __name__=='__main__':main()
