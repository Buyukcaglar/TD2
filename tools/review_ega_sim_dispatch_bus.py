"""Review actual SS curve writes, eleven near targets, and the open 491D context."""
import argparse, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
ENTRIES=[0x4929,0x4947,0x494d,0x495d,0x499a,0x49c9,0x49cf,0x49d5,0x49db,0x49e1,0x4a18]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence')
 d=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(d).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());m=Cs(CS_ARCH_X86,CS_MODE_16)
 def view(ip):
  i=next(m.disasm(d[0x6c90+ip:][:15],ip,count=1));return {'site':f'06C9:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}
 expected={0x4929:'c606713301',0x492e:'833e109400',0x4935:'a11e33',0x4938:'a35633',0x493b:'a12e94',0x493e:'a35833',0x4941:'c606d53301',0x4947:'c606713302',0x494d:'833eda5200',0x4954:'8bc5',0x4956:'055000',0x4959:'a3da52',0x495d:'833eda5200',0x4964:'8b1ece52',0x4968:'81fb0032',0x496e:'891e5433',0x4972:'8bc5',0x4974:'053c00',0x4977:'a3da52',0x497a:'c706de520000',0x4980:'c606b73308',0x4985:'8bd8',0x4987:'f60780',0x498c:'c706dc522003',0x4993:'c706dc529001',0x499a:'8bcb',0x499c:'8a1e3e53',0x49a0:'80c345',0x49a3:'80e37f',0x49a6:'32ff',0x49a8:'8beb',0x49aa:'83e57f',0x49ad:'d1e9',0x49af:'8bd9',0x49b1:'83e916',0x49b4:'8bc1',0x49b6:'d1e0',0x49b8:'d1e0',0x49ba:'03c1',0x49bc:'88868a36',0x49c0:'8a87dd37',0x49c4:'88860a37',0x49c8:'c3',0x49c9:'8036f73701',0x49cf:'8036f63701',0x49d5:'8036f83701',0x49db:'80067a3310',0x49e1:'802e7a3310',0x4a18:'c3',0x4904:'8a4e01',0x4909:'80e17f',0x4916:'8a5c03',0x491b:'d1e3',0x491d:'ff97e633',0x4921:'a1c852',0x4924:'fecc',0x4926:'e9a1fd',0x46ca:'803e905402',0x475b:'9a0e78c906',0x4760:'2407',0x4762:'3c06',0x4764:'73f5'}
 for ip,raw in expected.items():assert view(ip)['bytes']==raw,(hex(ip),view(ip))
 fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in ENTRIES]];assert len(fs)==11;ips={ip for f in fs for ip in f['instructions']};ind=next(i for f in g['functions'] if f['entry']=='06C9:4674' for i in f['indirect'] if i['site']=='06C9:491D');assert not ind['review']['complete'];assert all(f'06C9:{ip:04X}' in ind['review']['targets'] for ip in ENTRIES)
 # BYTE transformation already admitted by the separate 780E packet. This is
 # a finite-state lemma with explicit stable-ring assumptions, not IRQ proof.
 def step(b):return ((b<<1)|(b<128))&255
 maximum=0;max_seeds=[];orbits=[]
 for initial in range(256):
  v=initial;n=0;trail=[]
  while True:
   v=step(v);trail.append(v)
   if v&7<6:break
   n+=1;assert n<=16
  if n>maximum:maximum=n;max_seeds=[initial]
  elif n==maximum:max_seeds.append(initial)
  v=initial
  for _ in range(8):v=step(v)
  assert v==initial^255
  for _ in range(8):v=step(v)
  assert v==initial
  orbits.append({'initial':initial,'consecutive_rejected_outputs':n,'first_accepted':trail[-1]})
 assert maximum==7 and 3 in max_seeds
 ring=[3]*256;cursor=0;calls=0
 while True:
  cursor=(cursor-1)&65535;idx=cursor&255;ring[idx]=step(ring[idx]);calls+=1
  if ring[idx]&7<6:break
  assert calls<1793
 assert calls==1793
 coefficients=[]
 for value in range(65536):
  half=value>>1;shifted=(half-22)&65535;left=(shifted*4)&65535;total=left+shifted;coefficients.append(((total&65535),int(total>65535)))
 assert len(coefficients)==65536
 deps=['docs/recovery/evidence/td2ega-sim-primitives-validation-v1.json','docs/recovery/evidence/td2ega-small-state-validation-v3.json','docs/recovery/evidence/td2ega-byte-ring-validation.json','docs/recovery/evidence/td2ega-sample-guards-context-v2.json']
 record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'flow_ledger':gp,'flow_ledger_sha256':hashlib.sha256((ROOT/gp).read_bytes()).hexdigest(),'instruction_observations':[view(ip) for ip in sorted(ips)],'caller_and_rejection_window':[view(ip) for ip in sorted(set(expected)-ips)],'instruction_sites_in_fence':len(ips),'indirect_caller_candidate':{'owner':'06C9:4674',**ind},'external_span_candidates':[],'curve_static_inputs':65536,'ring_lemma':{'individual_initial_bytes':256,'individual_maximum_consecutive_rejections':maximum,'maximum_seed_bytes':max_seeds,'stable_256_slot_maximum_calls':1793,'sharp_bound_witness_initial_byte':3,'witness_calls':calls,'proof':'Every slot can reject at most7 consecutive transformed outputs; each is visited once per256 calls. Thus the first accepted output occurs by7*256+1. Uniformbyte3attainsbound.','preconditions':['SerializedcurrentDS/ringbase66E8andcursor66E6stableexceptliteral780Ewrites; nointerveningwriters/reset/IRQ/reentry.','ActualcalleeSSframes/savedSI/returnwords disjointfromringbytes/cursor; nosegmentaliaseschangingcode orcontrol.','This provesonly475B..4764 rejectionloop underthoseconditions, notthewhole4674controller oractualcallerexclusion.'],'per_byte_results':orbits},'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'facts':['Eleven initialized491Dtargets alreadyhaveboundedportableviews; thispacketaddsfullSSbus+CFZF interfaceswithoutnewuniqueoriginalentries. Plain4A18RET2 already belongs tosmall-state. Existingpuregroup APIsandreceipts remainfrozen.','499A capturesincomingBXintoCX; BL=(DS533E+45)&7F/BH0/BPindex; unsignedCX>>1/BXhalf/CXhalf-22/AX=5*CXmod16. Actual8886at49BCand49C4defaulttoSS becauseBPbase; intervening49C0defaultDS becauseBXbase. FirstSSbytewrite precedes liveDSread37DD+half, then secondSSbytewrite. DS=SSonlyoneadmittedprofile; inputsegmentsmaydifferandstillphysicalalias.','CurveCFZFcome fromfinalwordADDAXCX beforeMOVs, notfromfinalAXwithALreplacedbybyte. Both493xMOVsnapshot paths and4947/4A18 preservetheirpriorflagsasliteral; nativeinputZFexplicit.495D finalTESTbit80afterordered52DA-52DE-33B7stores rereadsaliasedtarget.','AllrootsplainnearRET/noownpush/noargs; actualSSwordcanbechangedbytheirbyte-wordstatewrites. Native0meansactualREToperationandrawreturnedcoordinate, notproofitmatchesparentIP4921. Parentmustcaptureindirectwordbeforepushingframe/checkreturnedcoordinate.','491Dselectorremainsrawbyte0..255 scaled2/currentDS33E6..35E4wordlookup. Initialized48wordtable and13recognizedtargetbodies donotboundactualrecordbyte3/allwriters. 4904recordselectorisSS:[BP+1], masked7F/fourbytes; 4916callbackselectorisDS:[SI+3]. KeepDS-SSviewsdistinct.','After491Dnormalreturn4921MOVAX/4924DECAH/4926JMP46CA, CMPDS5490,2 killsreturnedCFZFbeforebranch. Full4674/rootcallframes/returnedGPR-currentDS-state/sourcewriters/IRQexclusion remainopen.','475B..4764rejectionlemmaexhaustivelyreviews256bytes/transform16orbit andsharp1793callstable256slotbound. ThiscannotreplaceactualSSalias/sharedwriter/reset/IRQclosure anddoesnotnameRNGpurpose/timeunit.','No newembeddedspan, resourceformatdecode, DOSsession, realdevices, renderer/audio/fullstate/gameplay/fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'],'limits':'ElevenadditionalcurrentDS-independentSS nearinterfaces/literalCFZF/inputZF/actualRET/curvepostwritealias plusconditionalstable-ringmathlemma. Complete491Dtarget-writerdomain, whole4674-403B/sourceownership-reset-lifetime-exclusion/core/P1-GATE remainopen.'}
 out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(ips),'entries':11,'curve_static_inputs':65536,'conditional_ring_bound':1793,'indirect_domain_closed':False}))
if __name__=='__main__':main()
