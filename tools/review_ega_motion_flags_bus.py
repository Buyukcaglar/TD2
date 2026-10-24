"""Review motion FLAGS liveness, clamps, actual stack and sole direct caller."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
 d=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(d).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'
 gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());m=Cs(CS_ARCH_X86,CS_MODE_16)
 def view(seg,ip):
  i=next(m.disasm(d[seg*16+ip:seg*16+ip+15],ip,count=1));return {'site':f'{seg:04X}:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}
 fs=[f for f in g['functions'] if f['entry'] in ['06B3:0008','13A8:2EE8']]
 observations=[view(int(f['entry'][:4],16),ip) for f in fs for ip in f['instructions']];assert len(observations)==146
 expected={(0x6b3,0xa7):'2bc0',(0x6b3,0xa9):'e9b100',(0x6b3,0x10a):'f7da',(0x6b3,0x10c):'52',(0x6b3,0x10d):'50',(0x6b3,0x10e):'8b46fc',(0x6b3,0x111):'99',(0x6b3,0x112):'52',(0x6b3,0x113):'50',(0x6b3,0x114):'9ae82ea813',(0x6b3,0x141):'813e462f800e',(0x6b3,0x147):'7e06',(0x6b3,0x149):'c706462f800e',(0x6b3,0x14f):'813e462f80f1',(0x6b3,0x155):'7d06',(0x6b3,0x157):'c706462f80f1',(0x6b3,0x15d):'8be5',(0x6b3,0x15f):'5d',(0x6b3,0x160):'cb',(0x13a8,0x2f00):'ca0800',(0x13a8,0x2f19):'ca0800'}
 for (s,i),raw in expected.items():assert view(s,i)['bytes']==raw
 def sw(v):return v if v<0x8000 else v-65536
 def sub(a,b):
  v=(a-b)&65535;return int(a<b),int(v==0),int(bool(v&0x8000)),int(bool((a^b)&(a^v)&0x8000))
 changed=discriminators=upper_overflows=0
 for v in range(65536):
  cf,zf,sf,of=sub(v,0xe80);assert (bool(zf) or sf!=of)==(sw(v)<=0xe80)
  upper_overflows+=of;a_cmp=0xe80 if sw(v)>0xe80 else v
  cf,zf,sf,of=sub(a_cmp,0xf180);assert (sf==of)==(sw(a_cmp)>=-0xe80) and of==0
  after=0xf180 if sw(a_cmp)<-0xe80 else a_cmp
  changed+=int(a_cmp!=after);discriminators+=int(sub(a_cmp,0xf180)!=sub(after,0xf180))
 assert changed==discriminators and changed and upper_overflows
 callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target']=='06B3:0008'];assert {c['site'] for c in callers}=={'06C9:4261'}
 windows=[view(s,i) for s,i in [(0x6c9,0x4261),(0x6c9,0x4266),(0x6c9,0x426b),(0x6c9,0x6601),(0x6c9,0x6603),(0x6c9,0x6605)]]
 assert windows[0]['bytes'].startswith('9a0800b306') and windows[1]['bytes'].startswith('9a0166c906') and windows[3]['bytes']=='b401' and windows[4]['bytes']=='cd16'
 deps=['docs/recovery/evidence/td2ega-motion-scan-bus-context-v1.json','docs/recovery/evidence/td2ega-signed-motion-validation-v1.json','docs/recovery/evidence/td2ega-input-poll-bus-context-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json','docs/recovery/evidence/intel-record-flags-reference-v1.json','analysis/history/motion-flags-validation-refinement-v2.json']
 record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'flow_ledger':gp,'flow_ledger_sha256':hashlib.sha256((ROOT/gp).read_bytes()).hexdigest(),'instruction_sites_in_fence':146,'root_site_counts':{'motion':123,'actual_multiply':23},'instruction_observations':observations,'direct_caller_candidates':callers,'caller_windows':windows,'exhaustive_upper_lower_clamp_review':{'word_inputs':65536,'upper_CMP_overflow_inputs':upper_overflows,'terminal_CMP_overflow_inputs':0,'lower_clamp_operand_changes':changed,'postclamp_reconstruction_discriminators':discriminators},'facts':['Normaldamping ends00A7 SUBAXAX: allsixarithflagsdefined. Generalends014FCMPword2F46,F180 beforepossible0157MOVclamp; MOVSP-BP/POPBP/RETF preserveFLAGS.','All65536 serializedwordinputs satisfy signedupper/lowerbranches. UpperCMPcanoverflow; afterupperclamp finalCMP OFalways0. PostlowerclampRAM losesoriginalCMPoperand; reconstructedpostclampflags canthereforebeincorrect.','Before0114CALL lastflagwriter010ANEGDX; PUSH/MOV/CWD preserveit. NativeCALLbudget prefixcanexposefullydefinedarithmeticFLAGS without executingcallee.','ActualSS savedBP/twolocals/fourwordarguments/farCALL/savedchildBP/RETF8/plainrootRETF retained. Maximuminitialdepth20bytes; sourceSP20..FFE0 profileavoidsordinaryboundaryfaults. Childrawreturnsarechecked beforeparentcontinuation.','Solegraphdirectcaller420A4261calls6601at4266 immediately. ItsMOVAH1/INT16stores incomingfullFLAGS beforeanyflagkill, so motionfullFLAGSrequired. Returned6601 ORAX at426Bkillsreturnedflags, notincominginterruptsavedword.','CurrentDS maydifferfromSS; noglobalDS=SS/actualcallerproof. No newinitializedresourceextent; existing motionfieldviews/caller-writers remainqualified.','Physical086Cunassigned/CGAbehindEGAclosure. NoDOSsession/realBIOS-device-IRQ/renderer/audio/fullresourceformats/complete-state-machine/gameplay/fidelity.'],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Motion/fullFLAGS static146site and65536wordclampreview only; actual20bitRAM comparison andnativeinterfacechecks separate. Same originalentrycountedonce. Whole420A-403B/allwriters-domain-capacity-lifetime-exclusion/caller-IRQ-core/P1-GATE remainopen.'}
 out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(json.dumps({'result':'pass','sites':146,'clamp_inputs':65536,'postclamp_discriminators':discriminators}))
if __name__=='__main__':main()
