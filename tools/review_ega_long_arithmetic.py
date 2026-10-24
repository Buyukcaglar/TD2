"""Review signed word-DIV roots, RETF8 frames and actual caller flag liveness."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());md=Cs(CS_ARCH_X86,CS_MODE_16)
 def instruction(s,ip):return next(md.disasm(image[s*16+ip:s*16+ip+15],ip,count=1))
 def view(s,ip):
  i=instruction(s,ip);return {'site':f'{s:04X}:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}
 selected=[f for f in g['functions'] if f['entry'] in ['13A8:2E42','13A8:2F1C','13A8:2EE8']];observations=[{'entry':f['entry'],**view(0x13a8,ip)} for f in selected for ip in sorted(f['instructions'])];assert len(observations)==170;expected={0x2e5d:'894608',0x2e60:'895606',0x2e76:'89460c',0x2e79:'89560a',0x2e88:'f7f1',0x2e8f:'f7f1',0x2ea1:'d1eb',0x2ea3:'d1d9',0x2ead:'f7f1',0x2ebb:'9ae82ea813',0x2ee4:'ca0800',0x2ef1:'0bd8',0x2ef6:'750b',0x2f14:'03d1',0x2f19:'ca0800',0x2f2a:'f7d7',0x2f43:'8b560a',0x2f5f:'f7f1',0x2f64:'f7f1',0x2f94:'9ae82ea813',0x2fa5:'2b460a',0x2fa8:'1b560c',0x2fab:'2b4606',0x2fae:'1b5608',0x2fc1:'ca0800'}
 for ip,raw in expected.items():assert image[0x13a80+ip:0x13a80+ip+len(raw)//2].hex()==raw,hex(ip)
 callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in ['13A8:2E42','13A8:2F1C']];assert len(callers)==17 and {c['owner'] for c in callers}=={'0267:0039'};neutral={'mov','lea','push','pop','xchg','cbw','cwd','cwde','cdq','nop'};full_setters={'add','sub','cmp','and','or','xor','test'}
 def entry_reset(target):
  f=next(f for f in g['functions'] if f['entry']==target);s=int(target[:4],16);ip=int(target[5:],16);prefix=[]
  for unused in range(24):
   assert ip in f['instructions'];i=instruction(s,ip);prefix.append(view(s,ip))
   if i.mnemonic in full_setters:return prefix
   assert i.mnemonic in neutral,('Unreviewed callee FLAGS before setter',target,i.mnemonic)
   ip+=i.size
  raise AssertionError('No callee reset '+target)
 windows=[];liveness=[]
 for c in callers:
  f=next(f for f in g['functions'] if f['entry']==c['owner']);s=int(c['site'][:4],16);site=int(c['site'][5:],16);windows.append({'caller':c,'instructions':[view(s,ip) for ip in sorted(f['instructions']) if site-24<=ip<=site+20]});ip=site+c['size'];trace=[]
  for unused in range(64):
   assert ip in f['instructions'];i=instruction(s,ip);trace.append(view(s,ip))
   if i.mnemonic in full_setters:liveness.append({'site':c['site'],'disposition':'arithmetic_FLAGS_redefined_before_read','trace':trace});break
   if i.mnemonic in ['call','lcall']:
    nextcall=next(v for v in f['calls'] if v['site']==f'{s:04X}:{ip:04X}');prefix=entry_reset(nextcall['target']);liveness.append({'site':c['site'],'disposition':'next_callee_redefines_arithmetic_FLAGS_before_read','trace':trace,'next_callee':nextcall['target'],'entry_prefix':prefix});break
   assert i.mnemonic in neutral,('Unreviewed caller FLAGS consumer',c,i.mnemonic)
   ip+=i.size
  else:raise AssertionError('No FLAGS disposition '+c['site'])
 record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'caller_instruction_windows':windows,'caller_arithmetic_FLAGS_liveness':liveness,'flow_ledger':graph,'flow_ledger_sha256':hashlib.sha256((ROOT/graph).read_bytes()).hexdigest(),'unreachable_under_parent_guards':['13A8:2EF8','13A8:2EFB','13A8:2EFD','13A8:2EFF','13A8:2F00'],'facts':['FourSSwords numeratorlow/high,denominatorlow/high. Negative operands become magnitudes through NEGhigh/NEGlow/SBBhigh and actualSSstores. QuotientDI togglesbothsigns; remainderDItogglesnumeratorsignonly. No host signed overflow/division behavior substituted.','Fast two wordDIVs form longquotient orremainder. Slow SHR/RCRnormalizes bothoperands untildivisorBXhigh0, dividesestimate, actualfrozen2EE8 C multiply/sourceSSABI adapter forms product and sourcecompares/corrects it. CXcross/BXsecondlow and actualSSframes retained.','LiteralRETF8 at2EE4/2FC1 and2F19; noADDSP8 beforeordinaryRET substitution. ChildreturnsSPpreCALL+8, rootreturnsSPentry+12; magnitude writes remainin popped argumentstorage. BP/SS operands do not use currentDS.','Both roots callmultiplyonlywhen magnitude denominator highwordnonzero; SSargumentwords staydisjointfrom all pushes underSP32profile, sochildfirsthighwordnonzero/secondhighword0 andJNE2EF6musttake. Fivefastmultiplysites unreachablefromtheseparentsonly, separatelycoveredstandalonemultiply.','ZeroDIVfaultprefixes stopbeforeinstruction/exceptiondelivery. Nonzero fastdivision hasDX0 firstthenremainder<divisor; slow normalizeddivisor≥8000 andnumeratorhigh≤4000, excluding quotient overflow underfourwordmagnitudeprofile. INT_MIN/-1 raw80000000quotient and0remainder therefore returnwithout host signedoverflowfault.','UndefinedsuccessfulDIVFLAGS areunadmitted; XORDX/ORBX/parentCMP andsignprocedures defineexposedCF atprefix/root. Sign/fast/slow paths canreturndifferentCF foridenticalnegative remainderbits; preservetheprocedure.','Seventeendirectsites in0267:0039 preserveargumentpools andliteralcallee8-bytecleanup. Forall17, returnedarithmeticFLAGS areredef ined before read by a caller arithmeticinstruction orverifiedneutral calleeentryprefix followedbyfullsetter. This proof coversonlythesedirectedges, not IRQ/newcallers orwholeowner state.'],'limits':'Complete source bodies/17directcaller windows and bounded arithmeticFLAGS liveness only. Allvalues are rawwordbitpatterns; originalsourceCtype/argumentstorageownership/whole0267caller/lifetime/exclusion/othercallers/core andactualexceptionhandler/CPUdelivery/runtime/gameplay/fidelity remainopen.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':170,'direct_callers':17,'FLAGS_dispositions':len(liveness)}))
if __name__=='__main__':main()
