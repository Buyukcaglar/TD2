"""Review relative raw counter wait and its direct caller operands."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());md=Cs(CS_ARCH_X86,CS_MODE_16)
 def view(s,ips):
  result=[]
  for ip in ips:
   i=next(md.disasm(image[s*16+ip:s*16+ip+15],ip,count=1));result.append({'site':f'{s:04X}:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str})
  return result
 observations=[v for f in g['functions'] if f['entry'] in ['06C9:C6C5','06C9:C692'] for v in view(0x6c9,sorted(f['instructions']))];assert len(observations)==21
 expected={(0x6c9,0xc6d0):'034606',(0x6c9,0xc6d3):'135608',(0x6c9,0xc6e1):'3b56fe',(0x6c9,0xc6e4):'72f6',(0x6c9,0xc6e6):'3b46fc',(0x6c9,0xc6e9):'72f1',(0x6c9,0xc6ee):'cb',(0x6c9,0xc692):'fa',(0x6c9,0xc69a):'fb',(0x16fc,0x2fb):'ff760a',(0x16fc,0x2fe):'ff7608',(0x16fc,0x306):'83c404',(0x1769,0x1b7):'b80400',(0x1769,0x1ba):'99',(0x1769,0x1bb):'52',(0x1769,0x1bc):'50',(0x1769,0x1c2):'83c404'}
 for (s,ip),raw in expected.items():assert image[s*16+ip:s*16+ip+len(raw)//2].hex()==raw,(s,ip)
 callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target']=='06C9:C6C5'];assert [(c['owner'],c['site']) for c in callers]==[('16FC:0220','16FC:0301'),('1769:000E','1769:01BD')]
 caller_views=view(0x16fc,[0x2f3,0x2f8,0x2fb,0x2fe,0x301,0x306,0x309])+view(0x1769,[0x1af,0x1b4,0x1b7,0x1ba,0x1bb,0x1bc,0x1bd,0x1c2,0x1c5]);ds_writes=[]
 for f in g['functions']:
  if f['entry'] in ['16FC:0220','1769:000E']:
   s=int(f['entry'][:4],16)
   for v in view(s,sorted(f['instructions'])):
    if v['text'].startswith(('mov ds,','pop ds','lds ')):ds_writes.append({'owner':f['entry'],**v})
 record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'caller_instruction_view':caller_views,'explicit_caller_DS_changes':ds_writes,'flow_ledger':graph,'flow_ledger_sha256':hashlib.sha256((ROOT/graph).read_bytes()).hexdigest(),'facts':['C6C5 takes raw low/high SS argument words, adds them with ADD/ADC to the first C692 pair and writes real SS locals low then high. Later high and low guards are both required; this is not unsigned lexicographic comparison.','Actual C692 CLI/read DS5E90/read DS5E92/STI/plain RETF consumes its real far frame, leaving IF1 regardless of incoming IF; CF and DF survive the reader. No synthetic counter-return stub replaces it.','16FC:0301 forwards caller SS BP+8/BP+A raw words. 1769:01BD sets AX4 then unprefixed99 word CWD gives DX0 and pushes high/low. Both postcall ADDSP4 instructions redefine arithmetic FLAGS before any branch; plain root RETF consumes only its four-byte far frame.','Current DS is inherited and used by C692. Explicit caller DS instructions alone cannot prove transitive called-helper preservation, writer domains, IRQ exclusion or lifetime. No fixed global DS, source C type or clock unit is assigned.','Physical086C anomaly belongs to a separate source; no timer frequency, BIOS tick mapping or real IRQ delivery inferred.'],'limits':'Static byte operands and two direct caller windows only. Transitive DS/SS context, all counter writers, interrupt/reentry lifetime, FLAG needs outside these windows, execution-write exclusion, actual parent bodies and core integration remain open. No real DOS/device/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'callers':len(callers),'explicit_caller_DS_changes':len(ds_writes)}))
if __name__=='__main__':main()
