"""Compare eleven 491D targets with independent DS/SS, live RAM and near RET."""
import argparse, ctypes as C, hashlib, itertools, json, random, struct, sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
ENTRIES=[0x4929,0x4947,0x494d,0x495d,0x499a,0x49c9,0x49cf,0x49d5,0x49db,0x49e1,0x4a18]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32)]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve()
 require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image')
 gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in ENTRIES]];require(len(fs)==11,'Entries');fence={ip for f in fs for ip in f['instructions']};returns={ip for ip in fence if image[0x6c90+ip]==0xc3}
 fn=C.CDLL(str(lib)).td2ega_sim_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*4+[C.POINTER(StateRegisters),C.c_uint16,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==40,'Result layout')
 counts=Counter();sites=set();vectors=instructions=0;seed=0x491d499a;rng=random.Random(seed)
 def fixture(entry,**kw):
  c=dict(entry=entry,existing=0,sample=0x3201,selector=0,bx=0x1234,bp=0x529e,flag=0,flags=2,ds=None,ss=None,sp=0xe000);c.update(kw);return c
 cases=[]
 for e in range(11):
  cases.extend(fixture(e,flags=flags,ss=ss,sp=sp,existing=existing) for flags,ss,sp,existing in itertools.product([2,3,0x42,0x643],[None,'same'],[0,0xe000,0xfffe],[0,1,0xffff]))
 for existing,sample,bp,flags,ss in itertools.product([0,1,0xffff],[0,1,0x31ff,0x3200,0x3201,0xffff],[0,0xffb0,0xffc4,0x529e,0x52a2,0x337b,0xffff],[2,0x643],[None,'same']):
  cases.extend([fixture(2,existing=existing,bp=bp,flags=flags,ss=ss),fixture(3,existing=existing,sample=sample,bp=bp,flags=flags,ss=ss)])
 for selector,bx,ss,flags in itertools.product(range(256),[0,1,43,44,45,0x7fff,0x8000,0xffff],[None,'same'],[2,0x643]):cases.append(fixture(4,selector=selector,bx=bx,ss=ss,flags=flags))
 for e,flag,ss,flags in itertools.product(range(5,10),range(256),[None,'same'],[2,0x643]):cases.append(fixture(e,flag=flag,ss=ss,flags=flags))
 # Actual BP-indexed SS first store must be visible to the following DS read.
 # DS:37DD+half aliases SS:368A+index for half=index-0x153 (mod 64KiB).
 for selector,delta,flags in itertools.product(range(256),[-1,0,1],[2,0x643]):
  index=(selector+0x45)&0x7f;half=100+index;segment_delta=(0x37dd+half-0x368a-index)//16
  # Use an exact byte alignment by adjusting half; both positive and negative SS shifts occur below.
  half=(0x368a+index+16*segment_delta-0x37dd)&65535
  if half<0x8000:cases.append(fixture(4,selector=selector,bx=2*half,ss=('alias',segment_delta+delta),flags=flags))
 # Return words can be overwritten by each body's state stores; they remain raw returns.
 for e,sp,flags in itertools.product(range(11),[0x3371,0x3354,0x3356,0x3358,0x33d5,0x33b7,0x52da,0x52dc,0x52de,0x368a,0x370a,0x37f6,0x37f7,0x37f8,0x337a],[2,0x643]):cases.append(fixture(e,ss='same',sp=sp,selector=59,bx=0xffff,flags=flags,flag=0xff))
 for e,ds,ss,sp,flags in itertools.product(range(11),[0,0xffff],[None,'same'],[0,0xfffe],[2,0x643]):cases.append(fixture(e,ds=ds,ss=ss,sp=sp,flags=flags,selector=127,bx=0xffff))
 for _ in range(1024):cases.append(fixture(rng.randrange(11),selector=rng.randrange(256),bx=rng.randrange(65536),bp=rng.randrange(65536),sample=rng.randrange(65536),existing=rng.choice([0,0,1,0xffff]),flag=rng.randrange(256),flags=rng.choice([2,3,0x42,0x643]),ss=rng.choice([None,'same'])))
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=image;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(ip));active['sites'].add(ip);active['instructions']+=1
   if ip in returns:active['return']=ip;cpu.emu_stop()
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['ss']=='same' else (ds+c['ss'][1])&65535 if isinstance(c['ss'],tuple) else 0x9000;sp=c['sp'];flags=c['flags'];e=c['entry']
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   for o,v in [(0x9410,c['existing']),(0x331e,0x1357),(0x942e,0x2468),(0x52da,c['existing']),(0x52ce,c['sample'])]:put(ds,o,v)
   for o,v in [(0x533e,c['selector']),(0x337a,c['flag']),(0x37f7,c['flag']),(0x37f6,c['flag']),(0x37f8,c['flag'])]:put(ds,o,v,1)
   put(ds,(c['bp']+0x3c)&65535,c['flag'],1);put(ss,sp,0x1111)
   incoming=StateRegisters(Registers(0xa55a,c['bx'],0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),c['bp'],flags&1)
   u.mem_write(0,bytes(data));active.update(sites=set(),instructions=0,writes=0,executing_return=False,**{'return':None})
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[e]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   label=str((load,c));u.emu_start(cs*16+ENTRIES[e],0,count=80);require(active['return'] is not None,'Return '+label);active['executing_return']=True;u.emu_start(cs*16+active['return'],0,count=1)
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(data),load,ss,sp,e,C.byref(incoming),(flags>>6)&1,C.byref(r));ef=u.reg_read(UC_X86_REG_EFLAGS)
   require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.zero_flag,r.flags_valid)==(0,u.reg_read(UC_X86_REG_SP),cs,u.reg_read(UC_X86_REG_IP),active['writes'],(ef>>6)&1,1),'Result '+label)
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Whole RAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label)
   require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);counts[f'entry_{e}']+=1;counts['CPU_bus_writes']+=r.bus_writes;counts['DS_equals_SS']+=int(ds==ss);counts['DS_differs_SS']+=int(ds!=ss);counts['changed_near_returns']+=int(r.next_ip!=0x1111);counts['near_SP_wraps']+=int(sp==0xfffe)
   if e==4:counts['curve_cross_segment_alias_fixtures']+=int(isinstance(c['ss'],tuple));counts['curve_postwrite_read_discriminators']+=int(isinstance(c['ss'],tuple) and c['ss'][1]%65536==((0x37dd+(c['bx']>>1)-0x368a-((c['selector']+0x45)&127))//16)%65536 and (r.returned.registers.ax&255)!=0xa5)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence,'Missing sites '+str(sorted(fence-sites)));require(counts['curve_postwrite_read_discriminators']>0 and counts['changed_near_returns']>0 and counts['near_SP_wraps']>0,'Discriminators')
 records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(f['id'] for f in records if any(e.get('segment')==0x6c9 and e.get('segment_offset')==ip for e in f['entries'])) for ip in ENTRIES]
 deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json']
 record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sim_dispatch_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(counts),'limits':'Eleven literal near bodies/full1MiB bus/separateDS-SS/actualBP-defaultSScurve stores/liveDSread/CFZFIFDF-GPR-BP/actualreturnword/SP0..FFFE. Additional interface views only, no new unique original entries. Whole4674/491Dtargetbounds-allwriters/sourceownership-reset-IRQ-exclusion-lifetime/core remainopen. NoDOSsession/renderer/audio/fullresourcecodec/complete-state-machine/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'}
 out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
