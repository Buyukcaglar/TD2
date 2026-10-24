"""Compare412C/4639 additional fullSS bus interfaces, flags and actualnearRET."""
import argparse,ctypes as C,hashlib,itertools,json,random,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32)]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());fs=[f for f in g['functions'] if f['entry'] in ['06C9:412C','06C9:4639']];fence={ip for f in fs for ip in f['instructions']};require(len(fence)==95,'Fence');returns={ip for ip in fence if image[0x6c90+ip]==0xc3};fn=C.CDLL(str(lib)).td2ega_sample_fields_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*4+[C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==40,'Layout')
 def case(**kw):
  c=dict(entry=0,current=0,target=0,lower=1,upper=2,bytecounter=0,samplecounter=0,active=0,blocked=0,down=1,decaying=0,overshoot=0,wordflag=0,bitword=0,direction=0,field=0,ds=None,same=False,sp=0xe000,flags=2);c.update(kw);return c
 edges=[0,1,95,96,97,0x7fff,0x8000,0xff9f,0xffa0,0xffff]
 cases=[case(current=current,target=target,same=same,flags=flags) for current,target,same,flags in itertools.product(edges,edges,[False,True],[2,0x643])]
 cases += [case(samplecounter=b,decaying=b,down=down,overshoot=over,same=same,flags=flags) for b,down,over,same,flags in itertools.product(range(256),[0,1],[0,1],[False,True],[2,0x643])]
 cases += [case(active=1,wordflag=wordflag,bitword=bitword,direction=direction,field=field,same=same,flags=flags) for wordflag,bitword,direction,field,same,flags in itertools.product([0,8],[0,4],[0,127,128,255],[0,1,1499,1500,1501,1798,1799,1800,1801,0x7fff,0x8000,0xffff],[False,True],[2,0x643])]
 cases += [case(blocked=blocked,same=same,flags=flags) for blocked,same,flags in itertools.product([1,128,255],[False,True],[2,0x643])]
 profiles=[(0,1,2),(1,1,2),(2,1,2),(3,1,2),(0x7fff,0x8000,0xffff),(0x8000,0x7fff,0xffff),(0xffff,0x7fff,0x8000),(1,2,0),(2,2,0),(0xffff,0,0xffff),(0,0,0)]
 cases += [case(entry=1,target=target,lower=lo,upper=hi,bytecounter=b,same=same,flags=flags) for (target,lo,hi),b,same,flags in itertools.product(profiles,range(256),[False,True],[2,0x643])]
 cases += [case(entry=1,target=target,lower=lo,upper=hi,bytecounter=b,same=same) for target,lo,hi,b,same in itertools.product([0,1,0x7fff,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],[0,1,29,30,127,128,255],[False,True])]
 cases += [case(entry=e,current=current,target=target,active=active,wordflag=8,direction=direction,field=field,overshoot=1,same=True,sp=sp,flags=flags) for e,(current,target),active,direction,field,sp,flags in itertools.product([0,1],[(0,0),(0x48a0,0)],[0,1],[0,128],[0,1499,1799],[0,0xfffe,0x332a,0x5fde,0x5fd8,0x5fda,0x3350,0x335c,0x33b2,0x336a,0x33b3,0x332c,0x5490],[2,0x643])]
 cases += [case(entry=e,ds=ds,same=same,sp=sp,flags=flags) for e,ds,same,sp,flags in itertools.product([0,1],[0,0xffff],[False,True],[0,0xfffe],[2,0x643])]
 rng=random.Random(0x412c4639)
 for _ in range(512):cases.append(case(entry=rng.randrange(2),current=rng.randrange(65536),target=rng.randrange(65536),lower=rng.randrange(65536),upper=rng.randrange(65536),bytecounter=rng.randrange(256),samplecounter=rng.randrange(256),active=rng.randrange(2),blocked=rng.randrange(2),down=rng.randrange(2),decaying=rng.randrange(256),overshoot=rng.randrange(2),wordflag=rng.randrange(16),bitword=rng.randrange(8),direction=rng.randrange(256),field=rng.randrange(65536),flags=rng.choice([2,0x643]),same=rng.choice([False,True])))
 vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,principal=load+0x6c9,load+0x178f;base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=image;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(ip));active['sites'].add(ip);active['instructions']+=1
   if ip in returns:active['return']=ip;cpu.emu_stop()
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];entry=0x412c if c['entry']==0 else 0x4639
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   for i in range(1024):put(ds,0x30e8+2*i,(0x1357+137*i)&65535)
   for o,v in [(0x332a,c['current']),(0x332c,c['target']),(0x23aa,c['lower']),(0x23a8,c['upper']),(0x942e,c['wordflag']),(0x3346,c['bitword']),(0x3350,c['field'])]:put(ds,o,v)
   for o,v in [(0x33b3,c['bytecounter']),(0x336a,c['samplecounter']),(0x3374,c['active']),(0x33bc,c['blocked']),(0x3368,c['down']),(0x33b2,c['decaying']),(0x336f,c['overshoot']),(0x335c,c['direction']),(0x5490,0x55)]:put(ds,o,v,1)
   put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));active.update(sites=set(),instructions=0,writes=0,executing_return=False,**{'return':None})
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   label=str((load,c));u.emu_start(cs*16+entry,0,count=100);require(active['return'] is not None,'Return '+label);active['executing_return']=True;u.emu_start(cs*16+active['return'],0,count=1);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],C.byref(incoming),C.byref(r));ef=u.reg_read(UC_X86_REG_EFLAGS)
   require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.zero_flag,r.flags_valid)==(0,u.reg_read(UC_X86_REG_SP),cs,u.reg_read(UC_X86_REG_IP),active['writes'],(ef>>6)&1,1),'Result '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS']+=int(ss==ds);coverage['changed_near_return_words']+=int(r.next_ip!=0x1111);coverage['near_SP_wraps']+=int(sp==0xfffe);coverage['signed_DEC_80_return_without_store']+=int(c['entry']==1 and c['bytecounter']==128 and c['target']<c['lower'] and 0x465c not in active['sites']);coverage['target_table_postwrite_alias']+=int(c['entry']==0 and c['current']==0x48a0 and c['target']==0 and r.returned.registers.bx==0x4840)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['signed_DEC_80_return_without_store']>0 and coverage['target_table_postwrite_alias']>0 and coverage['changed_near_return_words']>0,'Coverage/discriminators');records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(f['id'] for f in records if any(e.get('segment')==0x6c9 and e.get('segment_offset')==ip for e in f['entries'])) for ip in [0x412c,0x4639]];deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sample_fields_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':95,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Additional412C/4639fullSSnearinterfaces/currentDS/actualnearreturnword/GPR-BP-CFZFIFDF/fullbus/writecounts/SP0..FFFE. Post332A-store tablealias/signedDEC80-JLoverflow/INC-bytewrap/wordINC-DECwrap/branchflags retained; oldgroup APIsunchanged. Whole403B/420A/caller-writers-storage-lifetime-IRQ-exclusion/core open. No newuniqueoriginalentry andnoDOSsession/devices/renderer/audio/fullresourceformat/complete-state-machine/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
