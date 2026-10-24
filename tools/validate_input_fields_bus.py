"""Compare four420A dependency entries/fullSS/203sites/actualnear4612-4441."""
import argparse,ctypes as C,hashlib,itertools,json,random,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
ENTRIES=[0x4281,0x43c3,0x4441,0x448a]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in ENTRIES+[0x4612]]];fence={ip for f in fs for ip in f['instructions']};require(len(fence)==203,'Fence');returns={ip for ip in fence if image[0x6c90+ip]==0xc3};calls={0x4332:0x4335,0x4335:0x4338,0x443a:0x443d,0x443d:0x4440};fn=C.CDLL(str(lib)).td2ega_input_fields_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==44,'Layout')
 def case(**kw):
  c=dict(entry=0,prepared=0,raw=0,dl=0,dh=1,marked=0,mode=2,automatic=0,bp=500,lo=100,hi=1000,low=200,selector=1,maxselector=6,special=0,state=0,repeat=0,table=(1,1,0x80),x=0,y=0,tx=0,ty=0,basey=0,multiplier=0x8000,control=2000,cx=0,dx=4000,damage=0,byte_limit=255,factor=255,sample=0,same=False,ds=None,sp=0xe000,flags=2,calls=2);c.update(kw);return c
 cases=[case(raw=b,prepared=prepared,dl=dl,dh=dh,same=same,flags=0x643 if b&1 else 2) for b,prepared,dl,dh,same in itertools.product(range(256),[0,1],[0,1],[0,1],[False,True])]
 cases += [case(prepared=prepared,mode=mode,marked=marked,automatic=auto,raw=raw,dl=dl,dh=dh,bp=bp,table=table,same=same) for prepared,mode,marked,auto,raw,(dl,dh),bp,table,same in itertools.product([0,1],[0,1,2],[0,1],[0,1],[0,1,0x11,0x15],[(0,0),(0,1)],[0,500,0xffff],[(0,0,0),(1,1,0x80),(0xff,0x80,0xff)],[False,True])]
 cases += [case(raw=raw,special=special,state=state,repeat=repeat,maxselector=maxsel,selector=sel,mode=mode,table=table,same=same) for raw,special,state,repeat,maxsel,sel,mode,table,same in itertools.product([0x10,0x11,0x15],[0,1],[0,1],[0,1],[1,255],[1,255],[1,2],[(0,0,0),(1,1,0x80),(0xff,0x80,0xff)],[False,True])]
 edges=[0,6,0x7fff,0x8000,0xffff]
 cases += [case(entry=1,x=x,y=y,tx=tx,ty=ty,basey=0xffff if (tx^y)&1 else 0,same=same,flags=0x643 if (x^ty)&1 else 2) for x,y,tx,ty,same in itertools.product(edges,edges,edges,edges,[False,True])]
 for (cx,dx),profile,selector,same,flags in itertools.product(itertools.product([0,1,2699,2700,2999,3000,0x7fff,0x8000,0xffff],repeat=2),[(0,0,0),(255,0,255),(127,128,1),(255,220,200),(35,0,200)],[0,1],[False,True],[2,0x643]):
  limit,damage,factor=profile;cases.append(case(entry=2,cx=cx,dx=dx,selector=selector,byte_limit=limit,damage=damage,factor=factor,same=same,flags=flags))
 cases += [case(entry=3,sample=sample,same=same,flags=flags) for sample,same,flags in itertools.product(range(256),[False,True],[2,0x643])]
 cases += [case(entry=entry,prepared=prepared,sp=sp,calls=limit,mode=mode,same=True,raw=0,dl=0,dh=1,tx=0,ty=0,y=0,x=0,bp=bp,flags=flags) for entry,prepared,sp,limit,(mode,bp),flags in itertools.product(range(4),[0,1],[20,0xffe0,0x2f56,0x332c,0x332e,0x3328,0x52ce,0x52d1,0x33b2,0x33b4,0x52cf,0x30e4,0x30e6,0x3365,0x3366,0x3367,0x3352,0x23c6,0x2418],range(3),[(2,0),(2,4000),(1,0xffff)],[2,0x643])]
 cases += [case(entry=e,ds=ds,same=same,sp=sp,flags=flags) for e,ds,same,sp,flags in itertools.product(range(4),[0,0xffff],[False,True],[20,0xffe0],[2,0x643])]
 cases += [case(entry=e,same=same,sp=sp,flags=flags) for e,same,sp,flags in itertools.product([2,3],[False,True],[0,0xfffe],[2,0x643])]
 rng=random.Random(0x4281448a)
 for _ in range(512):cases.append(case(entry=rng.randrange(4),prepared=rng.randrange(2),raw=rng.randrange(256),dl=rng.randrange(2),dh=rng.randrange(2),marked=rng.randrange(2),mode=rng.randrange(3),automatic=rng.randrange(2),bp=rng.randrange(65536),selector=rng.randrange(256),maxselector=rng.randrange(256),special=rng.randrange(2),state=rng.randrange(2),repeat=rng.randrange(2),table=(rng.randrange(256),rng.randrange(256),rng.randrange(256)),x=rng.randrange(65536),y=rng.randrange(65536),tx=rng.randrange(65536),ty=rng.randrange(65536),basey=rng.randrange(65536),multiplier=rng.randrange(65536),control=rng.randrange(65536),cx=rng.randrange(65536),dx=rng.randrange(65536),damage=rng.randrange(256),byte_limit=rng.randrange(256),factor=rng.randrange(256),sample=rng.randrange(256),same=rng.choice([False,True]),flags=rng.choice([2,0x643])))
 vectors=instructions=0;sites=set();coverage=Counter();pattern=bytes((i*17+31)&255 for i in range(65536))
 cases += [case(selector=selector,bp=bp,marked=marked,automatic=auto,mode=mode,prepared=prepared,same=same,flags=flags) for selector,bp,marked,auto,mode,prepared,same,flags in itertools.product([1,2,255],[0,100,200,201,1000],[0,1],[0,1],[0,1,2],[0,1],[False,True],[2,0x643])]
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=image;active={};u=None;backing=None
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(address))
   if ip in returns:active['return']=ip;cpu.emu_stop();return
   if ip in calls:
    if active['calls']==active['limit']:active['prefix']=True;cpu.emu_stop();return
    active['calls']+=1;active['frames'].append((calls[ip],cpu.reg_read(UC_X86_REG_SP)))
   active['instructions']+=1;active['sites'].add(ip)
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  emulators={}
  for form in [0,1]:
   cpu=Uc(UC_ARCH_X86,UC_MODE_16);storage=map_twenty_bit_ram(cpu);cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_WRITE,write);emulators[form]=(cpu,storage)
  for c in cases:
   u,backing=emulators[c['prepared']]
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags']
   start=(ds<<4)&0xfffff;first=min(65536,0x100000-start);data[start:start+first]=pattern[:first]
   if first<65536:data[:65536-first]=pattern[first:]
   data[cs*16+0x42ad]=0x75 if c['prepared'] else 0x77
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   def wb(o,v):put(ds,o,v,1)
   shift,steer,direction=c['table']
   for i in range(16):wb(0x3394+i,shift)
   for i in range(16):wb(0x339d+i,steer)
   for i in range(16):wb(0x33a6+i,direction)
   for i in range(16):wb(0x2406+i,shift)
   for i in range(16):wb(0x240f+i,steer)
   for o,v in [(0x332c,c['bp']),(0x8a9a,c['mode']),(0x23aa,c['lo']),(0x23ac,c['hi']),(0x23ae,c['low']),(0x2f4c,c['x']),(0x2f4e,c['y']),(0x3324,c['tx']),(0x3326,c['ty']),(0x23c8,c['basey']),(0x3328,c['multiplier']),(0x52ce,c['control'])]:put(ds,o,v)
   for o,v in [(0x3365,c['dl']),(0x3366,c['dh']),(0x33b0,c['raw']),(0x33d5,c['marked']),(0x90a8,c['automatic']),(0x2f56,c['selector']),(0x23a6,c['maxselector']),(0x33af,c['special']),(0x5490,c['state']),(0x3367,c['repeat']),(0x2418,c['byte_limit']),(0x33c6,c['damage'])]:wb(o,v)
   if c['entry']==2:wb(0x3329,c['factor'])
   for i in range(8):wb(0x335d+i,c['sample'])
   put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,c['cx'],c['dx'],0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(calls=0,limit=c['calls'],frames=[],instructions=0,writes=0,sites=set(),executing_return=False,prefix=False,**{'return':None});label=str((load,c));u.emu_start(cs*16+ENTRIES[c['entry']],0,count=400);root=raw=False
   while active['return']:
    ip=active['return'];active['return']=None;active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if not active['frames']:root=True;break
    nextip,nextsp=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,nextip,nextsp):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=400)
   require(root or raw or active['prefix'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(data),load,ss,sp,c['entry'],c['prepared'],C.byref(incoming),c['calls'],C.byref(r));ef=u.reg_read(UC_X86_REG_EFLAGS)
   require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes)==(0 if root else 1 if raw else 3,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['calls'],active['writes']),'Result '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label);require((r.flags_valid,r.zero_flag)==(int(root),(ef>>6)&1 if root else 0),'RootZF '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['prepared_'+str(c['prepared'])]+=1;coverage['root_RET' if root else 'raw_child_RET' if raw else 'before_CALL_budget']+=1;coverage['CPU_bus_writes']+=r.bus_writes;coverage['actual_near_calls']+=r.calls;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root_returns']+=int(root and r.next_ip!=0x1111);coverage['near_SP_wraps']+=int(sp==0xfffe)
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['raw_child_RET']>0 and coverage['before_CALL_budget']>0,'Coverage '+str([f'{ip:04X}' for ip in sorted(fence-sites)]));records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(f['id'] for f in records if any(e.get('segment')==0x6c9 and e.get('segment_offset')==ip for e in f['entries'])) for ip in ENTRIES];deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_fields_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':203,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Fouradditionalnear4281-43C3-4441-448A/fullSS plusactualfrozen4612/203sites/currentDS/JA-JNE42ADsnapshots/GPR-BP-CFIFDF-normalZF/fullbus/control/writecounts/globaltwo-nearCALLcap/rawchildRETneverfollowed. OldgroupAPIsfrozen/no newuniqueoriginalentries. Whole420A-403B/actualmutabletransitions/validdata-allwriters-capacity-lifetime-IRQ/core open. No DOSsession/realdevices/renderer/audio/fullsuppliedresourceformats/complete-state-machine/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'};record['validator_dependencies'] += [{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in ['analysis/history/input-fields-bus-code-cache-probe-v1.json','analysis/reviews/probe_input_fields_code_cache_v1.py','analysis/history/input-fields-bus-validation-attempt-v2.json','analysis/history/validate_input_fields_bus_attempt_v2.py','analysis/history/input-fields-bus-preparation-refinement-v2.json','analysis/history/validate_input_fields_bus_probe_v1.py']];record['immutable_emulator_code_forms']=[{'prepared42AD':0,'opcode':0x77},{'prepared42AD':1,'opcode':0x75}];record['limits']+=' FreshindependentUCperimmutablebranchform; earlierResultmismatchfromreusedUCcachedJAwhilememory75, exactfailure/fresh4caseprobe preserved. No recoveredC-DLL change orISA/historicalselfmodtiming claim.';out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
