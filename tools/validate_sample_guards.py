"""Compare49E7-4A19 guards/actual4D26/fullSS/frozen4A2E tail and source ordering."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,Limits as SampleLimits,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Limits(C.Structure):_fields_=[('guard_calls',C.c_uint32),('sample',SampleLimits)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['guard_calls','sample_calls','control_calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_sample_guards;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];require(C.sizeof(Result)==52 and C.sizeof(Limits)==12,'Layout');gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());family=['06C9:49E7','06C9:4A19','06C9:4D26','06C9:4A2E','06C9:45FC','06C9:4612','06C9:7977','06C9:780E'];fs=[f for f in g['functions'] if f['entry'] in family];fence={ip for f in fs for ip in f['instructions']};require(len(fence)==156,'Fence');returns={ip for ip in fence if image[0x6c90+ip] in [0xc3,0xcb]};root_returns={ip for f in fs if f['entry'] in ['06C9:49E7','06C9:4A19'] for ip in f['instructions'] if image[0x6c90+ip]==0xc3};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in returns:active['return']=ip;u.emu_stop();return
   if ip in [0x49fe,0x4a10,0x4a26]:
    if active['guards']==active['limits'].guard_calls:active['prefix']='guard';u.emu_stop();return
    active['guards']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP),'guard'))
   if ip in [0x4a31,0x4a39,0x4a41]:
    if active['calls']==active['limits'].sample.calls:active['prefix']='sample';u.emu_stop();return
    active['calls']+=1;active['frames'].append((0x4a34 if ip==0x4a31 else 0x4a3e if ip==0x4a39 else 0x4a46,u.reg_read(UC_X86_REG_SP),'control' if ip==0x4a31 else 'setter' if ip==0x4a39 else 'ring'))
   if ip==0x460e:
    if active['control_calls']==active['limits'].sample.control_calls:active['prefix']='control';u.emu_stop();return
    active['control_calls']+=1;active['frames'].append((0x4611,u.reg_read(UC_X86_REG_SP),'product'))
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written)
  def case(**kw):
   c=dict(entry=0,bit=0,flag=0,bx=0,min=0x8000,max=0x7fff,before=0,counter=0,blocked=0,late=0,selector=1,field=0,threshold=0xffff,control=2000,multiplier=0x8000,cursor=1,same=False,sp=0xe000,flags=2,guards=2,calls=3,control_calls=1);c.update(kw);return c
  def bounds(centers,radius):return sorted({v&65535 for center in centers for v in [0,0x7fff,0x8000,0xffff,center-radius-1,center-radius,center-radius+1,center+radius-1,center+radius,center+radius+1]})
  cases=[]
  for bit,flag in itertools.product([0,1],[0,1]):
   first=-800 if bit and flag else -400;second=800 if bit else 400;edge=bounds([first,second],5)
   cases += [case(bit=bit,flag=flag,min=low,max=high,same=same,flags=flags) for low,high,same,flags in itertools.product(edge,edge,[False,True],[2,0x603])]
  for bx in [0,2]:
   edge=bounds([-200 if bx&2 else 200],7)
   cases += [case(entry=1,bx=bx,min=low,max=high,same=same,flags=flags) for low,high,same,flags in itertools.product(edge,edge,[False,True],[2,0x603])]
  boundary=[0,1,25,74,75,199,200,201,0x7fdb,0x8000,0x8024,0xffe7,0xffff]
  cases += [case(entry=e,bx=bx,before=b,selector=b,field=boundary[b%len(boundary)],threshold=[0,127,0x8000,0xffff][b%4],same=same,flags=flags) for e,bx,b,same,flags in itertools.product([0,1],[0,2],range(256),[False,True],[2,0x603])]
  cases += [case(entry=e,bx=bx,guards=guards,calls=calls,control_calls=control,control=seed,min=low,max=high,same=same) for e,bx,guards,calls,control,seed,(low,high),same in itertools.product([0,1],[0,2],range(3),range(4),[0,1],[0,2000],[(0x8000,0x7fff),(0,0),(395,405)],[False,True])]
  cases += [case(entry=e,bx=bx,before=b,selector=selector,same=True,sp=sp,flags=flags,cursor=0xb5 if sp==0x67a0 else 0x3e if sp==0x672b else 1) for e,bx,b,selector,sp,flags in itertools.product([0,1],[0,2],[0,50,128],[1,135,151,161],[0x3334,0x3336,0x3338,0x333a,0x3330,0x52d0,0x5ef8,0x5efa,0x66e6,0x66ea,0x66ec,0x672b,0x67a0],[2,0x603])]
  cases += [case(entry=e,bx=bx,before=b,ds=ds,same=same,sp=sp,flags=flags) for e,bx,b,ds,same,sp,flags in itertools.product([0,1],[0,2],[0,50,128],[0,0xffff],[False,True],[20,0xffe0],[2,0x603])]
  cases += [case(entry=e,bx=bx,counter=counter,blocked=blocked,late=late,before=b,same=same,flags=flags) for e,bx,counter,blocked,late,b,same,flags in itertools.product([0,1],[0,2],[0,4,255],[0,1],[0,1],[0,50,128],[False,True],[2,0x603])]
  for c in cases:
   data=bytearray(base);ds=c.get('ds',principal);ss=ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];entry=0x49e7 if c['entry']==0 else 0x4a19
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   def wb(sg,o,v):data[((sg<<4)+(o&65535))&0xfffff]=v&255
   for o,v in [(0x3334,c['min']),(0x3336,c['max']),(0x52ce,c['control']),(0x3328,c['multiplier']),(0x332c,0x1234),(0x8a9a,c['blocked']),(0x33c8,c['field']),(0x33ca,c['field']),(0x33cc,c['field']),(0x23b2,c['threshold']),(0x66e6,c['cursor'])]:put(ds,o,v)
   for o,v in [(0x5491,c['bit']),(0x37f6,c['flag']),(0x2f56,c['selector']),(0x337b,c['counter']),(0x33c6,c['field']),(0x2418,c['threshold']),(0x90a8,c['late']),(0x5490,0x55)]:wb(ds,o,v)
   for i in range(256):wb(ds,0x66e8+i,c['before'])
   put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,c['bx'],0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);limits=Limits(c['guards'],SampleLimits(c['calls'],c['control_calls']));u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limits=limits,guards=0,calls=0,control_calls=0,frames=[],writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});label=f'{load:x}/{ds:x}/'+str(c);u.emu_start(cs*16+entry,0,count=500);root=raw=False;raw_kind=''
   while active['return']:
    ip=active['return'];active['return']=False;active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip in root_returns:require(not active['frames'],'Rootframe '+label);root=True;break
    nextip,nextsp,kind=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,nextip,nextsp):raw=True;raw_kind=kind;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=500)
   require(root or raw or active['prefix'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],C.byref(incoming),C.byref(limits),C.byref(r));require((r.status,r.current_sp,r.guard_calls,r.sample_calls,r.control_calls,r.bus_writes)==(0 if root else 1 if raw else 3,u.reg_read(UC_X86_REG_SP),active['guards'],active['calls'],active['control_calls'],active['writes']),'Status/counters '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);require((r.flags_valid,r.zero_flag)==(int(root),(ef>>6)&1 if root else 0),'RequiredZF '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['root_near_return' if root else 'raw_'+raw_kind+'_return' if raw else 'prefix_'+active['prefix']]+=1;coverage['guard_CALLs']+=r.guard_calls;coverage['tail_control_setter_ring_CALLs']+=r.sample_calls;coverage['control_4612_CALLs']+=r.control_calls;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['raw_root_returns']+=int(root and r.next_ip!=0x1111);coverage['no_sample_root_returns']+=int(root and r.sample_calls==0);coverage['actual_IF1_sample_returns']+=int(root and r.sample_calls==3 and r.returned.registers.interrupts_enabled==1)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence,'Coverage '+str([f'{ip:04X}' for ip in sorted(fence-sites)]));f=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(v['id'] for v in f if any(e.get('segment')==0x6c9 and e.get('segment_offset')==ip for e in v['entries'])) for ip in [0x49e7,0x4a19]];deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sample_guards.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Twoactualnearroots49E7/4A19/fullSS4D26guardframes/frozeninterval-arithmeticC/requiredZF/conditional4A2E-tail-fullcontrol-setter-ring/globalguard-sample-controlCALLcaps/wholebus-GPR-BP-CFIFDF-rootZF/control/counts. No newspan. Actualindirectcaller-indexdomains/allwriters-reset-seed-sharedsource-lifetime-IRQexclusion/core/RNGpurpose open. NoDOSsession/device/audio/fullresourcecodec/complete-state-machine/gameplay/fidelity acceptance. Physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
