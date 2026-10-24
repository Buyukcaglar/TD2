"""Compare motion full FLAGS before clamps, actual SS and actual multiply/RETF8."""
import argparse, ctypes as C, hashlib, itertools, json, random, struct, sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[(0x6b3,8),(0x13a8,0x2ee8)]
TARGETS=[0x44be,0x44bf,0x44c5,0x44d2]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid','unresolved_target','reserved']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ')
 n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
 g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={(seg,ip) for seg,start in ENTRIES for f in g['functions'] if f['entry']==f'{seg:04X}:{start:04X}' for ip in f['instructions']};require(len(fence)==146,'Fence')
 returns={(0x6b3,0x160),(0x13a8,0x2f00),(0x13a8,0x2f19)}|{(0x6c9,ip) for ip in [0x44be,0x44c4,0x44d1,0x44d7]}
 fn=C.CDLL(str(lib)).td2ega_motion_flags_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==52,'Layout')
 def case(**kw):
  c=dict(entry=0,steer=0,sample=0,rotation=0,lateral=0,drag=1,other=0,factor=0,shift=0xffff,same=False,ds=None,es=None,sp=0xe000,flags=2,calls=1,first=1,second=1,key=1,ah=0xa5,match=0,target=0x44bf,flag=0,toggle=0,zeroax=False,flags_mask=0xffff,tag="base");c.update(kw);return c
 edges=[0,1,0xff,0x100,0x5ff,0x600,0xbff,0xc00,0xe7f,0xe80,0xe81,0x7fff,0x8000,0xf17f,0xf180,0xffff]
 cases=[case(steer=b,sample=sample,rotation=edges[(b+sample)%len(edges)],lateral=(b*257)^sample,drag=b&1,other=(b>>1)&1,factor=b*257,shift=sample*257,same=same,flags=flags) for b,sample,same,flags in itertools.product(range(256),[0,0x7f,0x80,0xff],[False,True],[2,0x643])]
 cases += [case(rotation=r,lateral=l,steer=steer,drag=drag,other=other,same=same,sample=0x80,flags=0x643) for r,l,steer,(drag,other),same in itertools.product(edges,edges,[0,1,0xff],[(0,0),(1,0),(1,1)],[False,True])]
 shifts=[0,1,0x1ff,0x200,0x201,0x7fff,0x8000,0xffff]
 cases += [case(steer=steer,sample=0xff,rotation=0x1000,lateral=0x8000,drag=1,other=1,factor=factor,shift=shift,same=same) for factor,shift,steer,same in itertools.product(shifts,shifts,[0,1,0x80,0xff],[False,True])]
 cases += [case(steer=steer,sample=0x80,rotation=0x8000,lateral=0xffff,drag=drag,other=1,same=True,sp=field+delta,flags=flags) for field,delta,steer,drag,flags in itertools.product([0x2f46,0x2f4a,0x30e4,0x30e6,0x3322,0x335a,0x336d,0x336e],[0,2,4,6,8,12,14,16,18,20],[0,1,0x80,0xff],[0,1],[2,0x643])]
 cases += [case(sp=sp,ds=ds,same=same,steer=steer,rotation=0x1000,lateral=0xffff,other=1,calls=limit,flags=flags) for sp,ds,same,steer,limit,flags in itertools.product([20,0xffe0],[None,0,0xffff],[False,True],[0,1,0xff],[0,1],[2,0x643])]
 longs=[0,1,0xffff,0x10000,0x10001,0x7fffffff,0x80000000,0xffffffff,0xffff0000,0x12345678]
 cases += [case(entry=1,first=first,second=second,same=same,sp=sp,flags=flags) for first,second,same,sp,flags in itertools.product(longs,longs,[False,True],[0,1,2,0xe000,0xfffc,0xfffd,0xfffe,0xffff],[2,0x643])]
 cases += [case(entry=1,first=0xffff0000|b,second=0x10001,same=True,sp=0x30e4+(b%20),flags=0x643) for b in range(256)]
 cases += [case(entry=2,key=key,match=match,target=TARGETS[key%4],same=same,es=0x8000 if key&1 else None,flags=0x643 if key&2 else 2,flag=(key>>2)&1,toggle=(key>>3)&1) for key,match,same in itertools.product(range(256),range(5),[False,True])]
 cases += [case(entry=2,key=key,match=match,target=target,same=same,sp=sp,flags=flags,flag=flag,toggle=toggle,zeroax=zeroax) for key,match,target,same,sp,flags,flag,toggle,zeroax in itertools.product([0,0x80],[None,0,4],[0,0xffff]+TARGETS,[False,True],[0,0xfffe,0x33af,0x2f58,0x5490,0x33dc,0x33de],[2,0x643],[0,1],[0,1],[False,True])]
 cases += [case(entry=entry,ds=ds,es=ds,same=same,sp=0x4000,flags=flags,steer=0xff,rotation=0x1000,first=0xffffffff,second=0xffffffff,key=0xff,target=0x44c5) for entry,ds,same,flags in itertools.product(range(3),[0,0xffff],[False,True],[2,0x643])]
 rng=random.Random(0x6b344a6)
 for _ in range(512):cases.append(case(steer=rng.randrange(256),sample=rng.randrange(256),rotation=rng.randrange(65536),lateral=rng.randrange(65536),drag=rng.randrange(2),other=rng.randrange(2),factor=rng.randrange(65536),shift=rng.randrange(65536),same=rng.choice([False,True]),flags=rng.choice([2,3,0x202,0x402,0x643])))
 cases=[c for c in cases if c['entry']==0]
 flag_words=[2|sum(((k>>i)&1)<<b for i,b in enumerate([0,2,4,6,7,9,10,11])) for k in range(256)]
 cases += [case(steer=steer,rotation=rotation,lateral=0,drag=1,other=other,flags=f,flags_mask=mask,tag='all_flags') for f,mask,(steer,rotation,other) in itertools.product(flag_words,[0xffff,0xffef],[(0,0x100,0),(1,0x8000,1),(0xff,0x7fff,1)])]
 # Capture original operand at014F before a conditional clamp can overwrite it.
 cases += [case(steer=steer,rotation=rotation,lateral=0,drag=0,other=1,factor=factor,flags=f,flags_mask=mask,tag='clamp_flags') for steer,rotation,factor,f,mask in itertools.product([0,1,0x7f,0x80,0xff],[0,1,0xe7f,0xe80,0xe81,0x7fff,0x8000,0xf17f,0xf180,0xf181,0xffff],[0,0xffff],[2,0xed7],[0xffff,0xffef])]
 cases += [case(steer=steer,rotation=rotation,drag=0,other=1,calls=0,flags=f,flags_mask=mask,tag='prefix_flags') for steer,rotation,f,mask in itertools.product([0,1,0x80,0xff],[0,0x8000,0xffff],flag_words,[0xffff,0xffef])]
 vectors=instructions=0;sites=set();coverage=Counter();pattern=bytes((i*19+23)&255 for i in range(65536))
 for load in [0x1000,0x2345]:
  principal=load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def word(cpu,sg,o):
   at=((sg<<4)+(o&65535))&0xfffff;return int.from_bytes(cpu.mem_read(at,2),'little')
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   seg=(cpu.reg_read(UC_X86_REG_CS)-load)&65535;ip=cpu.reg_read(UC_X86_REG_IP);site=(seg,ip);require(site in fence,'Fence '+str(site))
   if site==(0x6b3,0xa7):active['damped']=True
   if site==(0x6b3,0x147):active['upper_cmp_OF1']=bool(cpu.reg_read(UC_X86_REG_EFLAGS)&0x800)
   if site==(0x6b3,0x14f):active['cmp_operand']=word(cpu,cpu.reg_read(UC_X86_REG_DS),0x2f46)
   if site==(0x6b3,0x15d) and active.get('cmp_operand') is not None:
    active['postclamp_word']=word(cpu,cpu.reg_read(UC_X86_REG_DS),0x2f46)
   if site in returns:active['return']=site;cpu.emu_stop();return
   if site==(0x6b3,0x114):
    if active['calls']==active['limit']:active['prefix']=3;cpu.emu_stop();return
    active['calls']+=1;active['frames'].append((load+0x6b3,0x119,(cpu.reg_read(UC_X86_REG_SP)+8)&65535,cpu.reg_read(UC_X86_REG_BP)))
   if site==(0x6c9,0x44ba):
    target=word(cpu,cpu.reg_read(UC_X86_REG_DS),(cpu.reg_read(UC_X86_REG_BX)+0x33dc)&65535)
    if target not in TARGETS:active['prefix']=4;active['unresolved']=target;cpu.emu_stop();return
    active['targets'].add(target)
   active['instructions']+=1;active['sites'].add(site)
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;es=ds if c['es'] is None else c['es'];sp=c['sp'];flags=c['flags']
   start=(ds<<4)&0xfffff;first=min(65536,0x100000-start);data[start:start+first]=pattern[:first]
   if first<65536:data[:65536-first]=pattern[first:]
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   for o,v in [(0x2f46,c['rotation']),(0x2f4a,c['lateral']),(0x3322,c['other']),(0x30e6,c['factor']),(0x335a,c['shift'])]:put(ds,o,v)
   for o,v in [(0x336d,c['steer']),(0x30e4,c['sample']),(0x336e,c['drag']),(0x90a8,c['flag']),(0x33af,c['toggle']),(0x2f58,c['toggle'])]:put(ds,o,v,1)
   if c['entry']==2:
    for i in range(5):put(es,0x33da-i,(c['key']+1)&255,1)
    if c['match'] is not None:put(es,0x33da-c['match'],c['key'],1)
    for i in range(5):put(ds,0x33dc+2*i,c['target'])
   put(ss,sp,0x1111)
   if c['entry']!=2:put(ss,sp+2,0x2222)
   if c['entry']==1:
    for i,v in enumerate([c['first']&65535,c['first']>>16,c['second']&65535,c['second']>>16]):put(ss,sp+4+2*i,v)
   ax=(c['ah']<<8)|c['key'] if c['entry']==2 else 0xa55a
   if c['zeroax']:ax=0
   incoming=StateRegisters(Registers(ax,0xb123,0xc456,0xd789,0x3456,0x4567,ds,es,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);seg,ip=ENTRIES[c['entry']];cs=load+seg;u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(calls=0,limit=c['calls'],frames=[],instructions=0,writes=0,sites=set(),targets=set(),executing_return=False,prefix=0,unresolved=0,damped=False,upper_cmp_OF1=False,cmp_operand=None,postclamp_word=None,**{'return':None});label=str((load,c));u.emu_start(cs*16+ip,0,count=1000);root=raw=False;root_site=None
   while active['return']:
    ret=active['return'];active['return']=None
    if ret[0]!=0x6c9 and u.reg_read(UC_X86_REG_SP)>0xfffc:active['prefix']=5;break
    active['sites'].add(ret);active['instructions']+=1;active['executing_return']=True;u.emu_start(u.reg_read(UC_X86_REG_CS)*16+ret[1],0,count=1);active['executing_return']=False
    if not active['frames']:root=True;root_site=ret;break
    expected=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_BP))!=expected:raw=True;break
    u.emu_start(u.reg_read(UC_X86_REG_CS)*16+u.reg_read(UC_X86_REG_IP),0,count=1000)
   require(root or raw or active['prefix'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,flags,c['flags_mask'],C.byref(incoming),c['calls'],C.byref(r));ef=u.reg_read(UC_X86_REG_EFLAGS);status=0 if root else 1 if raw else active['prefix']
   require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.unresolved_target)==(status,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['calls'],active['writes'],active['unresolved']),'Result '+label+str((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,active)))
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label+str((values(r.returned.registers)[:8]+[r.returned.bp],[u.reg_read(reg) for reg in REGS]+[u.reg_read(UC_X86_REG_BP)])))
   require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label+str((r.returned.carry,ef&1)));valid=int(root and root_site!=(0x13a8,0x2f00));require(r.flags_valid==valid and r.zero_flag==((ef>>6)&1 if valid else 0),'Defined rootZF '+label)
   expected_mask=0xffff if status in [0,3] else (0xffff&~0x8d5)|0x601
   require(r.flags_mask==expected_mask and ((r.flags_word^ef)&r.flags_mask)==0,'FullFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(ef))))
   coverage['full_defined_FLAGS_normal']+=int(root and r.flags_mask==0xffff)
   coverage['full_defined_FLAGS_before_CALL']+=int(status==3 and r.flags_mask==0xffff)
   coverage['initial_AF_unknown']+=int(c['flags_mask']==0xffef)
   coverage['damping_terminal_SUB']+=int(root and active['damped'])
   if root and active['cmp_operand'] is not None:
    coverage['general_terminal_CMP']+=1
    coverage['general_terminal_OF1']+=int((ef>>11)&1)
    coverage['upper_CMP_OF1']+=int(active['upper_cmp_OF1'])
    coverage['preclamp_operand_changed']+=int(active['cmp_operand']!=active['postclamp_word'])
    a_cmp=active['postclamp_word'];b_cmp=0xf180;v_cmp=(a_cmp-b_cmp)&65535
    wrong_of=int(bool((a_cmp^b_cmp)&(a_cmp^v_cmp)&0x8000))
    wrong_cf=int(a_cmp<b_cmp);wrong_zf=int(v_cmp==0)
    coverage['postclamp_reconstruction_discriminator']+=int((wrong_cf,wrong_zf,wrong_of)!=(ef&1,(ef>>6)&1,(ef>>11)&1))
   coverage['tag_'+c['tag']]+=1
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['root_return' if root else 'raw_child_return' if raw else 'prefix_'+str(active['prefix'])]+=1;coverage['actual_far_calls']+=r.calls;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS']+=int(ds==ss);coverage['ES_differs_DS']+=int(es!=ds);coverage['changed_root_coordinates']+=int(root and (r.next_segment,r.next_ip)!=((cs if c['entry']==2 else 0x2222),0x1111));coverage['stack_offset_wrap_cases']+=int(sp in [0,1,0xfffc,0xfffd,0xfffe,0xffff]);coverage['undefined_fast_MUL_ZF_excluded']+=int(root_site==(0x13a8,0x2f00))
   for target in active['targets']:coverage['scanner_target_'+hex(target)]+=1
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{s:04X}:{i:04X}' for s,i in sorted(fence-sites)]}),flush=True)
 require(sites==fence and all(coverage[k] for k in ['full_defined_FLAGS_normal','full_defined_FLAGS_before_CALL','initial_AF_unknown','damping_terminal_SUB','general_terminal_CMP','upper_CMP_OF1','preclamp_operand_changed','postclamp_reconstruction_discriminator']),'Coverage '+str(sorted(fence-sites))+str(coverage))
 records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(f['id'] for f in records if any(e.get('segment')==seg and e.get('segment_offset')==ip for e in f['entries'])) for seg,ip in ENTRIES[:1]];deps=['tools/validate_motion_scan_bus.py','tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json','analysis/reviews/far-return-stack-probe-v1.json','tools/validation/probe_far_return_stack.py']
 record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_motion_flags_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':146,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Additional06B3:0008 actualSS motion view with actual13A8:2EE8 RETF8; whole1MiB20bitRAM/GPR-BP/CFIFDF/full defined terminalFLAGS/control/writes. NormaldampingSUBAXAX andgeneralCMP2F46,F180 capturedbeforeclamp; before114CALL NEGDX fullydefined. BothincomingAFvalidityprofiles/all256rawflagwords; noCODE-hookEFLAGSmutations. Childprefix flags conservativelymasked. No new uniqueoriginalentry. Whole420A-403B/caller-validdomains-allwriters-capacity-lifetime-exclusion-IRQ/core remainopen; noDOSsession/realdevices/renderer/audio/fullresourceformats/complete-state-machine/gameplay/fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
