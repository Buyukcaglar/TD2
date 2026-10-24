"""Compare6528 actualSS/42sites with explicit callback effects and retiredfarRET."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
TARGETS=[0x645a,0x646f,0x6488,0x64c7,0x6508,0x6518]
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['site','target_segment','target_ip','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Response(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32)]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Response))
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid','callback_target','reserved']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:6528')['instructions']);require(len(fence)==42,'Fence');fn=C.CDLL(str(lib)).td2ega_key_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;require((C.sizeof(Request),C.sizeof(Response),C.sizeof(Result))==(34,36,48),'Layouts')
 def case(**kw):
  c=dict(key=1,guard=0,target=0x645a,mode=0,outds=None,same=False,ds=None,sp=0xe000,flags=2,limit=1);c.update(kw);return c
 cases=[case(key=(high<<8)|low,guard=guard,target=TARGETS[(high+low)%6] if low&1 else 0,same=same,flags=f) for high,low,guard,same,f in itertools.product([0,1,0x7f,0x80,0xff],range(256),[0,1],[False,True],[2,0x643])]
 cases += [case(key=high<<8,guard=guard,target=target,same=same,flags=f) for high,guard,target,same,f in itertools.product(range(256),[0,1],[0,0x645a],[False,True],[2,0x643])]
 cases += [case(key=key,mode=mode,outds=ds,limit=limit,same=same,flags=f) for key,mode,ds,limit,same,f in itertools.product([0,0x80,0x7f,0x8500,0xffff],range(8),[None,0,0xffff,0x6000],[0,1],[False,True],[2,0x643])]
 stack=[0,1,2,6,8,10,0xfffa,0xfffc,0xfffd,0xfffe,0xffff,0x6048,0x604a,0x6050,0x6148,0x6250,0x6252,0x6254,0x6256]
 cases += [case(key=key,mode=mode,sp=sp,same=same,flags=f) for key,mode,sp,same,f in itertools.product([0,1,0x80,0x7f,0x8400,0xffff],[0,1,2,5],stack,[False,True],[2,0x643])]
 cases += [case(key=key,ds=ds,same=same,sp=sp,flags=f,mode=mode) for key,ds,same,sp,f,mode in itertools.product([0,1,0xffff],[0,0xffff],[False,True],[0xe000,0x6254],[2,0x643],[0,1])]
 rng=random.Random(0x6528)
 for _ in range(256):cases.append(case(key=rng.randrange(65536),guard=rng.randrange(2),target=rng.choice([0]+TARGETS),mode=rng.randrange(8),outds=rng.choice([None,0,0x6000,0xffff]),same=rng.choice([False,True]),flags=rng.choice([2,3,0x202,0x402,0x643])))
 vectors=instructions=synthetic_returns=0;sites=set();coverage=Counter();pattern=bytes((i*31+13)&255 for i in range(65536))
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;base[0xa0100]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def snapshot(cpu):
   ef=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),cpu.reg_read(UC_X86_REG_BP),ef&1)
  def code(cpu,address,size,unused):
   if active.get('executing_control'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(address))
   if ip in [0x6535,0x6565,0x6584]:active['return']=ip;cpu.emu_stop();return
   if ip==0x6559:
    active['target']=cpu.reg_read(UC_X86_REG_BX)
    if active['calls']==active['limit']:active['prefix']=3
    else:active['call_pending']=True
    cpu.emu_stop();return
   active['instructions']+=1;active['sites'].add(ip)
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
  def effects(c,q,put):
   mode=c['mode'];sp=q.stack_sp;ss=q.stack_segment;sg=q.incoming.registers.ds
   if mode==1:
    for delta,value in [(4,0xcafe),(6,0xbabe),(8,0xf00d)]:put(ss,sp+delta,value)
   elif mode==2:put(ss,sp,0x4444)
   elif mode==3:put(ss,sp+2,0x5555)
   elif mode==5:put(ss,sp+10,0x3333);put(ss,sp+12,0x4444)
   elif mode==7:put(sg,0x6252,0xee,1)
   returned=StateRegisters(Registers(0x1357,0x2468,0x369c,0xabcd,0x1111,0x2222,sg if c['outds'] is None else c['outds'],0x7070,mode&1,(mode>>1)&1),0xaaaa,(mode>>2)&1)
   return returned,(sp+2)&65535 if mode==4 else sp
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;sp=c['sp'];ef=c['flags'];start=(ds<<4)&0xfffff;first=min(65536,0x100000-start);data[start:start+first]=pattern[:first]
   if first<65536:data[:65536-first]=pattern[first:]
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   block=struct.pack('<H',c['target'])*261;at=((ds<<4)+0x6048)&0xfffff;cut=min(len(block),0x100000-at);data[at:at+cut]=block[:cut]
   if cut<len(block):data[:len(block)-cut]=block[cut:]
   put(ds,0x6252,c['guard'],1);put(ss,sp,0x1111);put(ss,sp+2,0x2222);put(ss,sp+4,c['key']);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(ef>>9)&1,(ef>>10)&1),0x5678,ef&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6528),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,v)
   active.update(calls=0,limit=c['limit'],instructions=0,writes=0,sites=set(),executing_control=False,call_pending=False,prefix=0,target=0,callback_request=None,synthetic_returns=0,**{'return':None});label=str((load,c));root=raw=False;u.emu_start(cs*16+0x6528,0,count=100)
   if active['call_pending']:
    before=u.reg_read(UC_X86_REG_SP);active['instructions']+=1;active['sites'].add(0x6559);active['calls']+=1;active['executing_control']=True;u.emu_start(cs*16+0x6559,0,count=1);active['executing_control']=False
    require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,active['target'],(before-2)&65535),'ActualnearCALLBX '+label);q=Request(0x6559,cs,active['target'],ss,u.reg_read(UC_X86_REG_SP),snapshot(u));active['callback_request']=bytes(q)
    def guest_put(sg,o,v,width=2):
     at=((sg<<4)+(o&65535))&0xfffff;u.mem_write(at,bytes([v&255]))
     if width==2:u.mem_write((at+1)&0xfffff,bytes([(v>>8)&255]))
    changed,child_sp=effects(c,q,guest_put)
    for reg,v in list(zip(REGS,values(changed.registers)[:8]))+[(UC_X86_REG_BP,changed.bp),(UC_X86_REG_SP,child_sp),(UC_X86_REG_EFLAGS,2|changed.carry|((c['mode']&1)<<6)|(changed.registers.interrupts_enabled<<9)|(changed.registers.direction<<10))]:u.reg_write(reg,v)
    if child_sp>0xfffc:active['prefix']=5
    else:
     u.reg_write(UC_X86_REG_CS,0xa000);u.reg_write(UC_X86_REG_IP,0x100);active['executing_control']=True;u.emu_start(0xa0100,0,count=1);active['executing_control']=False;active['synthetic_returns']+=1
     if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x655b,(before+2)&65535):raw=True
     else:u.emu_start(cs*16+0x655b,0,count=100)
   if active['return']:
    ip=active['return']
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['prefix']=5
    else:active['instructions']+=1;active['sites'].add(ip);active['executing_control']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_control']=False;root=True
   require(root or raw or active['prefix'],'Outcome '+label);errors=[];native_calls=[]
   def native_service(ctx,memory,qptr,rptr):
    try:
     q=qptr.contents;require(bytes(q)==active['callback_request'],'Fullcallbackrequest');native_calls.append(bytes(q))
     def native_put(sg,o,v,width=2):
      at=((sg<<4)+(o&65535))&0xfffff;memory[at]=v&255
      if width==2:memory[(at+1)&0xfffff]=(v>>8)&255
     changed,child_sp=effects(c,q,native_put);response=rptr.contents;response.returned=changed;response.bus_writes=0
     if child_sp>0xfffc:response.status=5;response.current_sp=child_sp;response.next_segment=q.target_segment;response.next_ip=q.target_ip
     else:
      def word(o):
       at=((q.stack_segment<<4)+(o&65535))&0xfffff;return memory[at]|(memory[(at+1)&0xfffff]<<8)
      response.status=0;response.current_sp=(child_sp+4)&65535;response.next_ip=word(child_sp);response.next_segment=word(child_sp+2)
     return 1
    except Exception as error:errors.append(str(error));return 0
   callback=Service(native_service);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),c['limit'],callback,None,C.byref(r));observed=u.reg_read(UC_X86_REG_EFLAGS)
   require(not errors,'Nativecallback '+label+str(errors));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.callback_target)==(0 if root else 1 if raw else active['prefix'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['calls'],active['writes'],active['target']),'Result '+label+str((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.callback_target,active['writes'])))
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(observed&1,(observed>>9)&1,(observed>>10)&1),'CFIFDF '+label);require((r.flags_valid,r.zero_flag)==(int(root),(observed>>6)&1 if root else 0),'NormalZF '+label)
   vectors+=1;instructions+=active['instructions'];synthetic_returns+=active['synthetic_returns'];sites.update(active['sites']);coverage['root_RETF' if root else 'raw_child_farRET' if raw else 'prefix_'+str(active['prefix'])]+=1;coverage['actual_near_CALLBX']+=r.calls;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root_coordinates']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['callback_DS_changes']+=int(bool(native_calls) and c['outds'] is not None and c['outds']!=ds);coverage['callback_target_from_saved_BP']+=int(active['target']==0x5678);coverage['callback_saved_SI_DI_BP_mutations']+=int(bool(native_calls) and c['mode']==1);coverage['busy_guard_from_saved_BP']+=int(ds==ss and sp==0x6254 and not native_calls)
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and all(coverage[k] for k in ['raw_child_farRET','prefix_3','prefix_5','changed_root_coordinates','callback_target_from_saved_BP','busy_guard_from_saved_BP']),'Coverage '+str(sorted(fence-sites)))
 deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/td2ega-key-dispatch-validation-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json','analysis/reviews/far-return-stack-probe-v1.json'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000153'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_key_dispatch_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':42,'instruction_sites_exercised':len(sites),'synthetic_callback_farRET_operations':synthetic_returns,'fixture_coverage':dict(coverage),'limits':'AdditionalactualSS6528/42originalsites/whole1MiB20bitRAM/GPR-BP-CFIFDF-normalZF/SSkeyrewrite-guard-table-aliases/savedDI-SI/PUSHCS-actualnearCALLBX/retiredfarcallbackresponse/actualrootRETF. Callbackbodies areexplicitABI effects plusprivategenericRETFinstruction; syntheticreturns excludedfromoriginalinstructioncount andnotbodyproof. Responsecanwrapactualrecoveredcallee later; unknown/rawreturnneverfollowed. NativebeforeCALL3/preunqualifiedfarRET5 prefixes separatefromoriginalerrors. Sameentrycountedonce/oldsource-DLL-receiptsfrozen. Callbackdomain-allwriters-lifetime-exclusion/actualIRQ/inputpoll-420A-403B-core/P1-GATE remainopen; noDOSsession/realdevices/renderer/audio/fullresourceformats/complete-state-machine/gameplay/fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','synthetic_callback_farRET_operations','fixture_coverage']},indent=2))
if __name__=='__main__':main()
