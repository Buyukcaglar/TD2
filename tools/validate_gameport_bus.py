"""Compare actualSS gameport sampler/initializer/translator and ordered port states."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
ENTRIES=[0x6686,0x680a,0x6828]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['operation','port','value','segment','ip','ss','sp','zero_flag']]+[('state',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Request),C.POINTER(C.c_uint8))
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['reads','transfers','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in ENTRIES] for ip in f['instructions']};require(len(fence)==150,'Fence')
 fn=C.CDLL(str(lib)).td2ega_gameport_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Request)==40 and C.sizeof(Result)==48,'Layouts')
 profiles=[(0x50,0,0x4e20,8,0,0),(0,4000,500,8,100,300),(100,300,200,1,125,275),(100,300,200,0,125,275),(0x7fff,0x8000,0xffff,1,0x7ffe,0x8001),(0x8000,0x7fff,0x8001,1,0xffff,0),(0xffff,0,0x7fff,0xffff,0x8000,0x7fff)]
 delays=[(0,0),(0,1),(1,0),(1,2),(2,1),(79,81),(81,79),(80,80),(3999,3999),(4000,4000),(4001,4001),(2,4001),(4001,2)]
 def case(**kw):
  c=dict(entry=0,x=1,y=2,xp=profiles[0],yp=profiles[0],initial=0xff,final=0xdf,enabled=1,config=1,same=False,ds=None,sp=0xe000,flags=2,limit=5000,argument=0x1234,fill=None);c.update(kw);return c
 cases=[]
 for (index,(x,y)),(xi,xp),(yi,yp),same in itertools.product(enumerate(delays),enumerate(profiles),enumerate(profiles),[False,True]):
  initial,final=[(0,0),(0x33,0x33),(0xff,0xdf),(0xdf,0xef)][(xi+yi+index)%4];cases.append(case(x=x,y=y,xp=xp,yp=yp,initial=initial,final=final,same=same,flags=0x643 if (xi+yi+index)&1 else 2))
 flags=[2,3,0x42,0x43,0x202,0x402,0x642,0x643]
 cases += [case(enabled=enabled,config=config,same=same,sp=sp,flags=f) for enabled,config,same,sp,f in itertools.product([0,1,255],[0,2,254],[False,True],[0,0xfffc,0xfffd,0xffff],flags)]
 cases += [case(x=x,y=y,xp=profiles[p],yp=profiles[(p+2)%len(profiles)],same=True,sp=field+delta,flags=f) for (x,y),p,field,delta,f in itertools.product([(0,1),(1,0),(2,3)],range(len(profiles)),[0x6cfc,0x627c,0x627e,0x6280,0x6281,0x6282,0x6284,0x6286,0x6288,0x628a,0x628c,0x628e,0x6290,0x6292,0x6294,0x6296,0x6298,0x629a,0x629c],[0,1,2],[2,0x643])]
 cases += [case(x=x,y=y,same=same,limit=limit,sp=sp,flags=f) for (x,y),same,limit,sp,f in itertools.product([(0,0),(0,4001),(4001,0),(4001,4001)],[False,True],[0,1,2,3,10,4002,4003],[0xe000,0x6280],[2,0x643])]
 cases += [case(entry=1,fill=fill,same=same,sp=sp,flags=f) for fill,same,sp,f in itertools.product([0,255,0xa5,0x3c],[False,True],[0,1,0xfffc,0xfffd,0xfffe,0xffff,0x6281,0x6282,0x6283,0x6284,0x628d,0x628e,0x6290,0x6cfc],flags)]
 cases += [case(entry=2,argument=(high<<8)|low,same=same,flags=0x643 if low&1 else 2) for high,low,same in itertools.product([0,1,0x7f,0x80,0xff],range(256),[False,True])]
 cases += [case(entry=2,argument=argument,same=same,sp=sp,flags=f) for argument,same,sp,f in itertools.product([0,1,15,16,0x7fff,0x8000,0xffff],[False,True],[0,1,2,0xfffc,0xfffd,0xfffe,0xffff,0x629d,0x629e,0x629f,0x62a0,0x62a1,0x62af,0x62b0,0x62b1],flags)]
 cases += [case(entry=entry,ds=ds,same=same,sp=sp,flags=f) for entry,ds,same,sp,f in itertools.product(range(3),[0,0xffff],[False,True],[0,0xfffc,0xfffd,0xffff],flags)]
 rng=random.Random(0x66866828)
 for _ in range(128):cases.append(case(x=rng.randrange(9),y=rng.randrange(9),xp=tuple(rng.randrange(65536) for _ in range(6)),yp=tuple(rng.randrange(65536) for _ in range(6)),initial=rng.randrange(256),final=rng.randrange(256),same=rng.choice([False,True]),flags=rng.choice(flags)))
 vectors=instructions=0;sites=set();coverage=Counter();pattern=bytes((i*23+41)&255 for i in range(65536))
 for load in [0x1000,0x2345]:
  cs,principal=load+0x6c9,load+0x178f;base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=image;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def snapshot(cpu,operation,ip):
   ef=cpu.reg_read(UC_X86_REG_EFLAGS);state=StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),cpu.reg_read(UC_X86_REG_BP),ef&1)
   return Request(operation,cpu.reg_read(UC_X86_REG_DX),cpu.reg_read(UC_X86_REG_AX)&255,cpu.reg_read(UC_X86_REG_CS),ip,cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP),(ef>>6)&1,state)
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(address))
   if ip in [0x668f,0x6802,0x6827,0x6838]:active['return']=ip;cpu.emu_stop();return
   if ip in [0x669f,0x66ba,0x67f0]:
    if active['guest']['reads']==active['limit']:active['prefix']=True;cpu.emu_stop();return
    active['io_request']=snapshot(cpu,0,ip)
   elif ip==0x66b5:active['io_request']=snapshot(cpu,1,ip)
   active['instructions']+=1;active['sites'].add(ip)
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  def device(model,request):
   require(request.port==0x201,'Port201');enabled=request.state.registers.interrupts_enabled
   if request.operation:
    require(model['phase']=='trigger' and enabled==0 and request.value==active['c']['initial'],'Trigger');model['phase']='poll';value=0
   elif model['phase']=='initial':value=active['c']['initial'];model['phase']='trigger';model['reads']+=1
   elif model['phase']=='poll' and enabled==0:
    tick=model['polls'];model['polls']+=1;value=(0xf0 if tick&1 else 0x0c)|(1 if tick<active['c']['x'] else 0)|(2 if tick<active['c']['y'] else 0);model['reads']+=1
   else:require(model['phase']=='poll' and enabled==1,'Final read');value=active['c']['final'];model['phase']='done';model['reads']+=1
   model['events'].append((bytes(request),value));return value
  def port_in(cpu,port,size,unused):require(size==1 and port==0x201,'INwidth');return device(active['guest'],active['io_request'])
  def port_out(cpu,port,size,value,unused):require(size==1 and port==0x201 and value==active['io_request'].value,'OUTwidth/value');device(active['guest'],active['io_request'])
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;sp=c['sp'];ef=c['flags'];segment_pattern=pattern if c['fill'] is None else bytes([c['fill']])*65536;start=(ds<<4)&0xfffff;first=min(65536,0x100000-start);data[start:start+first]=segment_pattern[:first]
   if first<65536:data[:65536-first]=segment_pattern[first:]
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   if c['entry']==0:
    for offset,profile in [(0x6282,c['xp']),(0x628e,c['yp'])]:
     for i,v in enumerate(profile):put(ds,offset+2*i,v)
    put(ds,0x6cfc,c['enabled'],1);put(ds,0x6cfe,c['config'],1)
   if c['entry']==2:
    for i in range(16):put(ds,0x629e+i,(i*17+3)&255,1)
   put(ss,sp,0x1111);put(ss,sp+2,0x2222)
   if c['entry']==2:put(ss,sp+4,c['argument'])
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(ef>>9)&1,(ef>>10)&1),0x5678,ef&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,v)
   active.update(c=c,guest={'phase':'initial','polls':0,'reads':0,'events':[]},limit=c['limit'],instructions=0,writes=0,sites=set(),executing_return=False,prefix=False,**{'return':None});label=str((load,c));u.emu_start(cs*16+ENTRIES[c['entry']],0,count=100000);root=False;boundary=False
   if active['return']:
    ip=active['return']
    if u.reg_read(UC_X86_REG_SP)>0xfffc:boundary=True
    else:active['instructions']+=1;active['sites'].add(ip);active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;root=True
   require(root or boundary or active['prefix'],'Outcome '+label)
   model={'phase':'initial','polls':0,'reads':0,'events':[]};errors=[]
   def native_service(ctx,request,read_value):
    try:read_value.contents.value=device(model,request.contents);return 1
    except Exception as error:errors.append(str(error));return 0
   callback=Service(native_service);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],(ef>>6)&1,C.byref(incoming),c['limit'],callback,None,C.byref(r));observed=u.reg_read(UC_X86_REG_EFLAGS)
   require(not errors,'Native adapter '+label+str(errors));require(model==active['guest'],'Ordered full port request states '+label+str((model,active['guest']))[:1600]);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.reads,r.transfers,r.bus_writes)==(0 if root else 5 if boundary else 3,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),model['reads'],len(model['events']),active['writes']),'Result '+label+str((r.status,r.current_sp,r.next_segment,r.next_ip,r.reads,r.transfers,r.bus_writes,active['writes'])))
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label+str((values(r.returned.registers)[:8]+[r.returned.bp],[u.reg_read(reg) for reg in REGS]+[u.reg_read(UC_X86_REG_BP)])));require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(observed&1,(observed>>9)&1,(observed>>10)&1),'CFIFDF '+label);require((r.flags_valid,r.zero_flag)==(int(root),(observed>>6)&1 if root else 0),'RootZF '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['root_RETF' if root else 'pre_RETF_boundary' if boundary else 'before_IN_budget']+=1;coverage['CPU_bus_writes']+=r.bus_writes;coverage['port_reads']+=r.reads;coverage['port_transfers']+=r.transfers;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root_coordinates']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['4000_counter_timeout']+=int(model['polls']>=4000);coverage['translation_savedBP_overlaps_lookup']+=int(c['entry']==2 and ds==ss and 0x629e<=(sp-2)&65535<=0x62ad);coverage['initializer_incoming_ZF1']+=int(c['entry']==1 and ef&0x40!=0)
   if vectors%2048==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['before_IN_budget']>0 and coverage['pre_RETF_boundary']>0 and coverage['changed_root_coordinates']>0 and coverage['translation_savedBP_overlaps_lookup']>0,'Coverage '+str(sorted(fence-sites)))
 deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json','analysis/reviews/far-return-stack-probe-v1.json','tools/validation/probe_far_return_stack.py'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000156','FN-EGA-000412','FN-EGA-000413'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_gameport_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':150,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Three additional actualSS gameport6686/680A/6828/plainRETF-caller-clean/currentDS-independentSS/whole1MiB20bitRAM/GPR-BP-CFIFDF-normalZF/ordered40byteportrequests/CPUwrites. Syntheticbyte201adapter preservesRAM-GPR-FLAGS; onlyINreturnsAL. Native3beforeINbudget/5beforefarRETSP>FFFC retainqualifiedbackendprofile; nativefailedservice4 separatediagnostics. MOV-onlyinitializerpreservesexplicitincomingZF; translatoractualsavedBP-before-liveDSlookup. Same3originalentriescountedonce/oldsource-DLL-receiptsfrozen. No actualporthardware-timebase-IRQ/caller-allwriters-capacity-lifetime/full420A-403B-core/resourceformats/session/renderer/audio/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
