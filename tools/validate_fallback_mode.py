"""CompareEGA5F64 BIOS10/27byteOUTs/12rawtablebytes/CLD-REP16384wordeffects/fullSS."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
class BIOSRequest(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
BIOSService=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(BIOSRequest),C.POINTER(StateRegisters))
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['events','services','ports','words','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def device_event(q):return [q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,q.port,q.value,list(q.arguments),q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
def bios_event(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_fallback_mode;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BIOSService,C.c_void_p,Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==52 and C.sizeof(BIOSRequest)==34,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:5F64')['instructions']);require(len(fence)==40,'Fence');outs={0x5f88,0x5f8e,0x5f99,0x5f9f,0x5fb8};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def response(r,profile):
   ret=StateRegisters.from_buffer_copy(bytes(r));mode=profile%7
   if mode:
    ret.registers.ax=0xf123;ret.registers.bx=0x8001;ret.registers.cx=0xcafe;ret.registers.dx=0xbada;ret.registers.si=0x1357+mode;ret.registers.di=0x2468+mode;ret.registers.ds=[ds,ds+0x100,0,0xffff,ds+0x200,ds,ds+0x100][mode];ret.registers.es=0x9876;ret.bp=0xd000+mode;ret.carry=mode%2;ret.registers.interrupts_enabled=1-r.registers.interrupts_enabled;ret.registers.direction=1-r.registers.direction
   return ret
  def bios_mutations(ss,sp,profile):
   kind=(profile//7)%4
   if kind==0:return []
   if kind==1:return [((((ss<<4)+((sp-2)&65535))&0xfffff),0x1357,2)]
   if kind==2:return [((((ss<<4)+sp)&0xfffff),0x2468,2),((((ss<<4)+((sp+2)&65535))&0xfffff),0x369c,2)]
   return [(0x410,0xbeef,2)]
  def device_mutations(q,sp,profile):
   if q.site==0x5f99 and profile%3==1:return [((((q.incoming.registers.ds<<4)+((q.incoming.registers.bx+0x5e70)&65535))&0xfffff),((profile+q.incoming.registers.bx)*17)^0x55,1)]
   if q.site==0x5fb8 and profile%3==2:return [((((q.stack_segment<<4)+((sp-2)&65535))&0xfffff),0xabcd,2)]
   return []
  def source_mutations(items):
   for at,v,size in items:u.mem_write(at,bytes([v&255]) if size==1 else struct.pack('<H',v&65535));active['adapter_mutations']+=1
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x5fba:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['ret_boundary']=True;u.emu_stop();return
    active['return']=True;u.emu_stop();return
   effect=ip==0x5f81 or ip in outs or (ip==0x5fb1 and u.reg_read(UC_X86_REG_CX)!=0)
   if effect and len(active['events'])==active['limit']:active['prefix']=True;u.emu_stop();return
   if effect and ip!=0x5f81:
    r=state(u);kind=1 if ip in outs else 4;physical=(((r.registers.es<<4)+r.registers.di)&0xfffff) if kind==4 else 0;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),r.registers.dx,(r.registers.ax&255) if kind==1 else r.registers.ax,(C.c_uint16*5)(0,0,0,0,0),physical,r);active['events'].append(['device',device_event(q)]);active['words']+=int(kind==4);active['ports']+=int(kind==1);source_mutations(device_mutations(q,active['sp'],active['profile']))
   active['instructions']+=1;active['sites'].add(ip)
  def output(cpu,port,size,value,unused):
   last=active['events'][-1];require(last[0]=='device' and last[1][0]==1 and size==1 and (port,value)==(last[1][6],last[1][7]),'ActualbyteOUTidentity')
  def interrupt(cpu,number,unused):
   site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x10 and site==0x5f81,'BIOS10only');r=state(u);require(r.registers.ax==4,'ModeAX0004');q=BIOSRequest(number,site,cs,active['ss'],u.reg_read(UC_X86_REG_SP),r);active['events'].append(['bios',bios_event(q)]);active['services']+=1;returned=response(r,active['profile'])
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10));source_mutations(bios_mutations(active['ss'],active['sp'],active['profile']))
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INSN,output,None,1,0,UC_X86_INS_OUT);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=[(p,ss,f,0xe000,16412) for p,ss,f in itertools.product(range(7),[0x9000,0xb800],[2,0x603])];cases +=[(p,0xb800,f,sp,16412) for p,f,sp in itertools.product([0,1],[2,0x603],[0,0x8000])];cases +=[(p,0xffff,f,0xffff,b) for p,f,b in itertools.product([0,8,13],[2,0x203,0x402,0x603],[0,1,2,3,4,5,26,27,28,29,16411,16412])];cases +=[(p,ds,f,sp,16412) for p,f,sp in itertools.product([0,1],[2,0x603],[0x5e70,0x5e6f])];cases +=[(0,0x40,f,0x10,16412) for f in [2,0x603]];cases +=[(p,0x9000,2,0xe000,16412) for p in [8,15,21,27]]
  for profile,ss,flags,sp,limit in cases:
   data=bytearray(base)
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   for sg in [ds,ds+0x100,ds+0x200,0,0xffff]:
    for i in range(12):data[((sg<<4)+0x5e70+i)&0xfffff]=(profile*17+i*3)&255
   put(0x40,0x10,[0,0xffff,0x30,0x20,0x1234,0xabcd,0x8000,1][profile%8]);put(ss,sp,0x1111);put(ss,sp+2,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x5f64),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(ss=ss,sp=sp,profile=profile,limit=limit,events=[],services=0,ports=0,words=0,adapter_mutations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,ret_boundary=False,**{'return':False});label=f'{load:x}/{profile}/{ss:x}/{flags:x}/{sp:x}/{limit}';u.emu_start(cs*16+0x5f64,0,count=40000);root=active['return']
   if root:active['sites'].add(0x5fba);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0x5fba,0,count=1);active['executing_return']=False
   require(root or active['prefix'] or active['ret_boundary'],'Outcome '+label);native_events=[]
   def native_mutations(memory,items):
    for at,v,size in items:
     memory[at]=v&255
     if size==2:memory[(at+1)&0xfffff]=(v>>8)&255
   @BIOSService
   def bios(context,memory,request,result):q=request.contents;native_events.append(['bios',bios_event(q)]);result[0]=response(q.incoming,profile);native_mutations(memory,bios_mutations(ss,sp,profile));return 1
   @Service
   def device(context,memory,request,result):
    q=request.contents;native_events.append(['device',device_event(q)]);result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=0xffff;native_mutations(memory,device_mutations(q,sp,profile))
    if q.kind==4:memory[q.address]=q.value&255;memory[(q.address+1)&0xfffff]=(q.value>>8)&255
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),bios,None,device,None,limit,C.byref(r));require((r.status,r.current_sp,r.events,r.services,r.ports,r.words,r.bus_writes)==(0 if root else 5 if active['ret_boundary'] else 3,u.reg_read(UC_X86_REG_SP),len(active['events']),active['services'],active['ports'],active['words'],active['writes']),'Status/count '+label);require(native_events==active['events'],'EffectABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'unqualified_farframe_prefix' if active['ret_boundary'] else 'event_budget_prefix']+=1;coverage['BIOS10_mode0004']+=r.services;coverage['byte_OUTs']+=r.ports;coverage['device_word_writes']+=r.words;coverage['bus_write_events']+=r.bus_writes;coverage['adapter_bus_mutations']+=active['adapter_mutations'];coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['SS_B800_cases']+=int(ss==0xb800);coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['SS_FFFF_cases']+=int(ss==0xffff);coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['BIOS_changedDS_cases']+=int(response(incoming,profile).registers.ds!=ds);coverage['CLD_completed_cases']+=int(0x5fa4 in active['sites'])
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['raw_root_returns']>0 and coverage['unqualified_farframe_prefix']>0,'Coverage '+str(fence-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x5f64 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_fallback_mode.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualEGAexe06C9:5F64 far/noargs/DS5E6Eflag/BDAphysical0410word/BIOS10AX0004-fullreturnedGPR-BP-DS-ES-CFIFDF/syntheticnoINTframes/27byteOUTs/currentDS12tablebytes/CLD-REP16384devicewords-B800/actualSSsavedDI-farframe. Typeddevicekind1byteOUT-kind4wordwrite preservesCPUstate/responseignored/rawRAMadapterlittleendianwordeffect. AllSPbodywork retained/native5SP>FFFCpreRETqualification/nohistoricalfaultdeliveryclaim; boundedchangedrootwordsafterRETneverfollowed. Wholebus/GPR-BP-CFIFDF/control/BIOS-port-device-eventcounts. No CGAeditionrecovery, actualBIOS/device-planar-register-hardware/renderer/CPU-A20/callerDF-IF-stackdomain/writers/storage/exclusion/core/resource/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
