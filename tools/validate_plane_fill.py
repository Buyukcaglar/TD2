"""Compare840A sixOUTs/REP8000bytes/incomingDF/SSaliases/rawRAMdeviceadapter."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['events','bytes','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def event(q):return [q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,q.port,q.value,list(q.arguments),q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_plane_fill;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==44,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:840A')['instructions']);require(len(fence)==30,'Fence');outs={0x8418,0x841c,0x8422,0x8426,0x8436,0x843a};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def mutations(ss,sp,profile,index):
   if profile>=1000:return []
   if index==3 and profile%4==1:return [((((ss<<4)+((sp+4)&65535))&0xfffff),0x80ff)]
   if index==4 and profile%4==2:return [((((ss<<4)+sp)&0xfffff),0x1357),((((ss<<4)+((sp-2)&65535))&0xfffff),0x2468)]
   if index==8004 and profile%4==3:return [((((ss<<4)+((sp-4)&65535))&0xfffff),0xabcd)]
   return []
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x843d:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['ret_boundary']=True;u.emu_stop();return
    active['return']=True;u.emu_stop();return
   if ip in outs or (ip==0x842f and u.reg_read(UC_X86_REG_CX)!=0):
    if len(active['events'])==active['limit']:active['prefix']=True;u.emu_stop();return
    r=state(u);kind=1 if ip in outs else 3;physical=(((r.registers.es<<4)+r.registers.di)&0xfffff) if kind==3 else 0;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),r.registers.dx,r.registers.ax&255,(C.c_uint16*5)(0,0,0,0,0),physical,r);index=len(active['events']);active['events'].append(event(q));active['bytes']+=int(kind==3)
    for at,v in mutations(active['ss'],active['sp'],active['profile'],index):u.mem_write(at,struct.pack('<H',v));active['adapter_mutations']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def output(cpu,port,size,value,unused):
   last=active['events'][-1];require(last[0]==1 and size==1 and (port,value)==(last[6],last[7]),'ActualbyteOUTidentity')
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT/faultdeliveryadmitted')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INSN,output,None,1,0,UC_X86_INS_OUT);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=[(p,ss,f,sp,8006) for p,ss,f,sp in itertools.product(range(8),[0x9000,0xa000],[2,0x603],[0,0xe000])];cases +=[(p,0xffff,f,sp,b) for p,f,sp,b in itertools.product([0,7],[2,0x203,0x402,0x603],[0,0xffff],[0,1,2,3,4,5,7999,8004,8005,8006])];cases +=[(1000+p,ds,f,0xe000,5) for p,f in itertools.product(range(256),[2,0x603])]
  for profile,ss,flags,sp,limit in cases:
   data=bytearray(base);value=[0,1,0xf,0xf0,0xff,0x1234,0x8000,0xffff][profile%8] if profile<1000 else 0x5a00+(profile-1000)
   def put(o,v):at=((ss<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   for i,v in enumerate([0x1111,0x2222,value]):put(sp+2*i,v)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x840a),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(ss=ss,sp=sp,profile=profile,limit=limit,events=[],bytes=0,adapter_mutations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,ret_boundary=False,**{'return':False});label=f'{load:x}/{profile}/{ss:x}/{flags:x}/{sp:x}/{limit}';u.emu_start(cs*16+0x840a,0,count=20000);root=active['return']
   if root:active['sites'].add(0x843d);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0x843d,0,count=1);active['executing_return']=False
   require(root or active['prefix'] or active['ret_boundary'],'Outcome '+label);native_events=[]
   @Service
   def callback(context,memory,request_pointer,response):
    q=request_pointer.contents;index=len(native_events);native_events.append(event(q));response.contents.returned=q.incoming;response.contents.returned.carry=2;response.contents.returned.registers.direction=2;response.contents.returned.bp=0xffff;response.contents.value=0xffff
    for at,v in mutations(ss,sp,profile,index):memory[at]=v&255;memory[(at+1)&0xfffff]=v>>8
    if q.kind==3:memory[q.address]=q.value
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,limit,C.byref(r));require((r.status,r.current_sp,r.events,r.bytes,r.bus_writes)==(0 if root else 5 if active['ret_boundary'] else 3,u.reg_read(UC_X86_REG_SP),len(active['events']),active['bytes'],active['writes']),'Status/count '+label);require(native_events==active['events'],'EffectABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'unqualified_farframe_prefix' if active['ret_boundary'] else 'event_budget_prefix']+=1;coverage['byte_OUTs']+=len(active['events'])-r.bytes;coverage['device_byte_writes']+=r.bytes;coverage['bus_write_events']+=r.bus_writes;coverage['adapter_bus_mutations']+=active['adapter_mutations'];coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['SS_A000_cases']+=int(ss==0xa000);coverage['SS_FFFF_cases']+=int(ss==0xffff);coverage['all16bitSP_wrap_cases']+=int(sp in [0,0xffff]);coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['all_byte_input_cases']+=int(profile>=1000)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['raw_root_returns']>0,'Coverage '+str(fence-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json','analysis/reviews/far-return-stack-probe-v1.json','tools/validation/probe_far_return_stack.py'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x840a for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_plane_fill.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual06C9:840A far/oneSSwordfill/6actualbyteOUTs/REP8000STOSB/incomingDF/fullSS/all16bitSPthroughpreRETqualification(SP>FFFC native5/noRET/faultclaim)/typedport-deviceevents preserveGPR-FLAGS (responseGPRignored)/rawRAMadapterownsdevicewrite/orderedSSargumentread-saves-farreturnafteradaptermutations-fill. Wholebus/GPR-BP-CFIFDF/control/eventcounts. Syntheticserialized20bitRAM/A000literaladdresses do notadmitEGAplanar-register-latchhardwareeffects/renderer. Nativeeventbudgets/failureprefixesnotoriginalerrors; rawrootfarwordsafterRETneverfollowed. HistoricalCPU-A20/actualcallers/writers/storage/domain/IRQ/core/resource/device/session/gameplay/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
