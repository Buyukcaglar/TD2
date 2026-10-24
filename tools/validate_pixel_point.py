"""CompareBA3C/fullSS/wordOUT-byteReadWrite-ORtransactions/rawplane-row-mask aliases."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,require,values
from validate_fallback_mode import device_event
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['events','reads','writes','ports','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_pixel_point;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==52,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:BA3C')['instructions']);require(len(fence)==61,'Fence');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def mutations(q,profile):
   if profile==1 and q.site==0xba70:return [((((cs<<4)+0xaf3c)&0xfffff),0,2)]
   if profile==5 and q.site in [0xba82,0xbab0,0xbab6]:return [((((active['ss']<<4)+((active['sp']-2)&65535))&0xfffff),0x1357,2)]
   return []
  def source_mutations(q):
   for at,v,size in mutations(q,active['profile']):u.mem_write(at,bytes([v&255]) if size==1 else struct.pack('<H',v));active['mutations']+=1
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in [0xba90,0xbac6]:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']=True;u.emu_stop();return
    active['return']=ip;u.emu_stop();return
   kind=5 if ip in [0xba70,0xba7a,0xba7e,0xba88,0xba8c] else 2 if ip in [0xba7f,0xbaab] else 3 if ip in [0xba82,0xbab0] else 6 if ip==0xbab6 else 0
   if kind:
    if len(active['events'])==active['limit']:active['prefix']=True;u.emu_stop();return
    r=state(u);physical=0 if kind==5 else ((r.registers.es<<4)+r.registers.di)&0xfffff;v=r.registers.ax if kind==5 else 0 if kind==2 else (r.registers.cx&255) if ip==0xba82 else (r.registers.ax&255) if kind==3 else r.registers.dx&255;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),r.registers.dx,v,(C.c_uint16*5)(0,0,0,0,0),physical,r);active['events'].append(device_event(q));active['reads']+=int(kind==2);active['stores']+=int(kind in [3,6]);active['ports']+=int(kind==5);source_mutations(q)
    # The selected RAM adapter owns byte effects. Executed MOV/OR repeats the
    # same idempotent store; original CPU writes and FLAGS are still observed.
    if kind==3:u.mem_write(physical,bytes([v&255]))
    if kind==6:u.mem_write(physical,bytes([u.mem_read(physical,1)[0]|v]))
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['CPU_writes']+=1
  def output(cpu,port,size,value,unused):q=active['events'][-1];require(q[0]==5 and size==2 and (port,value)==(q[6],q[7]),'ActualwordOUTidentity')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INSN,output,None,1,0,UC_X86_INS_OUT)
  # hardware,profile,x,y,color,rowoffset,SS,SP,FLAGS,eventbudget
  cases=[(hw,0,x,y,color,row,ss,0xe000,flags,8) for hw,x,y,color,row,ss,flags in itertools.product([0,1],[0,7,8,0x7fff,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],[0,1,0xf,0x10,0xff],[0,0xfff8],[0x9000,ds],[2,0x603])]
  cases +=[(hw,0,0,0,5,0x1234,0xffff,sp,flags,limit) for hw,sp,flags,limit in itertools.product([0,1],[0,1,0xfffc,0xfffd,0xfffe,0xffff],[2,0x603],range(9))]
  cases +=[(hw,profile,0,0,1,0,0x9000,sp,flags,8) for hw,profile,sp,flags in itertools.product([0,1],[1,2,3,4,5,6],[0xe000,0xffff],[2,0x603])]
  for hw,profile,x,y,color,row,ss,sp,flags,limit in cases:
   data=bytearray(base)
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   plane=[0xa000]*4 if hw else [0x3000,0x4000,0x5000,0x6000]
   if not hw and profile in [2,3,4]:plane=[ss,0,0,0];row=sp if profile==2 else (sp-2)&65535 if profile==3 else (sp-6)&65535
   if not hw and profile==6:plane=[0,0,0,0]
   put(cs,0xaf44,0x4000);put(cs,((y<<1)+0x4000)&65535,row)
   for i,segment in enumerate(plane):put(cs,0xaf3c+2*i,segment)
   for i,mask in enumerate([0x80,0x40,0x20,0x10,8,4,2,1]):data[((ds<<4)+0x68ce+i)&0xfffff]=mask
   pixel=(row+(x>>3))&65535
   for segment in set(plane):
    if segment:data[((segment<<4)+pixel)&0xfffff]=0x55
   # Slot/stack initialization follows pixel filler so aliases are genuine.
   put(ss,sp,0x1111);put(ss,sp+2,0x2222);put(ss,sp+4,x);put(ss,sp+6,y);put(ss,sp+8,0xab00|color)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xba3c),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(ss=ss,sp=sp,profile=profile,limit=limit,events=[],reads=0,stores=0,ports=0,CPU_writes=0,mutations=0,instructions=0,sites=set(),executing_return=False,prefix=False,qualification=False,**{'return':False});label=f'{load:x}/{hw}/{profile}/{x:x}/{y:x}/{color:x}/{row:x}/{ss:x}/{sp:x}/{flags:x}/{limit}';u.emu_start(cs*16+0xba3c,0,count=200);root=False
   if active['return']:ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;root=True
   require(root or active['prefix'] or active['qualification'],'Outcome '+label);native_events=[]
   @Service
   def device(context,memory,request,result):
    q=request.contents;native_events.append(device_event(q));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=(memory[q.address]|0xff00) if q.kind==2 else 0xffff
    for at,v,size in mutations(q,profile):
     memory[at]=v&255
     if size==2:memory[(at+1)&0xfffff]=(v>>8)&255
    if q.kind==3:memory[q.address]=q.value&255
    if q.kind==6:memory[q.address]|=q.value&255
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),device,None,limit,C.byref(r));require((r.status,r.current_sp,r.events,r.reads,r.writes,r.ports,r.bus_writes)==(0 if root else 5 if active['qualification'] else 3,u.reg_read(UC_X86_REG_SP),len(active['events']),active['reads'],active['stores'],active['ports'],active['CPU_writes']),'Status/counters '+label);require(native_events==active['events'],'DeviceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'preRET_qualification' if active['qualification'] else 'prefix_event']+=1;coverage['word_OUTs']+=r.ports;coverage['byte_reads']+=r.reads;coverage['byte_stores']+=r.writes;coverage['byte_OR_transactions']+=sum(q[0]==6 for q in native_events);coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['adapter_bus_mutations']+=active['mutations'];coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['hardware_branch_cases' if hw else 'software_branch_cases']+=1
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['raw_root_returns']>0 and coverage['word_OUTs']>0 and coverage['byte_OR_transactions']>0,'Coverage '+str(fence-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_fallback_mode.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0xba3c for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_pixel_point.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualBA3C/fullSS/SSx-y-colorlowbyte/unsignedxSHR3/wrappedCSrowlookup/currentDS8maskbytes/CSfirstA000hardware5wordOUTs-byteReadWrite orfourplanezero-skip/readANDwrite/atomicbyteORprofile/currentDS-CS-SSaliases/wholebus/GPR-BP-CFIFDF/devicebudgets/native5preRET. RAWRAMadapterownsbyteeffects; originalMOV/ORexecutesidempotentstore/actualwordOUTwidth2. No realEGAports-latches-controller/renderer/coordinateclippingbounds/allwriters-storage-lifetime-exclusion/historicalCPU-A20/core/resource/CGA/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
