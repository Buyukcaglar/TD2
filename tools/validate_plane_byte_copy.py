"""CompareC784/fullSS/local-rereads/in-placeSAR3/CLD/byteCOPY/DEC-JGwide prefixes."""
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
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['work','ports','copies','rows','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_plane_byte_copy;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==52,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:C784')['instructions']);require(len(fence)==74,'Fence');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[0xa0000:0xb0000]=bytes(range(256))*256;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def mutations(q,profile):
   if profile==1 and q.site==0xc804 and q.incoming.registers.bx==0:return [((((cs<<4)+0xaf3c)&0xfffff),0,2)]
   if profile==2 and q.kind==7:return [((((q.stack_segment<<4)+((q.incoming.bp-0x10)&65535))&0xfffff),0,2)]
   if profile==3 and q.kind==7:return [((((q.stack_segment<<4)+((q.incoming.bp-2)&65535))&0xfffff),1,2)]
   if profile==4 and q.kind==7:return [((((q.stack_segment<<4)+((q.incoming.bp+0x10)&65535))&0xfffff),0,2)]
   return []
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0xc836:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']=True;u.emu_stop();return
    active['return']=True;u.emu_stop();return
   kind=1 if ip in [0xc800,0xc804] else 7 if ip==0xc81c and u.reg_read(UC_X86_REG_CX)!=0 else 0;row=ip==0xc819
   if kind or row:
    if active['work']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['work']+=1
    if row:active['rows']+=1
    else:
     r=state(u);rr=r.registers;source=((rr.ds<<4)+rr.si)&0xfffff;dest=((rr.es<<4)+rr.di)&0xfffff;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.dx,(rr.ax&255) if kind==1 else u.mem_read(source,1)[0],(C.c_uint16*5)(*([0]*5 if kind==1 else [rr.ds,rr.si,rr.es,rr.di,0])),0 if kind==1 else dest,r);active['events'].append(device_event(q));active['ports']+=int(kind==1);active['copies']+=int(kind==7)
     for at,v,size in mutations(q,active['profile']):u.mem_write(at,struct.pack('<H',v));active['mutations']+=1
     # SelectedrawRAMCOPYownsread-before-write; originalMOVSBexecutesits
     # idempotentbytewriteafterward, retainingactualGPR/FLAGS/CPUwritecount.
     if kind==7:u.mem_write(dest,bytes([q.value]))
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['CPU_writes']+=1
  def output(cpu,port,size,value,unused):q=active['events'][-1];require(q[0]==1 and size==1 and (port,value)==(q[6],q[7]),'ActualbyteOUTidentity')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INSN,output,None,1,0,UC_X86_INS_OUT)
  # profile,planetype,sourceX,destX,width,height,SS,SP,FLAGS,workbudget
  cases=[(0,planes,x,x,width,height,ss,0xe000,flags,256) for planes,x,width,height,ss,flags in itertools.product([0,1,2],[0,7,8,0x8000,0xffff],[0,8,16,0xffff],[0,1,2,0x8000,0xffff],[0x9000,ds],[2,0x603])]
  cases +=[(0,0,0,0,8,height,0xffff,sp,flags,budget) for height,sp,flags,budget in itertools.product([0,2,0x7fff],[0,1,8,17,0xfffd,0xfffe,0xffff],[2,0x603],[0,1,2,3,4,8,12,24,64])]
  cases +=[(profile,0,0,0,16,3,0x9000,0xe000,flags,128) for profile,flags in itertools.product(range(1,5),[2,0x603])]
  cases +=[(profile,3,0,0,8,1,0x9000,0xe000,flags,64) for profile,flags in itertools.product([5,6,7],[2,0x603])]
  for profile,planetype,srcx,dstx,width,height,ss,sp,flags,limit in cases:
   data=bytearray(base)
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   srcrow,dstrow=0x200,0x300;srcy,dsty=0,0
   plane=[[0x3000,0x4000,0x5000,0x6000],[0xa000,0,0,0],[0,0,0,0],[ss,0,0,0]][planetype]
   if profile in [5,6,7]:dstrow=sp if profile==5 else (sp-2)&65535 if profile==6 else (sp-4)&65535
   if planetype==1:dstrow=0x201
   put(cs,0xaf5e,0x4000);put(cs,0xaf44,0x6000);put(cs,0xaf4e,0x50);put(cs,0x4000,srcrow);put(cs,0x6000,dstrow)
   for i,segment in enumerate(plane):put(cs,0xaf3c+2*i,segment)
   put(ss,sp,0x1111);put(ss,sp+2,0x2222)
   for i,value in enumerate([srcx,srcy,dstx,dsty,width,height]):put(ss,sp+4+2*i,value)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xc784),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(ss=ss,sp=sp,profile=profile,limit=limit,work=0,ports=0,copies=0,rows=0,events=[],CPU_writes=0,mutations=0,instructions=0,sites=set(),executing_return=False,prefix=False,qualification=False,**{'return':False});label=f'{load:x}/{profile}/{planetype}/{srcx:x}/{dstx:x}/{width:x}/{height:x}/{ss:x}/{sp:x}/{flags:x}/{limit}';u.emu_start(cs*16+0xc784,0,count=50000);root=False
   if active['return']:active['sites'].add(0xc836);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0xc836,0,count=1);active['executing_return']=False;root=True
   require(root or active['prefix'] or active['qualification'],'Outcome '+label);native_events=[]
   @Service
   def device(context,memory,request,result):
    q=request.contents;native_events.append(device_event(q));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
    for at,v,size in mutations(q,profile):memory[at]=v&255;memory[(at+1)&0xfffff]=(v>>8)&255
    if q.kind==7:memory[q.address]=q.value
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),device,None,limit,C.byref(r));require((r.status,r.current_sp,r.work,r.ports,r.copies,r.rows,r.bus_writes)==(0 if root else 5 if active['qualification'] else 3,u.reg_read(UC_X86_REG_SP),active['work'],active['ports'],active['copies'],active['rows'],active['CPU_writes']),'Status/counters '+label);require(native_events==active['events'],'DeviceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'preRET_qualification' if active['qualification'] else 'prefix_work']+=1;coverage['byte_OUTs']+=r.ports;coverage['byte_COPY_transactions']+=r.copies;coverage['row_heads']+=r.rows;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['adapter_bus_mutations']+=active['mutations'];coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['normal_final_ADDSP_carry']+=int(root and r.returned.carry==1);coverage['height8000_cases']+=int(height==0x8000)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['raw_root_returns']>0 and coverage['byte_COPY_transactions']>0 and coverage['normal_final_ADDSP_carry']>0,'Coverage '+str(fence-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_fallback_mode.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0xc784 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_plane_byte_copy.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualC784/fullSS-sixargs/SSlocal-rereads/in-placeSAR3source-destX/SAR3width/CSsource-destrow-plane-strides/DSA000-CLD/fourplanes-zero-skip/byteOUT/atomicbyteCOPYrawRAMprofile/do-oncerows-wideDECJG/globalworkrowhead-port-copybudgets/wholebus/GPR-BP-CFIFDF/actualSSFNs-farwords/native5preRET. SourceoriginalMOVSBstill executesidempotentbytewrite/actualCPUwrites. No realEGAreadselector-latch-controller/renderer/clipping-coordinatebounds/allwriters-storage-lifetime-exclusion/historicalCPU-A20/core/resource/CGA/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
