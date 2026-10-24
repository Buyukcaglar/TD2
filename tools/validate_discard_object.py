"""Compare782C/actual7490 far descriptors, wrapped CS word, cache and live SS."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','scans','trims','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_discard_object;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:782C','06C9:7490'] for ip in f['instructions']};feasible=fence-{0x74b3};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in [0x74d3,0x7864]:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']='child' if ip==0x74d3 else 'root';u.emu_stop();return
    active['return']=ip;u.emu_stop();return
   if ip==0x74b3:active['fatal']=True;u.emu_stop();return
   if ip==0x7858:
    if active['calls']==active['call_limit']:active['prefix']='call';u.emu_stop();return
    active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip in [0x749c,0x74c3]:
    if active['scans']+active['trims']==active['scan_limit']:active['prefix']='scan' if ip==0x749c else 'trim';u.emu_stop();return
    active['scans' if ip==0x749c else 'trims']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written)
  # profile,target,free-predecessors,object word,SS kind,SP,FLAGS,CALL budget,scan budget
  cases=[(0,target,free,size,ssk,0xe000,flags,1,64) for target,free,size,ssk,flags in itertools.product(range(6),[0,1,3,4],[0,1,0x7ff2,0x7ff3,0xfff2,0xfff3,0xffff],[0,1,2],[2,0x603])]
  cases +=[(0,target,0,0xffff,0,sp,flags,call,scan) for target,sp,flags,call,scan in itertools.product([1,5],[0,1,13,14,15,0xfffd,0xfffe,0xffff],[2,0x603],[0,1],[0,1,2,4,16])]
  cases +=[(0,5,0,0xffff,0,sp,flags,1,64) for sp,flags in itertools.product([8,9,10,11],[2,0x603])]
  cases +=[(profile,5,0,0xffff,1,0xe000,flags,1,64) for profile,flags in itertools.product(range(1,7),[2,0x603])]
  for profile,target,free,objword,sskind,sp,flags,call_limit,scan_limit in cases:
   data=bytearray(base);ds=[principal,principal,0xffff][sskind];ss=[0x9000,ds,0xffff][sskind];object_segment=0x6000;descriptor_segment=0x5000;descriptor_offset=0x100;object_offset=0x200;row=0x7000+5*18
   if profile==1:sp=row+0x20;object_segment=(sp-2)&65535
   if profile==2:sp=row+0x10;object_segment=0x5678
   if profile==3:sp=row+0xe;object_segment=0x1111
   if profile==4:ss=cs;sp=0xb269
   if profile==5:ss=cs;sp=0xb26d
   if profile==6:descriptor_segment=ss;descriptor_offset=(sp-8)&65535
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   put(ds,0x6c66,0x7000);put(ds,0x6c68,row)
   for index in range(6):
    put(ds,0x7000+18*index+0xe,object_segment if index==target and target else 0x3000+index);put(ds,0x7000+18*index+0x10,0 if index>0 and 5-free<=index<5 else 1)
   put(object_segment,object_offset+2,objword);put(descriptor_segment,descriptor_offset,object_offset);put(descriptor_segment,descriptor_offset+2,object_segment);put(cs,0xb269,0x10)
   put(ss,sp,0x1111);put(ss,sp+2,0x2222);put(ss,sp+4,descriptor_offset);put(ss,sp+6,descriptor_segment)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x782c),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(calls=0,scans=0,trims=0,writes=0,call_limit=call_limit,scan_limit=scan_limit,instructions=0,sites=set(),executing_return=False,fatal=False,prefix=False,qualification=False,**{'return':False});label=f'{load:x}/{profile}/{target}/{free}/{objword:x}/{ss:x}/{sp:x}/{flags:x}/{call_limit}/{scan_limit}';u.emu_start(cs*16+0x782c,0,count=10000);root=raw=False
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip==0x7864:root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x785d,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=10000)
   require(root or raw or active['fatal'] or active['prefix'] or active['qualification'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),call_limit,scan_limit,C.byref(r));status=0 if root else 1 if raw else 6 if active['fatal'] else 5 if active['qualification'] else 3
   require((r.status,r.current_sp,r.calls,r.scans,r.trims,r.bus_writes)==(status,u.reg_read(UC_X86_REG_SP),active['calls'],active['scans'],active['trims'],active['writes']),'Status/counters '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'raw_child_return' if raw else 'original_fatal_prefix' if active['fatal'] else 'unqualified_'+active['qualification']+'_farframe_prefix' if active['qualification'] else 'prefix_'+active['prefix']]+=1;coverage['actual_7490_farCALLs']+=r.calls;coverage['search_iterations']+=r.scans;coverage['trim_iterations']+=r.trims;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ds==ss);coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['alias_profile_'+str(profile)]+=int(profile>0)
   if sp in [8,9,10,11] and root:require(r.returned.carry==1,'FinalADDSP4carry '+label);coverage['root_ADDSP4_carry_cases']+=1
   if profile==1:require(raw and r.next_ip==0,'FreedstatusaliaseschildfarIP '+label)
   if profile==2:require(root and r.next_ip==0,'FreedstatusaliasesrootfarIP '+label)
   if profile==3:require(root and r.next_segment==0,'FreedstatusaliasesrootfarCS '+label)
   if profile==4:require(root and r.next_ip==0x10f9,'CSB269aliasesrootfarIP '+label)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(feasible-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==feasible and coverage['raw_child_return']>0 and coverage['original_fatal_prefix']>0 and coverage['trim_iterations']>0,'Coverage '+str(feasible-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x782c for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_discard_object.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'instruction_dispositions':[{'site':'06C9:74B3','disposition':'OriginalfatalpreCALLprefix/external16A7:0002notexecuted/noexecutionclaim.'}],'fixture_coverage':dict(coverage),'limits':'Actual782C/7490fullCPU-SS/fardescriptor/CSB269wrappedwordupdate/rowsearch-ignorestatus/toptrim/all16bitSPbody/actualsaves-farframes/full20bitbus/CFIFDF/CALL-scanprefix/native1rawchildafterRETneverfollowed/native5preRETqualification/native6originalfatalpreCALL. No arena/size/descriptorbounds-storage-lifetime-writers/exclusion/CPU-A20/fatalcleanup/core/resource/CGA/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
