"""Compare0083-38D4/actual782C-7490/liveSS/deferredargumentcleanup/sharedbudgets."""
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
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_discard_wrappers;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:0083','06C9:38D4','06C9:782C','06C9:7490'] for ip in f['instructions']};feasible=fence-{0x74b3};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in [0x74d3,0x7864,0x93,0x38f1]:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']=f'{ip:04X}';u.emu_stop();return
    active['return']=ip;u.emu_stop();return
   if ip==0x74b3:active['fatal']=True;u.emu_stop();return
   if ip in [0x8b,0x38dc,0x38e9,0x7858]:
    if active['calls']==active['call_limit']:active['prefix']='call';u.emu_stop();return
    active['calls']+=1;active['frames'].append((cs,ip+5,u.reg_read(UC_X86_REG_SP)))
   if ip in [0x749c,0x74c3]:
    if active['scans']+active['trims']==active['scan_limit']:active['prefix']='scan' if ip==0x749c else 'trim';u.emu_stop();return
    active['scans' if ip==0x749c else 'trims']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written)
  # entry,profile,first-match-row,free-predecessors,objectword,SSkind,SP,FLAGS,CALLbudget,scanbudget
  cases=[(entry,0,target,free,size,ssk,0xe000,flags,4,64) for entry,target,free,size,ssk,flags in itertools.product([0,1],[0,3,5],[0,1,3],[0,0x7ff3,0xfff3,0xffff],[0,1,2],[2,0x603])]
  cases +=[(entry,0,5,0,0xffff,0,sp,flags,call,scan) for entry,sp,flags,call,scan in itertools.product([0,1],[0,1,3,4,5,6,7,8,9,10,11,12,21,22,23,24,25,26,27,28,0xfffd,0xfffe,0xffff],[2,0x603],[0,1,2,3,4],[0,1,4,64])]
  cases +=[(entry,profile,5,0,0xffff,1,0xe000,flags,4,64) for entry,profile,flags in itertools.product([0,1],range(1,7),[2,0x603])]
  for entry,profile,target,free,objword,sskind,sp,flags,call_limit,scan_limit in cases:
   data=bytearray(base);ds=[principal,principal,0xffff][sskind];ss=[0x9000,ds,0xffff][sskind];object_segment=0x6000;descriptor_segment=0x5000;descriptor_offset=0x100;object_offset=0x200;row=0x7000+5*18
   if profile==1:sp=row+0x28;object_segment=(sp-10)&65535
   if profile==2:sp=row+0x18;object_segment=0x5678
   if profile==3:sp=row+0x10;object_segment=descriptor_segment
   if profile==4:sp=row+0xe;object_segment=0x1111
   if profile==5:ss=cs;sp=0xb269
   if profile==6:ss=cs;sp=0xb275
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   put(ds,0x6c66,0x7000);put(ds,0x6c68,row)
   for index in range(6):
    put(ds,0x7000+18*index+0xe,object_segment if index==target and target else 0x6001 if index==1 else 0x3000+index);put(ds,0x7000+18*index+0x10,0 if index>0 and 5-free<=index<5 else 1)
   put(object_segment,object_offset+2,objword);put(descriptor_segment,descriptor_offset,object_offset);put(descriptor_segment,descriptor_offset+2,object_segment)
   put(0x6001,0x202,0);put(0x5000,0x104,0x200);put(0x5000,0x106,0x6001)
   for off in [0x9b2,0x2f60]:put(ds,off,0x100);put(ds,off+2,0x5000)
   put(ds,0x2f68,0x104);put(ds,0x2f6a,0x5000);put(cs,0xb269,0x10)
   put(ss,sp,0x1111);put(ss,sp+2,0x2222)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x83 if entry==0 else 0x38d4),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(frames=[],calls=0,scans=0,trims=0,writes=0,call_limit=call_limit,scan_limit=scan_limit,instructions=0,sites=set(),executing_return=False,fatal=False,prefix=False,qualification=False,**{'return':False});label=f'{load:x}/{entry}/{profile}/{target}/{free}/{objword:x}/{ss:x}/{sp:x}/{flags:x}/{call_limit}/{scan_limit}';u.emu_start(cs*16+(0x83 if entry==0 else 0x38d4),0,count=10000);root=raw=False
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip in [0x93,0x38f1]:root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=active['frames'].pop():raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=10000)
   require(root or raw or active['fatal'] or active['prefix'] or active['qualification'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),call_limit,scan_limit,C.byref(r));status=0 if root else 1 if raw else 6 if active['fatal'] else 5 if active['qualification'] else 3
   require((r.status,r.current_sp,r.calls,r.scans,r.trims,r.bus_writes)==(status,u.reg_read(UC_X86_REG_SP),active['calls'],active['scans'],active['trims'],active['writes']),'Status/counters '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'raw_child_return' if raw else 'original_fatal_prefix' if active['fatal'] else 'unqualified_'+active['qualification']+'_farframe_prefix' if active['qualification'] else 'prefix_'+active['prefix']]+=1;coverage['actual_farCALLs']+=r.calls;coverage['search_iterations']+=r.scans;coverage['trim_iterations']+=r.trims;coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ds==ss);coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['entry_'+str(entry)+'_cases']+=1;coverage['alias_profile_'+str(profile)]+=int(profile>0);coverage['normal_final_ADD_carry_cases']+=int(root and r.returned.carry==1)
   if profile==1:require(raw and r.next_ip==0,'Freedstatusaliases7490farIP '+label)
   if profile==2:require(raw and r.next_ip==0,'Freedstatusaliases782CfarIP '+label)
   if profile==3:require(root and r.next_ip==0,'FreedstatusaliaseswrapperrootfarIP '+label)
   if profile==4:require(root and r.next_segment==0,'FreedstatusaliaseswrapperrootfarCS '+label)
   if profile==5:require(root and r.next_ip==(0x10f9 if entry==0 else 0x10df),'CSB269aliaseswrapperrootfarIP '+label)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(feasible-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==feasible and coverage['raw_child_return']>0 and coverage['original_fatal_prefix']>0 and coverage['trim_iterations']>0,'Coverage '+str(feasible-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset') in [0x83,0x38d4] for e in r['entries'])],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_discard_wrappers.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'instruction_dispositions':[{'site':'06C9:74B3','disposition':'OriginalfatalpreCALLprefix/external16A7:0002notexecuted/noexecutionclaim.'}],'fixture_coverage':dict(coverage),'limits':'Actual0083-38D4/782C-7490/fullSS/currentDSdescriptorpointers/entry1deferredADDSP8/actualchildfarframes/CSB269wordwrap/cacheignorestatus-toptrim/globalCALL-scanbudgets/full20bitbus/CFIFDF/native1rawchildRETneverfollowed/native5preRETqualification/native6fatalpreCALL. No arena/size/descriptorbounds-storage-lifetime-writers/exclusion/CPU-A20/fatalcleanup/core/resource/CGA/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
