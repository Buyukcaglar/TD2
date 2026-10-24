"""Compare complete019E:0004 caller plus actual780E transformation and SS ABI."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_ring_selection;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());selected=[f for f in g['functions'] if f['entry'] in ['019E:0004','06C9:780E']];fence={(int(f['entry'][:4],16),ip) for f in selected for ip in f['instructions']};child_ret=next(int(e['site'][5:],16) for f in selected if f['entry']=='06C9:780E' for e in f['exits']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();categories=set()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x19e;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence,'Ring selection escaped '+str(pair))
   if pair in [(0x19e,0x9a),(0x6c9,child_ret)]:active['return_kind']='root' if pair[0]==0x19e else 'child';u.emu_stop();return
   if pair==(0x19e,0xa):
    if active['limit']==0:active['prefix']=True;u.emu_stop();return
    active['calls']=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if pair==(0x19e,0x12):active['category']=u.reg_read(UC_X86_REG_AX)
   active['instructions']+=1;active['sites'].add(pair)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No BIOS/IRQ or platform service in ring selection')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product([0,1,0x100,0xffff],range(256),[0,1],[2,0x603],[0xe000,0x66e6,0x66ea,0x67f2],[0,1]));cases +=[(cursor,value,same,flags,30,limit) for cursor,value,same,flags,limit in itertools.product([0,0xffff],range(0,256,8),[0,1],[2,0x203,0x402,0x603],[0,1])]
  for cursor,value,same,flags,sp,limit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;struct.pack_into('<H',data,ds*16+0x66e6,cursor)
   for k in range(256):data[ds*16+0x66e8+k]=(k*17+value)&255
   data[ds*16+0x66e8+((cursor-1)&255)]=value;frame=struct.pack('<2H',0x1111,0x2222);data[ss*16+sp:ss*16+sp+4]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,4),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,calls=0,writes=0,instructions=0,category=None,sites=set(),executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+4,0,count=1000);raw=root=False;label=f'{load:x}/{cursor:x}/{value}/{same}/{flags:x}/{sp:x}/{limit}'
   while active['return_kind']:
    kind=active['return_kind'];segment=u.reg_read(UC_X86_REG_CS)-load;ip=u.reg_read(UC_X86_REG_IP);sites.add((segment,ip));active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start((load+segment)*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0xf,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+0xf,0,count=1000)
   require(active['prefix'] or root or raw,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.calls==active['calls'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS/ring '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['before_CALL_prefix' if active['prefix'] else 'raw_child_far_return' if raw else 'root_far_return']+=1;coverage['actual_ring_CALLs']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['raw_root_returns']+=int(root and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['minimumSP30_cases']+=int(sp==30);coverage['DS_equals_SS_cases']+=same
   if active['category'] is not None:categories.add(active['category'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'categories':sorted(categories),'missing':[f'{s:04X}:{ip:04X}' for s,ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and categories==set(range(8)),'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000019'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_ring_selection.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'categories':sorted(categories),'limits':'Actual019E0004+actual780E original instructions compared with actual frozenbyte_ring C transformation plus source-proven SS ABI adapter: real parent/child frames, leafPUSHSI before snapshot, cursorcommit beforebytecommit/POPSI/actualfarreturn and complete mask7/wordCWD/raw8word chain. SerializedflatRAM, fullbus/SS/ring/GPR/BP/CFIFDF/control, noABImock/SSscratch exclusion. Native beforeCALL/rawchild/rawroot targets separate, no targetfollowed. This closes one caller body only; shared ring writer/reset/seed/reentry/IRQ exclusion/consumption acrossfullstate/callerlifetime/core/sourceCtype/otherFLAGS/runtime/gameplay/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
