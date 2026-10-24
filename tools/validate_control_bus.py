"""Comparefiveactualcontrolentries/fullSS/nested460Eframe/CFIFDF andrawreturns."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/freshpaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_control_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;entries=[0x4588,0x44d8,0x45bf,0x4612,0x45fc];g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in entries] for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={ip for ip in fence if next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic=='ret'};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Controlbusescaped '+hex(address))
   if ip in rets:active['return_kind']='child' if ip==0x4638 and active['in_child'] else 'root';u.emu_stop();return
   if ip==0x460e:
    if active['limit']==0:active['prefix']=True;u.emu_stop();return
    active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP);active['in_child']=True
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('NoINT inselectedcontrolbodies')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(64),range(5),[0,1],[2,0x603],[18,0xe000,0x332c,0x332e,0x2f58,0x52d0],[0,1]));cases +=[(seed,seed%5,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,1) for seed in range(10000,12000)]
  for profile,entry,same,flags,sp,limit in cases:
   rng=random.Random(0x46120000+profile);data=bytearray(base);ss=ds if same else 0x9000;old=[0,1,1599,1600,0xffff,0x8000,0x7fff,60000][profile%8];target=[0,800,999,1000,0xffff,0x8000,0x7fff,0xff38][profile%8];factor=[0,1,65535,0x8000,0x7fff,100,32767,2000][profile%8];dx=[0,1,1600,1601,0xffff,0x8000,0x7fff,100][profile%8]
   if profile>=10000:old,target,factor,dx=[rng.randrange(65536) for _ in range(4)]
   for o,v in [(0x52ce,old),(0x332c,target),(0x3328,factor)]:struct.pack_into('<H',data,ds*16+o,v)
   data[ds*16+0x2f56]=[0,1,0x80,0xff][profile%4];data[ds*16+0x336c]=[0,1,0x7f,0x80,0xff][profile%5];data[ds*16+0x2f5b]=0xa5
   for k in range(64):data[ds*16+0x324a+k]=(profile*17+3*k)&255
   struct.pack_into('<H',data,ss*16+sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,dx,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,calls=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_kind=None,in_child=False);u.emu_start(cs*16+entries[entry],0,count=1000);raw=root=False;label=f'{load:x}/{profile}/{entry}/{same}/{flags:x}/{sp:x}/{limit}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;active['return_kind']=None
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x4611,active['expected_sp']):raw=True;break
    active['in_child']=False;u.emu_start(cs*16+0x4611,0,count=1000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require((out.status,out.current_sp,out.calls,out.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['before460E_CALL_prefix' if active['prefix'] else 'raw_child_near_return' if raw else 'root_near_return']+=1;coverage['actual4612_near_CALLs']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP18_cases']+=int(sp==18);coverage['DS_equals_SS_cases']+=same;coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111);coverage[f'entry_{entries[entry]:04X}_cases']+=1;coverage['seeded_random_cases']+=int(profile>=10000)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['raw_child_near_return']>0 and coverage['raw_root_returns']>0,'Coverage '+str((fence-sites,dict(coverage))));records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[r['id'] for r in records if any(e.get('segment')==0x6c9 and e.get('segment_offset') in entries for e in r['entries'])];record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_control_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Additionalfullbus/SS/CFIFDF view foractual4588/44D8/45BF/4612/45FC, actual460EnearCALL4612frame/productbody/RET2, allsourceorderedreads/writes/word-bytewrap/signedguards/rawCF, noABImock orSSscratch exclusions. Priorhigher-levelgroup sources/receipts remainfrozen/separatelybounded; newliteralbus bodies retainactualnestedSS effects excludedbyoldgroupinterface. NativebeforeCALL/rawchildRET exposedafteractualRET targetneverfollowed. Actualcaller/DS-SS/tablebounds/writers/units/lifetime/IRQ/core/resource/device/session/gameplay/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
