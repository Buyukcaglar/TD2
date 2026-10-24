"""Compare word-DIV signed long quotient/remainder and actual RETF8 multiply."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','bus_writes']]+[('returned',StateRegisters)]
def signed(v):return v if v<0x80000000 else v-0x100000000
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_long_arithmetic;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['13A8:2E42','13A8:2F1C','13A8:2EE8'] for ip in f['instructions']};unreachable={0x2ef8,0x2efb,0x2efd,0x2eff,0x2f00};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();fault_sites=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence and ip not in unreachable,'Longarith escaped '+hex(address))
   if ip in [0x2ee4,0x2fc1,0x2f19]:active['return_kind']='child' if ip==0x2f19 else 'root';u.emu_stop();return
   if ip in [0x2ea1,0x2f7c,0x2ebb,0x2f94]:
    if active['steps']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['steps']+=1
   if ip in [0x2ebb,0x2f94]:active['calls']+=1;active['expected_ip']=ip+5;active['expected_sp']=(u.reg_read(UC_X86_REG_SP)+8)&65535
   if ip==0x2ef6:require((u.reg_read(UC_X86_REG_EFLAGS)&0x40)==0,'Actualchildfastbranch excluded by parentdenomHigh');active['multiply_general_calls']+=1
   if ip in [0x2e88,0x2e8f,0x2ead,0x2f5f,0x2f64,0x2f88]:
    by=u.reg_read(UC_X86_REG_CX);value=(u.reg_read(UC_X86_REG_DX)<<16)|u.reg_read(UC_X86_REG_AX)
    if by==0 or value//by>65535:active['fault']=True;active['fault_ip']=ip;active['sites'].add(ip);u.emu_stop();return
    active['successful_DIV']+=1
   if ip in [0x2ecc,0x2fa5]:active['estimate_corrections']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('SourceDIV prefix muststop before exception delivery; no actualINT')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  boundary=[0,1,2,3,0x7fff,0x8000,0xffff,0x10000,0x10001,0x10003,0x1ffff,0x40000001,0x7fffffff,0x80000000,0x80000001,0xffff0000,0xfffffffe,0xffffffff];cases=[(entry,num,den,same,flags,sp,limit,False) for entry,num,den,same,flags,sp,limit in itertools.product([0,1],boundary,boundary,[0,1],[2,0x203,0x402,0x603],[32,0xe000],[0,1,4,16,17,32])];rng=random.Random(0x2e422f1c)
  cases +=[(entry,rng.randrange(0x100000000),rng.randrange(0x100000000),seed%2,[2,0x203,0x402,0x603][seed%4],[32,0xe000][seed%2],[0,1,4,16,17,32][seed%6],True) for entry in [0,1] for seed in range(4000)]
  for entry,num,den,same,flags,sp,limit,randomized in cases:
   data=bytearray(base);ss=ds if same else 0x9000;frame=struct.pack('<6H',0x1111,0x2222,num&65535,num>>16,den&65535,den>>16);data[ss*16+sp:ss*16+sp+12]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));start=[0x2e42,0x2f1c][entry]
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,start),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,steps=0,calls=0,writes=0,instructions=0,successful_DIV=0,multiply_general_calls=0,estimate_corrections=0,sites=set(),executing_return=False,prefix=False,fault=False,fault_ip=0,return_kind=None);u.emu_start(cs*16+start,0,count=2000);raw=root=False;label=f'{load:x}/{entry}/{num:x}/{den:x}/{same}/{flags:x}/{sp:x}/{limit}/{randomized}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['expected_ip'],active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=2000)
   require(active['prefix'] or active['fault'] or root or raw,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 5 if active['fault'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.steps==active['steps'] and out.calls==active['calls'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SSarg rewrites '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
   if root:
    require(out.current_sp==sp+12 and (out.next_segment,out.next_ip)==(0x2222,0x1111),'LiteralrootRETF8 '+label);nval,dval=signed(num),signed(den);q=abs(nval)//abs(dval);q=-q if (nval<0)!=(dval<0) else q;expected=(q if entry==0 else nval-q*dval)&0xffffffff;require(((r.registers.dx<<16)|r.registers.ax)==expected,'Mathematicalbitpattern '+label);coverage['mathematical_bitpattern_checks']+=1;coverage['INT_MIN_minus_one_no_fault_returns']+=int(num==0x80000000 and den==0xffffffff)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['budget_prefix' if active['prefix'] else 'DIV_fault_prefix' if active['fault'] else 'raw_child_return' if raw else 'root_RETF8']+=1;coverage['actual_multiply_CALLs']+=out.calls;coverage['successful_DIV']+=active['successful_DIV'];coverage['estimate_corrections']+=active['estimate_corrections'];coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP32_cases']+=int(sp==32);coverage['DS_equals_SS_cases']+=same;coverage['seeded_random_cases']+=int(randomized)
   if active['fault']:fault_sites[f'13A8:{active["fault_ip"]:04X}']+=1
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-unreachable-sites)]}),flush=True)
 require(sites==fence-unreachable and coverage['estimate_corrections']>0 and set(fault_sites)=={'13A8:2E88','13A8:2F5F'},'Coverage '+str(fence-unreachable-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000343','FN-EGA-000345'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_long_arithmetic.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'unreachable_under_parent_guards':[f'13A8:{ip:04X}' for ip in sorted(unreachable)],'fault_prefix_sites':dict(fault_sites),'fixture_coverage':dict(coverage),'limits':'Actual2E42quotient/2F1Cremainder+actual2EE8 instructions against word-level C roots and frozenactualmultiply C with sourceSSABI adapter. FourSSoperandwords rewritten to magnitudes, twoDIVfastpath/SHR-RCRnormalize/correction/general multiply, actualSSsaves/args/farframes andliteralRETF8 atchildandroot(fullbus/GPR/BP/CFIFDF/control). Parentguards excludeonlyfive multiplyfastbranch sites alreadycovered byseparatemultiplyunit. UndefinedsuccessfulDIVFLAGS unadmitted; exposedprefix/rootCF definedbyotheroperations. DIVfaultprefixbeforeinstruction/exceptiondelivery; nativebefore-shift/CALL budgets separate. INT_MIN/-1 rawwrapreturnedwithout host signedUB, quotient/remainder mathematicalbitpattern checks separateassertionsoncompletedcases. Actualcaller/type/storage/exclusion/lifetime/otherFLAGS/core/session/gameplay/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
