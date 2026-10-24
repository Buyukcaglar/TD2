"""Compare0201 record projection, literalREP/CLD, do-once loops and actualfarreturn."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['records','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();out=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_projection;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==40,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());f=next(f for f in g['functions'] if f['entry']=='06C9:0201');fence=set(f['instructions']);require(len(fence)==106,'Fence');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x337:active['return']=True;u.emu_stop();return
   if ip in [0x279,0x2b4]:
    if active['records']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['records']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT/faultdelivery admitted')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(96),[0,1],[2,0x603],[0,0xe000,0x1308,0x73c,0x1340],[0,1,2,32]));cases +=[(profile,profile%2,[2,0x203,0x402,0x603][profile%4],0xe000,128) for profile in range(10000,11000)];cases +=[(20000+v,1,2,0x5354,4096) for v in range(2)]
  for profile,same,flags,sp,limit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;rng=random.Random(0x20100000+profile)
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   def wb(o,v):data[ds*16+(o&65535)]=v&255
   high=[0,1,60,61,0x7fff,0x8000,0xffff,0xfff0][profile%8];low=[0,1,0xffff,0x8000][profile%4];count=[0,1,8,16,33,0xfff8,0xffff,256][profile%8];period=[0,1,100,360,0xffff,0x8000][profile%6]
   if profile>=10000:high,low,period=[rng.randrange(65536) for _ in range(3)];count=[0,1,8,16,33,128,256,0xffff][profile%8]
   for base_offset in [0x3813,0x39a3]:
    for k in range(40):
     put(base_offset+8*k,0xa500+k);put(base_offset+8*k+2,high+[-1,0,1,59,60,61,0x7fff,0x8000][(profile+k)%8]);put(base_offset+8*k+4,low+[-1,0,1,0xffff][(profile+k)%4]);put(base_offset+8*k+6,k*193+profile)
   for o,v in [(0x52c8,low),(0x52ca,high),(0x52cc,[0,1,0xffff,0x8000][profile%4]),(0x52d0,low+1),(0x52d2,high+[-1,0,60,0x8000][profile%4]),(0x52d4,profile*17),(0x52d8,low-1),(0x52da,high+[0,1,0x7fff,0x8000][profile%4]),(0x52dc,profile*29),(0x5354,count),(0x5356,[0,1,8,24,33,0xfff8,0xffff,256][profile%8]),(0x380d,period),(0x533e,0xa55a),(0x2f48,0x5aa5),(0x9b0,0x1234)]:put(o,v)
   for o,v in [(0x5491,profile),(0x3372,profile*3),(0x3373,profile*5),(0x3375,profile*7),(0x33b8,profile*11),(0x33b7,profile*13)]:wb(o,v)
   if profile>=20000:
    for base_offset in [0x3813,0x39a3]:
     for k in range(8192):put(base_offset+8*k+2,1);put(base_offset+8*k+4,0)
    for o,v in [(0x52c8,0),(0x52ca,0),(0x5354,0xffff),(0x5356,0xffff),(0x380d,0)]:put(o,v)
   struct.pack_into('<2H',data,ss*16+sp,0x1111,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x201),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,records=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+0x201,0,count=200000);label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}';require(active['prefix'] or active['return'],'Outcome '+label)
   if active['return']:active['sites'].add(0x337);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0x337,0,count=1);active['executing_return']=False
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(r));require((r.status,r.current_sp,r.records,r.bus_writes)==(3 if active['prefix'] else 0,u.reg_read(UC_X86_REG_SP),active['records'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in regs]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['before_record_prefix' if active['prefix'] else 'far_return']+=1;coverage['records']+=r.records;coverage['bus_write_events']+=r.bus_writes;coverage['DS_equals_SS_cases']+=same;coverage['minimumSP0_cases']+=int(sp==0);coverage['raw_far_returns']+=int(active['return'] and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['final_shift_carry']+=int(active['return'] and r.returned.carry)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x201 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_projection.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual06C9:0201/far/noargs, literal17wordREPSTOSW/CLD/ESDS, twodo-once8byterecordloops/currentDS/orderedcountandrecordrereads/partial6byteoutputin8bytestride. Fullbus/SS/GPR/BP/CFIFDF/control/writecounts. SBBimmediateJGEuseswide signedborrowpredicate, unsigned60filter, BPactualclobber, finalSHLcarry. Nativebefore-recordbudget/rawfarreturn exposedafterRETneverfollowed. No capacity/units/allwriters/caller/DS-SS/lifetime/IRQ/core/resource/device/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
