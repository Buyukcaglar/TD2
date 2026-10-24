"""Compare28C0 inheritedBP/rawtable/rounding/fullreturnedDOS4A andnearRET."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['records','services','bus_writes']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_block_adjust;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==44,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='13A8:28C0')['instructions']);require(len(fence)==39,'Fence');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x2915:active['return']=True;u.emu_stop();return
   if ip==0x28c5:
    if active['records']==active['record_limit']:active['prefix']='record';u.emu_stop();return
    active['records']+=1
   if ip==0x2904 and active['service_limit']==0:active['prefix']='service';u.emu_stop();return
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(cpu,number,unused):
   require(number==0x21 and u.reg_read(UC_X86_REG_IP)==0x2906,'OnlyDOS4Aboundary');r=state(u);require(r.registers.ax>>8==0x4a,'DOS4A');active['requests'].append([number,0x2904,cs,active['ss'],active['sp'],*values(r.registers),r.bp,r.carry]);returned=active['returned']
   if returned is None:returned=r;returned.carry=active['error'];active['actual_returned']=returned
   else:active['actual_returned']=returned
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
   if active['mutate']:u.mem_write(active['ss']*16+active['sp'],struct.pack('<H',0x1357));u.mem_write(returned.registers.ds*16+returned.registers.si,struct.pack('<H',0xa55a));active['service_write_events']+=2
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(96),[0,1],[2,0x603],[0,0xe000,0x6d24],[0,1,32],[0,1]));cases +=[(profile,profile%2,[2,0x203,0x402,0x603][profile%4],0xe000,64,1) for profile in range(10000,11000)]
  for profile,same,flags,sp,recordlimit,servicelimit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;di=[0x6d2a,0x6d76,0x6d7a,0xfffe,0xffff,0,0x6d28,0x6d29][profile%8];bp=[0xd000,0x6d16,0xfffc][profile%3];segment=[0,1,0x7fff,0x8000,0xffff,0x2000,0x278f][profile%7];length=[0,1,15,16,0xffff,0x8000,0x7fff,0xfff1][profile%8];delta=[0,1,15,16,0x7fff,0x8000,0xffff,0xfff1][(profile//8)%8];match=[0,1,4,19,None][(profile//3)%5]
   def put(sg,o,v):struct.pack_into('<H',data,sg*16+(o&65535),v&65535)
   for k in range(32):put(ds,di+4*k,length);put(ds,di+4*k+2,segment if k==match else segment+1)
   put(ds,0x6d24,[0,1,16,0xffff][profile%4]);put(ds,0x6d9b,[0,1,0x2000,0xffff][profile%4]);put(ss,bp+14,segment);put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,delta,0x3456,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),bp,flags&1);mode=(profile//4)%5;returned=None if mode<2 else StateRegisters(Registers(0xbeef,0xabcd,0xbada,0xcafe,0x7ff0 if mode!=4 else 0x8010,0x7ff0 if mode==2 else 0x8000,ds+0x100,0x2468,1-incoming.registers.interrupts_enabled,1-incoming.registers.direction),0xd100,0);mutate=(profile//2)%2;u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x28c0),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(record_limit=recordlimit,service_limit=servicelimit,ss=ss,sp=sp,returned=returned,actual_returned=None,error=mode==1,mutate=mutate,service_write_events=0,records=0,writes=0,instructions=0,sites=set(),requests=[],executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+0x28c0,0,count=20000);label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{recordlimit}/{servicelimit}';require(active['prefix'] or active['return'],'Outcome '+label)
   if active['return']:active['sites'].add(0x2915);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0x2915,0,count=1);active['executing_return']=False
   native_requests=[]
   @Service
   def callback(context,memory,request,result):
    q=request.contents;r=q.incoming;native_requests.append([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(r.registers),r.bp,r.carry]);result[0]=active['actual_returned']
    if mutate:
     ret=result.contents;at=ss*16+sp;memory[at]=0x57;memory[at+1]=0x13;at=ret.registers.ds*16+ret.registers.si;memory[at]=0x5a;memory[at+1]=0xa5
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,recordlimit,servicelimit,C.byref(r));require((r.status,r.current_sp,r.records,r.services,r.bus_writes)==(3 if active['prefix'] else 0,u.reg_read(UC_X86_REG_SP),active['records'],len(active['requests']),active['writes']),'Status/count '+label);require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'near_return']+=1;coverage['records']+=r.records;coverage['syntheticDOS4Aservices']+=r.services;coverage['bus_write_events']+=r.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['DS_equals_SS_cases']+=same;coverage['minimumSP0_cases']+=int(sp==0);coverage['raw_near_returns']+=int(active['return'] and r.next_ip!=0x1111)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x28c0 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_block_adjust.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual13A8:28C0/near/inheritedBP/rawSS[BP+0E]/DIrecordstart/DXincrement, scan4byte/liveDSwords/wrappedtermination, ADD15/RCR/SHRparagraphrounding/fullreturnedDOS4AGPR-BP-DS-IFDF/orderedmetadataXCHG/fullSSnearRET. SyntheticservicepreservesSS-SP-CS/omitsrealINTframes, callbackbusmutationsincluded/excludedfrominstructionwritecounts. Nativebefore-record-INTbudgets/rawnearreturn exposedafterRETneverfollowed. No tabledomain/capacity/caller/storage/lifetime/IRQ/core/resource/device/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
