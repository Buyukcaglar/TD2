"""Compare actual5ADA with both5B5A and four optional5C30 near calls."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','iterations','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:5ADA','06C9:5B5A','06C9:5C30'] for ip in f['instructions']};call_sites={0x5ae8,0x5af6,0x5b07,0x5b19,0x5b39,0x5b4b};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Record sequence escaped '+hex(address))
   if ip in [0x5b59,0x5c2f,0x5c59]:active['return_kind']='root' if ip==0x5b59 else 'child';u.emu_stop();return
   if ip in call_sites:
    if active['calls']==active['limit']:active['prefix']='outer';u.emu_stop();return
    active['calls']+=1;active['child_iterations']=0;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip in [0x5b87,0x5bf6,0x5c3a]:
    if active['child_iterations']==active['child_limit']:active['prefix']='child';u.emu_stop();return
    active['child_iterations']+=1;active['iterations']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No platform/division instructions in selected sequence')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(48),[0,1],[2,0x603],[0xe000,0x5354,0x39a7],[0,1,2,3,6],[0,1,4,128]));cases +=[(profile,same,flags,24,limit,child) for profile,same,flags,limit,child in itertools.product(range(8),[0,1],[2,0x203,0x402,0x603],[0,6],[0,128])];cases +=[(999,same,2,0xe000,3,65536) for same in [0,1]]
  for profile,same,flags,sp,limit,child_limit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;origin=[0,8,16,24,1,0xfff8][profile%6];count=[8,16,24,32,33,0,0xffff,1][profile%8];ax=[0,1,0xffff,0x8000,0x7fff,0xfffe][profile%6];dx=[0,1,0x3b50,0x3b51,0x7fff,0x8000,0xffff,60][profile%8];period=[0,1,2,100,0x3b51,0x8000,0xffff,360][profile%8]
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   if profile==999:origin=count=ax=dx=period=0
   for o,v in [(0x380d,period),(0x3811,[0,1,0x3b51,0x8000][profile%4]),(0x5356,count),(0x5354,count),(0x330e,origin),(0x330c,origin),(0x52c8,ax),(0x52ca,dx),(0x52d0,ax^0xffff),(0x52d2,dx^0xffff)]:put(o,v)
   data[ds*16+0x3379]=profile%2
   for base_offset in [0x39a3,0x3813]:
    for k in range(6):
     put(base_offset+8*k+4,(ax+[-1,0,1,0xffff][(profile+k)%4])&65535);put(base_offset+8*k+2,(dx+[0,1,3,26,60,0x7fff,0x8000,0xffff][(profile+k)%8])&65535)
    if profile==999:put(base_offset+2,0x8000);put(base_offset+0xfff8+2,0x8000)
   frame=struct.pack('<2H',0x1111,0x2222);data[ss*16+sp:ss*16+sp+4]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x5ada),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,child_limit=child_limit,calls=0,iterations=0,child_iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0x5ada,0,count=2000000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['site']+3,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=2000000)
   require(active['prefix'] or root or raw,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,child_limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.calls==active['calls'] and out.iterations==active['iterations'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['outer_CALL_prefix' if active['prefix']=='outer' else 'child_loop_prefix' if active['prefix']=='child' else 'raw_child_near_return' if raw else 'root_far_return']+=1;coverage['actual_near_CALLs']+=out.calls;coverage['child_iterations']+=out.iterations;coverage['bus_write_events']+=out.bus_writes;coverage['raw_root_returns']+=int(root and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['minimumSP24_cases']+=int(sp==24);coverage['DS_equals_SS_cases']+=same;coverage['full65536_selector_runs']+=int(profile==999 and active['prefix']=='outer' and active['calls']==3)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['full65536_selector_runs']==4,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000127'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_sequence.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual5ADA far root with two actual5B5A and two or four actual5C30 near C bodies; no ABI-value leafmock/SSscratch exclusion. Fullbus/nestedSSsaves/near-farframes/GPR/BP/CFIFDF/control/actualCALLcount and child-loop budgets. Raw source count/origins and ordered rereads/updates; count0 selector LOOP65536 retained. Child normal RET checked for CS/IP/SP, changed raw coordinates exposed after actualRET never followed. Actual1B2Ccaller/fieldproducer/writers/capacity/alignment/sortedness/aliaslifetime/exclusion/otherFLAGS/core/resourcefedP2/P3/session/gameplay/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
