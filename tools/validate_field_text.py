"""Compare0432:0006 andactual2956 copy with fullSS/DF/trim/normalization loops."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','child_operations','iterations','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();out=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_field_text;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={(int(f['entry'][:4],16),ip) for f in g['functions'] if f['entry'] in ['0432:0006','13A8:2956'] for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={(seg,ip) for seg,ip in fence if next(md.disasm(image[16*seg+ip:16*seg+ip+15],ip,count=1)).mnemonic=='retf'};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x432;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);seg=(u.reg_read(UC_X86_REG_CS)-load)&65535;key=(seg,ip);require(key in fence,'Escaped '+hex(address))
   if key in rets:active['return']=key;u.emu_stop();return
   if key==(0x432,0x13):
    if active['calls']==active['call_limit']:active['prefix']='call';u.emu_stop();return
    active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if seg==0x13a8 and (ip==0x2978 or (ip in [0x296b,0x297c,0x2980] and u.reg_read(UC_X86_REG_CX)!=0)):
    if active['operations']==active['child_limit']:active['prefix']='child';u.emu_stop();return
    active['operations']+=1
   if key in [(0x432,0x2e),(0x432,0x51)]:
    if active['iterations']==active['iteration_limit']:active['prefix']='parent';u.emu_stop();return
    active['iterations']+=1
   active['instructions']+=1;active['sites'].add(key)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT/faultdelivery admitted')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(48),[0,1],[2,0x603],[30,0xe000,0x4008],[0,1],[0,64],[0,40]));cases +=[(profile,profile%2,[2,0x203,0x402,0x603][profile%4],0xe000,1,128,128) for profile in range(10000,11000)]
  for profile,same,flags,sp,calllimit,childlimit,iterationlimit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;rng=random.Random(0x43206000+profile);df=(flags>>10)&1;dest=[0x4000,0x4001,0xffff,sp,(sp-4)&65535,(sp-10)&65535,(sp-12)&65535,(sp-14)&65535,(sp-16)&65535,sp+4,0x5000,0x5001][profile%12];src=[0x5000,0xfff8,0x4000,sp+4,(sp-4)&65535,0x8000][profile%6];payloads=[b'',b' ',b' '*18,b'A'+b' '*17,b' A B  ',b'ABC',b'A_B',b'\x80 \xff',b'A'*17+b' ',b'A'*18,b'\x00 Z',b' '*17+b'X'];payload=payloads[profile%12] if profile<10000 else bytes(rng.choice([32,32,65,95,128,255]) for _ in range(profile%40))
   for i,b in enumerate(payload+b'\x00'):data[ds*16+((src+(-i if df else i))&65535)]=b
   struct.pack_into('<4H',data,ss*16+sp,0x1111,0x2222,dest,src);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,df),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,6),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(call_limit=calllimit,child_limit=childlimit,iteration_limit=iterationlimit,calls=0,operations=0,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+6,0,count=20000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{calllimit}/{childlimit}/{iterationlimit}'
   while active['return']:
    seg,ip=active['return'];active['sites'].add((seg,ip));active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start((load+seg)*16+ip,0,count=1);active['executing_return']=False
    if seg==0x432:root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x18,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=20000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),calllimit,childlimit,iterationlimit,C.byref(r));require((r.status,r.current_sp,r.calls,r.child_operations,r.iterations,r.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['operations'],active['iterations'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in regs]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'far_root_return']+=1;coverage['actual_far_CALLs']+=r.calls;coverage['child_operations']+=r.child_operations;coverage['parent_iterations']+=r.iterations;coverage['bus_write_events']+=r.bus_writes;coverage['DS_equals_SS_cases']+=same;coverage['minimumSP30_cases']+=int(sp==30);coverage['reverse_DF_cases']+=df;coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111))
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{seg:04X}:{ip:04X}' for seg,ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x432 and e.get('segment_offset')==6 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_field_text.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual0432:0006/far/twoSSnearoffsetarguments, actual2956copy/farframe/fullSSlocals-saves/returnedGPR-BP/orderedtrim17downward andspace-to-underscoreforward loops. IncomingDF childcopy retained; parentscalarforward independent. Fullbus/GPR/BP/CFIFDF/control/counts. NativeCALL-childoperation-parentloopbudgets/rawchildfarreturn exposedafterRETneverfollowed. No stringcapacity/NUL/format/allwriters/caller/DS-SS/lifetime/IRQ/core/resource/device/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
