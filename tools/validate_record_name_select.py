"""Compare0000:0730/actual2B40-2956/fullSS/signedcount/stride32/finaluncleanedargs."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','operations','iterations','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();library=a.library.resolve();out=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_name_select;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={(int(f['entry'][:4],16),ip) for f in g['functions'] if f['entry'] in ['0000:0730','13A8:2956','13A8:2B40'] for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={(seg,ip) for seg,ip in fence if next(md.disasm(image[16*seg+ip:16*seg+ip+15],ip,count=1)).mnemonic=='retf'};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);seg=(u.reg_read(UC_X86_REG_CS)-load)&65535;key=(seg,ip);require(key in fence,'Escaped '+hex(address))
   if key in rets:active['return']=key;u.emu_stop();return
   if key in [(0,0x752),(0,0x77e),(0,0x79b)]:
    if active['calls']==active['call_limit']:active['prefix']='call';u.emu_stop();return
    active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP);active['expected_ip']=ip+5;active['local_operations']=0
   if seg==0x13a8 and (ip in [0x2978,0x2b51] or (ip in [0x296b,0x297c,0x2980] and u.reg_read(UC_X86_REG_CX)!=0)):
    if active['local_operations']==active['child_limit']:active['prefix']='child';u.emu_stop();return
    active['operations']+=1;active['local_operations']+=1
   if key==(0,0x767):
    if active['iterations']==active['iteration_limit']:active['prefix']='parent';u.emu_stop();return
    active['iterations']+=1
   active['instructions']+=1;active['sites'].add(key)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT/faultdelivery admitted')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=[(p,s,f,sp,0 if k==0 else 16,0 if k==1 else 128,0 if k==2 else 8) for p,s,f,sp,k in itertools.product(range(32),[0,1],[2,0x603],[28,0xe000,0x8d08,0x8a7e,0x9216,0x90ae],range(4))];cases +=[(p,p%2,[2,0x203,0x402,0x603][p%4],0xe000,32,256,16) for p in range(10000,11000)]
  cases +=[(p,1,f,0x921c,16,128,8) for p,f in itertools.product([1,2,3,6],[2,0x603])]
  for profile,same,flags,sp,calllimit,childlimit,iterationlimit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;rng=random.Random(0x730865c+profile);df=(flags>>10)&1;count=[0,1,2,3,7,8,0x7fff,0x8000,0xffff][profile%9];names=[b'',b'AB',b'ab',b'A_B',b'A B',b'XYZ',b'\x80\xff',b'AbCd'];query=names[profile%8] if profile<10000 else bytes(rng.choice([65,66,97,98,32,95,128,255]) for _ in range(profile%24))
   def put(o,v,sg=ds):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   def wb(o,v):data[((ds<<4)+(o&65535))&0xfffff]=v
   for i,name in enumerate(names):
    off=0x865c+32*i;wb(off-1,0)
    for j,b in enumerate(name+b'\x00'):wb(off+j,b)
    put(off+26,0x1200+257*i)
   wb(0x9212-1,0)
   for j,b in enumerate(query+b'\x00'):wb(0x9212+(-j if df else j),b)
   put(0x90aa,count);put(0x8a80,0xa55a);put(sp,0x1111,ss);put(sp+2,0x2222,ss);
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,df),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x730),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(call_limit=calllimit,child_limit=childlimit,iteration_limit=iterationlimit,calls=0,operations=0,local_operations=0,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+0x730,0,count=20000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{calllimit}/{childlimit}/{iterationlimit}'
   while active['return']:
    seg,ip=active['return'];active['sites'].add((seg,ip));active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start((load+seg)*16+ip,0,count=1);active['executing_return']=False
    if seg==0:root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['expected_ip'],active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=20000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),calllimit,childlimit,iterationlimit,C.byref(r));require((r.status,r.current_sp,r.calls,r.operations,r.iterations,r.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['operations'],active['iterations'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in regs]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'far_root_return']+=1;coverage['actual_far_CALLs']+=r.calls;coverage['child_operations']+=r.operations;coverage['parent_iterations']+=r.iterations;coverage['bus_write_events']+=r.bus_writes;coverage['DS_equals_SS_cases']+=same;coverage['minimumSP28_cases']+=int(sp==28);coverage['reverse_DF_cases']+=df;coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111))
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{seg:04X}:{ip:04X}' for seg,ip in sorted(fence-sites-{(0x13a8,0x2978),(0x13a8,0x2979)})]}));return
   coverage['returned_CF1_root_cases']+=int(root and r.returned.carry==1)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{seg:04X}:{ip:04X}' for seg,ip in sorted(fence-sites)]}),flush=True)
 require(len(fence)==108 and sites==fence-{(0x13a8,0x2978),(0x13a8,0x2979)} and coverage['raw_child_return']>0 and coverage['returned_CF1_root_cases']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0 and e.get('segment_offset')==0x730 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_name_select.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'static_site_dispositions':[{'sites':['13A8:2978','13A8:2979'],'scope':'0730fixedcopydestination9212/even','reason':'LastPUSHAXbeforeactualfarCALLwrites9212destinationargument; distinctnonwrappingSSfarframe-ownBPsave/nointerveningdatawrites beforeTESTAL1. Standalone2956full26passed; notglobaldead.'}],'limits':'Actual0000:0730 far/noargs/SSlocalcounter-currentDS90AAsignedrereads/stride32casecompare2B40/query9212/fallbackrecord0/actual2956incomingDF/fullSS/allactualfarframes/final079BargumentsleftuntilMOVSPactualBP/POPBP/farRET. TailcurrentDS8CFAindexword/CL5SHLBXwordwrap-CFbit11/readDS8676+wrappedindex/storeDS8A80. Wholebus/GPR-BP-CFIFDF/control/counts. NativeCALL-perchildoperation-rootiterationbudgets/rawchildfarreturnsafterRETneverfollowed. Serialized20bitRAM/historicalCPU-A20unqualified. No validrecordcount-nameNUL-indexschema/capacity/allwriters/storage/DF-caller/ownership/lifetime/IRQ/core/resource/device/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
