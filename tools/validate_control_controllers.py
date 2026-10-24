"""Compare5A6F/44EA with actualcontrol_bus children/tailJMP/fullSS/CFIFDF."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','nested_calls','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/freshpaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_control_controllers;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;entries=[0x5a6f,0x44ea];family=entries+[0x4588,0x44d8,0x45bf,0x4612,0x45fc];g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in family] for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={ip for ip in fence if next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic=='ret'};outer={0x5a79,0x5a7c,0x4521,0x452d,0x4582};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Controlcontrollersescaped '+hex(address))
   if ip in rets:active['return_kind']='nested' if active['frames'] else 'root';u.emu_stop();return
   if ip in outer or ip==0x460e:
    inner=ip==0x460e
    if (active['child_limit']==0 if inner else active['calls']==active['limit']):active['prefix']='inner' if inner else 'outer';u.emu_stop();return
    active['nested_calls' if inner else 'calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP),'inner' if inner else 'outer'))
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('NoINT inselectedcontrolcontrollers')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(64),range(2),[0,1],[2,0x603],[20,0xe000,0x332e,0x3330,0x2f58,0x33ce],[0,1,2],[0,1]));cases +=[(seed,seed%2,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,2,1) for seed in range(10000,12000)]
  cases +=[(profile,1,same,flags,sp,2,1) for profile,same,flags,sp in itertools.product(range(20000,20004),[0,1],[2,0x603],[20,0xe000])]
  for profile,entry,same,flags,sp,limit,child_limit in cases:
   rng=random.Random(0x44ea0000+profile);data=bytearray(base);ss=ds if same else 0x9000
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   def wb(o,v):data[ds*16+(o&65535)]=v&255
   for k in range(1,256):wb(0x33bf+k,(profile+k)%2)
   for k in range(81):wb(0x2419+k,(profile*17+3*k)&255)
   for k in range(64):wb(0x324a+k,(profile*3+7*k)&255)
   for o,v in [(0x52ce,[0,1,1599,1600,3200,0xffff,0x8000,0x7fff][profile%8]),(0x332c,[0,800,999,1000,0xffff,0x8000,0x7fff,0xff38][profile%8]),(0x3328,[0,1,0xffff,0x8000,0x7fff,100,32767,2000][profile%8]),(0x52cc,[0,1,24,25,0xffff,0x8000,0x7fff,120][profile%8]),(0x33ce,[0,1,97,99,100,279,280,0xffff][profile%8]),(0x33d0,[0,25,26,100,0xffff,0x8000,0x7fff,200][profile%8]),(0x33d2,[0,1,2,0xffff,0x8000,0x7fff][profile%6])]:put(o,v if profile<10000 else rng.randrange(65536))
   for o,v in [(0x2f56,[0,1,0x80,0xff][profile%4]),(0x336c,[0,1,0x7f,0x80,0xff][profile%5]),(0x33d4,[0,1,4,0xff][profile%4]),(0x33d5,profile%5),(0x336f,(profile//2)%2),(0x3365,(profile//3)%2),(0x3366,(profile//4)%2),(0x33b7,[0,1,2,7,8,0xff][profile%6]),(0x33b2,[0,1,8,9,0x80,0xff][profile%6]),(0x2f5b,0),(0x5490,0)]:wb(o,v)
   if profile<8 and entry==1:
    for o,v in [(0x33d5,0),(0x336c,1),(0x336f,0),(0x3365,0),(0x3366,0),(0x2f56,1),(0x33c0,0),(0x33b7,8)]:wb(o,v)
    if profile==0:wb(0x33d5,1)
    elif profile==1:wb(0x336c,0x80)
    elif profile==2:wb(0x336f,1)
    elif profile==3:wb(0x2f56,0)
    elif profile==4:wb(0x336c,0)
    elif profile==5:wb(0x33c0,1)
    elif profile==6:wb(0x33b7,2)
   if 20000<=profile<20004:
    for o,v in [(0x33d5,0),(0x336c,1),(0x336f,0),(0x3365,0),(0x3366,0),(0x2f56,1),(0x33c0,0),(0x33b7,8)]:wb(o,v)
    put(0x3328,0xffff);put(0x332c,1000);put(0x52ce,[0,1,3200,0xffff][profile-20000])
    for k in range(81):wb(0x2419+k,255)
    for k in range(64):wb(0x324a+k,255 if profile%2 else 0)
   struct.pack_into('<H',data,ss*16+sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,[0,1,1600,1601,0xffff,0x8000,0x7fff,100][profile%8],0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,child_limit=child_limit,calls=0,nested_calls=0,writes=0,instructions=0,sites=set(),frames=[],executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+entries[entry],0,count=1000);raw=root=False;raw_kind=None;label=f'{load:x}/{profile}/{entry}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;active['return_kind']=None
    if kind=='root':root=True;break
    expected_ip,expected_sp,frame_kind=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,expected_ip,expected_sp):raw=True;raw_kind=frame_kind;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=1000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,child_limit,C.byref(out));require((out.status,out.current_sp,out.calls,out.nested_calls,out.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['nested_calls'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_'+raw_kind+'_return' if raw else 'root_near_return']+=1;coverage['actual_outer_CALLs']+=out.calls;coverage['actual4612_CALLs']+=out.nested_calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP20_cases']+=int(sp==20);coverage['DS_equals_SS_cases']+=same;coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111);coverage[f'entry_{entries[entry]:04X}_cases']+=1
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-{0x4580},'Coverage '+str((fence-sites,dict(coverage))));records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[r['id'] for r in records if any(e.get('segment')==0x6c9 and e.get('segment_offset') in entries for e in r['entries'])];require(len(ids)==2,'IDs');record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_control_controllers.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'site':'06C9:4580','scope':'From44EA entry/serializedflatRAMonly','reason':'Early336Fnonzero jumps44DE beforeactionpath; actionpathhasnowritesto336F/nocallsbeforelater336Ftest, so laternonzerobranch cannotexecute. Notglobaldead/IRQproof.'}],'fixture_coverage':dict(coverage),'limits':'Actual5A6F/44EA plus actualfrozencontrol_bus C, realouter/nestednearCALLframes andtailJMP/rootRET2, fullbus/SS/GPR/BP/CFIFDF/control/counts/noABImockorSSscratch exclusion. Sourceguard/counter/table/word-bytewrap/signed-vsunsigned effects retained, actualsourcecleared2F56 maychangevianearframe.4580boundedentry-specificstaticdisposition under serializedRAM; noIRQexclusion claim. NativeouterCALL/inner460Ebudgets distinct; rawtargets exposedafterRET neverfollowed. Actual403B/othercallers/writers/units/tablebounds/ownership/lifetime/IRQ/fullstate/core/resource/device/session/gameplay/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
