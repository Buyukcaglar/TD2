"""Compare actual5880 with five frozen child bodies and fullSS/field/table effects."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','child_iterations','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/freshpaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_field_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=['06C9:5880','06C9:5299','06C9:5C5A','06C9:52FD','06C9:5334','06C9:535B'];fence={ip for f in g['functions'] if f['entry'] in entries for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={ip for ip in fence if next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic=='ret'};require(0x595e in rets,'RootRET');calls={0x588d,0x589f,0x58b9,0x58d3,0x58e1,0x58ea};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fieldcontroller escaped '+hex(address))
   if ip in rets:active['return_kind']='root' if ip==0x595e else 'child';u.emu_stop();return
   if ip in calls:
    if active['calls']==active['limit']:active['prefix']='root';u.emu_stop();return
    active['calls']+=1;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip==0x52bf:
    if active['iterations']==active['child_limit']:active['prefix']='child';u.emu_stop();return
    active['iterations']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('NoINT/DIVfault delivery admitted inselected5880 chain')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(64),[0,1],[2,0x603],[34,0xe000,0x3342,0x3346],[0,2,6],[0,1,4]));cases +=[(seed,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,6,4) for seed in range(10000,12000)]
  for profile,same,flags,sp,limit,child_limit in cases:
   rng=random.Random(0x58800000+profile);data=bytearray(base);ss=ds if same else 0x9000
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   def wb(o,v):data[ds*16+(o&65535)]=v&255
   high=[0,1,0x3b40,0x3b41,0x3b42,0x7fff,0x8000,0xffff][profile%8];angle=[0,1,0xffff,0x7fff,0x8000,1600,3200,0xfb00][profile%8];field=[0,0xff38,160,560,0x7fff,0x8000,0xffff,0xffd8,120,200][profile%10];origin=[0,8,16,1,0xfff8][profile%5];period=[0,1,100,0x3b51,0x8000,0xffff][profile%6]
   if profile>=10000:high,angle,field,origin,period=[rng.randrange(65536) for _ in range(5)]
   for o,v in [(0x52ca,high),(0x52ce,angle),(0x52cc,field),(0x330c,origin),(0x330e,origin),(0x380f,period),(0x3342,[0,100,0xffff,0x8000][profile%4]),(0x333e,0),(0x3344,0)]:put(o,v)
   wb(0x33b7,profile%4)
   for k in range(4):wb((high+10*k)&65535,[0,1,0x7f,0x80,0xff,0x81,0x40,0xc0][(profile+k)%8])
   for k in range(128):wb(0x347f+4*k,(profile*17+k*3)&255)
   for k in range(256):put(0x32ee+2*k,[0,1,100,255,256,0xffff][(profile+k)%6])
   # The raw512byte table overlaps330C/330E; explicitly select finalfixture
   # origins afterinitializingtablebytes, preserving actualsharedbus aliases.
   put(0x330c,origin);put(0x330e,origin)
   for base_offset in [0x3813,0x39a3]:
    put(base_offset+origin+2,high+[-3,-2,-1,0,1,2,3,59,60,61,0x7fff,0x8000][profile%12]);put(base_offset+origin+6,[-401,-400,-1,0,399,400,800,801,0x7fff,0x8000][profile%10])
   struct.pack_into('<H',data,ss*16+sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x5880),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,child_limit=child_limit,calls=0,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0x5880,0,count=10000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['site']+3,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=10000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,child_limit,C.byref(out));require((out.status,out.current_sp,out.calls,out.child_iterations,out.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['iterations'],active['writes']),'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'root_near_return']+=1;coverage['actual_near_CALLs']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP34_cases']+=int(sp==34);coverage['DS_equals_SS_cases']+=same;coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111);coverage['seeded_random_cases']+=int(profile>=10000)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-{0x5303} and coverage['raw_child_return']>0,'Coverage '+str((fence-sites,dict(coverage))));records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[r['id'] for r in records if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x5880 for e in r['entries'])];require(len(ids)==1,'ID');record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_field_controller.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'site':'06C9:5303','scope':'From52FD entry under5880 calls only','reason':'AdjacentJLE/JG readunchangedZF/SF/OF andexhaust allcases; ADDCX380D cannotbefalleninto. Notglobaldeadcode.','evidence':'docs/recovery/evidence/td2ega-small-algorithms-context-v1.json'}],'fixture_coverage':dict(coverage),'limits':'Actual5880 plus fiveactualfrozenchildC bodies5299/5C5A/52FD/5334/535B, sixnearCALLsites/actualSSframes/RET2. NoABI-valuemock orSSscratch exclusion. Fullbus/GPR/BP/CFIFDF/control/writecount/childbudget. Rawtablebyte/wordlookups/lowbyteMUL/guardedDIV/signedfieldclamps andparentorderedrereads/branch/store effects retained; rawreturntargetsexposedafteractualRET neverfollowed. Source5299JL infeasiblefromselectedentry and52FD5303excluded byadjacentcomplementarysignedbranches requirestaticdisposition ifunexercised. Actual403B/fullcaller/writer/bounds/lifetime/IRQ/core/resource/device/session/gameplay/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
