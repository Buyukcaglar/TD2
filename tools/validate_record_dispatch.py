"""Compare56ED/fullSS children/mutable57A7dispatch andliteralPOPAX-nearRET unwind."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','child_iterations','bus_writes']]+[(n,C.c_uint16) for n in ['raw_target','dispatch_offset','return_kind','discarded_word']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/freshpaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_dispatch;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==52,'Resultlayout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());family=['06C9:56ED','06C9:5299','06C9:52FD','06C9:5334','06C9:535B'];fence={ip for f in g['functions'] if f['entry'] in family for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={ip for ip in fence if next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic=='ret'};calls={0x56fa,0x5715,0x572f,0x5756,0x575d,0x577a,0x5781,0x5787};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;base[ds*16+0x3446:ds*16+0x346a]=image[0x178f0+0x3446:0x178f0+0x346a];u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def readword(segment,offset):return int.from_bytes(u.mem_read(((segment<<4)+offset)&0xfffff,2),'little')
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Recorddispatchescaped '+hex(address))
   if ip in rets:active['return_kind_stop']='root' if ip in [0x585b,0x587f] else 'child';u.emu_stop();return
   if ip in calls:
    if active['calls']==active['limit']:active['prefix']='root';u.emu_stop();return
    active['calls']+=1;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip==0x52bf:
    if active['iterations']==active['child_limit']:active['prefix']='child';u.emu_stop();return
    active['iterations']+=1
   if ip==0x57a7:
    active['dispatch_offset']=(u.reg_read(UC_X86_REG_BX)+0x3460)&65535;active['raw_target']=readword(u.reg_read(UC_X86_REG_DS),active['dispatch_offset'])
    if active['raw_target'] not in [0x57ab,0x57b7,0x57cf]:active['prefix']='indirect';u.emu_stop();return
   if ip==0x585a:active['return_kind']=1;active['discarded_word']=readword(u.reg_read(UC_X86_REG_SS),u.reg_read(UC_X86_REG_SP))
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('NoINT/faultdelivery inselectedrecorddispatch')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(96),[0,1],[2,0x603],[34,0xe000,0x3342,0x3462,0x52dc],[0,3,8],[0,1,4]));cases +=[(seed,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,8,4) for seed in range(10000,12000)];cases +=[(20000,same,flags,sp,8,4) for same,flags,sp in itertools.product([0,1],[2,0x203,0x402,0x603],[34,0xe000,0x9258])]
  cases +=[(profile,same,flags,sp,8,4) for profile,same,flags,sp in itertools.product(range(20001,20005),[0,1],[2,0x203,0x402,0x603],[34,0xe000])]
  for profile,same,flags,sp,limit,child_limit in cases:
   rng=random.Random(0x56ed0000+profile);data=bytearray(base);ss=ds if same else 0x9000
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   def wb(o,v):data[ds*16+(o&65535)]=v&255
   high=[0,1,0x3b40,0x3b41,0x3b42,0x7fff,0x8000,0xffff][profile%8];distance=[0,1,0xffff,0x7fff,0x8000,1600,3200,0xfb00][profile%8];angle=[0,0xff38,200,1000,0x7fff,0x8000,0xffff,0xffd8,120,200][profile%10];origin=[0,8,16,1,0xfff8][profile%5];period=[0,1,100,360,0x3b51,0x8000,0xffff][profile%7];cap=[0,0xff,0x100,0x101,0x400,0x8000,0xff00,0xffff][profile%8];mode=[0,1,2,3,4,5,6,8,0x80,0xff][profile%10]
   if profile>=10000:high,distance,angle,origin,period,cap=[rng.randrange(65536) for _ in range(6)];mode=1+profile%5
   for k in range(128):wb(0x347f+4*k,(profile*17+k*3)&255)
   for k in range(256):put(0x32ee+2*k,k*257+profile*31)
   # The32EEwordview overlapsallthreejumptables. Selectfinalinitialized
   # dispatchbytes afterthatfixturefill, retaining their sharedbusidentity.
   data[ds*16+0x3446:ds*16+0x346a]=image[0x178f0+0x3446:0x178f0+0x346a]
   for k in range(16):put(0x5636+2*k,k*4093+profile*17)
   for o,v in [(0x52da,high),(0x52de,distance),(0x52dc,angle),(0x3314,origin),(0x3316,origin),(0x331a,cap),(0x380d,period),(0x3342,[0,100,0xffff,0x8000][profile%4]),(0x333e,0),(0x3344,0),(0x52d8,[0,1,0xffff,0xa55a][profile%4]),(0x52c8,[0,1,0xffff,0x8000][profile%4]),(0x52ca,high+[-200,-100,-5,0,1,5,100,200][profile%8]),(0x52ce,0x1234),(0x52d2,high+[-3,0,3,60][profile%4]),(0x52d4,[-401,-400,0,399,400,800,801][profile%7]),(0x52d6,0x5678),(0x3332,[0,180,360,0xffff,0x8000,0x7fff][profile%6]),(0x5362,[0,1,100,0xffff,0x8000,0x7fff][profile%6]),(0x5364,[0,1,20,100,0xffff][profile%5]),(0x5366,[0,1,0xff,0xffff,0x640][profile%5]),(0x5368,[0,1,44,0xffff,0x8000,100][profile%6])]:put(o,v)
   for o,v in [(0x3379,profile%2),(0x33b6,profile%4),(0x33b7,(profile//2)%3),(0x33b8,mode),(0x33ba,0xa5),(0x3373,0xa5),(0x9258,0)]:wb(o,v)
   for base_offset in [0x3813,0x39a3]:put(base_offset+origin+2,high+[-3,-2,-1,0,1,2,3,59,60,61,0x7fff,0x8000][profile%12]);put(base_offset+origin+6,[-401,-400,-1,0,399,400,800,801,0x7fff,0x8000][profile%10])
   for k in range(4):wb((high+10*k)&65535,[0,1,0x7f,0x80,0xff,0x81,0x40,0xc0][(profile+k)%8])
   if profile>=10000:put(0x3460+2*(mode-1),[0x57ab,0x57b7,0x57cf,0,0xfffe][profile%5])
   if profile==20000:
    for o,v in [(0x52da,0),(0x52d8,0),(0x52ca,200),(0x52c8,0),(0x380d,1000),(0x52de,0),(0x331a,0x100),(0x3460,0x57b7)]:put(o,v)
    wb(0x33b8,1);wb(0x33b7,1);wb(0x3379,0)
   if 20001<=profile<=20004:
    wb(0x33b8,1);wb(0x3379,0);put(0x52d8,0);put(0x52c8,0);put(0x380d,1000)
    if profile in [20001,20004]:
     for o,v in [(0x52da,0),(0x52ca,0),(0x52de,1),(0x331a,1000),(0x5366,255),(0x32f0,255),(0x3460,0x57ab),(0x5364,0 if profile==20001 else 0xffff),(0x52dc,200)]:put(o,v)
     wb(0x33b7,0)
     for k in range(4):wb(10*k,1)
     wb(0x3483,255)
    else:
     for o,v in [(0x52da,400 if profile==20002 else 0),(0x52ca,0 if profile==20002 else 400),(0x52de,0),(0x331a,0x100),(0x3460,0x57b7)]:put(o,v)
     wb(0x33b7,1)
   struct.pack_into('<2H',data,ss*16+sp,0x1111,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x56ed),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,child_limit=child_limit,calls=0,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_kind_stop=None,raw_target=0,dispatch_offset=0,return_kind=0,discarded_word=0);u.emu_start(cs*16+0x56ed,0,count=10000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}'
   while active['return_kind_stop']:
    kind=active['return_kind_stop'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['return_kind_stop']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['site']+3,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=10000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,child_limit,C.byref(out));expected_status=6 if active['prefix']=='indirect' else 3 if active['prefix'] else 1 if raw else 0;require((out.status,out.current_sp,out.calls,out.child_iterations,out.bus_writes)==(expected_status,u.reg_read(UC_X86_REG_SP),active['calls'],active['iterations'],active['writes']),'Status/count '+label);require((out.raw_target,out.dispatch_offset,out.return_kind,out.discarded_word)==(active['raw_target'],active['dispatch_offset'],active['return_kind'],active['discarded_word']),'Dispatch/unwind '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'POPAX_then_RET2' if out.return_kind else 'normal_RET2']+=1;coverage['actual_near_CALLs']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP34_cases']+=int(sp==34);coverage['DS_equals_SS_cases']+=same;coverage['raw_root_returns']+=int(root and out.next_ip!=(0x2222 if out.return_kind else 0x1111));coverage['actual_discarded_word_changed_cases']+=int(out.return_kind and out.discarded_word!=0x1111);coverage['mutable_known_target_cases']+=int(profile>=10000 and active['raw_target'] in [0x57ab,0x57b7,0x57cf]);
   if root:coverage[f'handled_target_{active["raw_target"]:04X}']+=1
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-{0x5303} and coverage['POPAX_then_RET2']>0 and coverage['prefix_indirect']>0,'Coverage '+str((fence-sites,dict(coverage))));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000397'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_dispatch.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'site':'06C9:5303','scope':'From52FD entry under56ED calls only','reason':'AdjacentJLE/JG exhaust unchangedZF/SF/OF, nofallthroughADDCX380D; notglobaldead.'}],'fixture_coverage':dict(coverage),'limits':'Actual56ED plus actual5299/52FD/5334/535B C, fullSS/bus/GPR/BP/CFIFDF/control/counts. ActualmutableDS[3460+wrapped2*(byte33B8-1)] supportsrawtargets57AB/57B7/57CF; unknownnative6 stopsbefore57A7JMP/operandretained, notsourceerror/domainclosure. RootnormalRET2 orliteralPOPAX+RET2 consumesTWO SSwords, AXactualdiscardedword/return_kind1; actual53A6caller/nonlocalintegration separate. NoABI-valuemock/SSscratch exclusion. NativeCALL-loop/unknownindirect/rawRET prefixes distinct, rawtargetsexposedafterRET neverfollowed. Alltargetwriters/modebounds/caller/DS-SS/tablevalues/lifetime/IRQ/core/resource/device/session/gameplay/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
