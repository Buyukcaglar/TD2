"""Compare280E actual2830-2852-28C0/fullSS/requiredZF/orderedheapmetadata."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from validation.twenty_bit_bus import map_twenty_bit_ram
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','child_far_calls','child_near_calls','services','records','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_block_tail;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==60,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['13A8:280E','13A8:2830','13A8:2852','13A8:28C0'] for ip in f['instructions']};require(len(fence)==130,'Fence');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in [0x282f,0x2850,0x28bf,0x2915]:active['return']=ip;u.emu_stop();return
   if ip==0x2810:
    if active['calls']==active['call_limit']:active['prefix']='root_call';u.emu_stop();return
    active['calls']+=1;active['frames'].append((0x2813,u.reg_read(UC_X86_REG_SP)))
   if ip==0x283e:
    if active['far_calls']==active['far_limit']:active['prefix']='far_call';u.emu_stop();return
    active['far_calls']+=1;active['frames'].append((0x2843,u.reg_read(UC_X86_REG_SP)))
   if ip in [0x286a,0x2883]:
    if active['child_calls']==active['near_limit']:active['prefix']='child_call';u.emu_stop();return
    active['child_calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP)));active['local_records']=0
   if ip==0x2846:active['compared_DX']=u.reg_read(UC_X86_REG_DX)
   if ip==0x28c5:
    if active['local_records']==active['record_limit']:active['prefix']='record';u.emu_stop();return
    active['local_records']+=1;active['records']+=1
   if ip in [0x2904,0x28a9] and len(active['requests'])==active['service_limit']:active['prefix']='service';u.emu_stop();return
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def response(r,site,profile):
   ret=StateRegisters.from_buffer_copy(bytes(r));mode=(profile//3)%7;ret.carry=int(mode in [1,2,4,6] and (site==0x2904 or mode==2))
   if site==0x28a9:ret.registers.ax=8 if ret.carry else 0x7000+(profile&255)
   elif ret.carry:ret.registers.ax=8
   if mode>=3:
    ret.registers.bx=0xabcd;ret.registers.cx=0xbada;ret.registers.dx=0xcafe;ret.registers.si=0x6d20 if mode==5 else 0x6d34;ret.registers.di=0x6d2a;ret.registers.ds=ds+0x100;ret.registers.es=0x2468;ret.registers.interrupts_enabled=1-r.registers.interrupts_enabled;ret.registers.direction=1-r.registers.direction
    if mode==6:ret.bp=0xd000
   return ret
  def mutations(ss,sp,qsp,r,profile):
   if 20000<=profile<30000:return [(ss*16+sp-10,0 if profile%2 else 42)]
   if profile>=30000:return []
   kind=(profile//2)%3
   if kind==0:return []
   return [(ss*16+(sp if kind==1 else qsp),0x1357),(r.registers.ds*16+r.registers.si,0xa55a)]
  def interrupt(cpu,number,unused):
   site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site in [0x28a9,0x2904],'OnlysyntheticDOS48-4A');r=state(u);require(r.registers.ax>>8==(0x48 if site==0x28a9 else 0x4a),'DOSidentity');qsp=u.reg_read(UC_X86_REG_SP);active['requests'].append([number,site,cs,active['ss'],qsp,*values(r.registers),r.bp,r.carry]);returned=response(r,site,active['profile'])
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
   for at,v in mutations(active['ss'],active['sp'],qsp,returned,active['profile']):u.mem_write(at,struct.pack('<H',v));active['service_write_events']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(32),[0,1],[2,0x603],[36,0xe000,0x6d4c],[0,1],[0,1],[0,1],[0,32],[0,1]));cases +=[(profile,profile%2,[2,0x203,0x402,0x603][profile%4],0xe000,1,1,1,32,1) for profile in range(10000,11000)];cases +=[(profile,same,flags,sp,1,1,1,32,1) for profile,same,flags,sp in itertools.product(range(20000,20021),[0,1],[2,0x203,0x402,0x603],[36,0xe000])];cases +=[(profile,same,flags,sp,1,1,1,32,1) for profile,same,flags,sp in itertools.product(range(30000,30005),[0,1],[2,0x203,0x402,0x603],[36,0xe000])]
  for profile,same,flags,sp,calllimit,farlimit,nearlimit,recordlimit,servicelimit in cases:
   data=bytearray(base);key=[ds,ds+0x100,0,0xffff][profile%4];ss=ds if same else 0x9000;size=[0,1,15,16,0xffff,0x8000,0x7fff,0xfff1][profile%8];match=(profile//2)%22
   def put(sg,o,v):struct.pack_into('<H',data,sg*16+(o&65535),v&65535)
   for k in range(20):put(ds,0x6d2a+4*k,[0,1,15,16,0xffff,0x8000,0x7fff,0xfff1][(profile+k)%8]);put(ds,0x6d2c+4*k,key if k==match else key+1)
   put(ds,0x6d24,[0,1,16,0xffff][profile%4]);put(ds,0x6d9b,[0,1,key,0xffff][profile%4]);put(ds,0x6d7a,0x6d2a)
   if profile>=20000:size=5;put(ds,0x6d2a,16);put(ds,0x6d2c,key);put(ds,0x6d24,0)
   si=[0,1,20,21,0xffff,sp-2,sp,sp+2][profile%8];bx=[0xb123,sp-8,sp-6,sp-12,0xffff][profile%5]
   if profile>=30000:
    key=ds;size=5;put(ds,0x6d2c,key);put(ds,0x6d24,0xffff);si=[20,21,22,0,sp+2][profile-30000];bx=sp-6 if profile==30004 else 0xb123
    if profile==30004:put(ds,0x6d2a,sp-3)

   put(ss,sp,0x1111);struct.pack_into('<3H',data,ss*16+0xd000,0x7777,0x4444,0x5555);incoming=StateRegisters(Registers(size,bx,0xc456,0xd789,si,0x4567,key,ds,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x280e),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(call_limit=calllimit,far_limit=farlimit,near_limit=nearlimit,far_calls=0,frames=[],compared_DX=None,child_calls=0,record_limit=recordlimit,service_limit=servicelimit,ss=ss,sp=sp,profile=profile,calls=0,records=0,local_records=0,service_write_events=0,writes=0,instructions=0,sites=set(),requests=[],executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+0x280e,0,count=20000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{calllimit}/{recordlimit}/{servicelimit}'
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip==0x282f:root=True;break
    expected_ip,expected_sp=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,expected_ip,expected_sp):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=20000)
   require(active['prefix'] or raw or root,'Outcome '+label);native_requests=[]
   @Service
   def callback(context,memory,request,result):
    q=request.contents;r=q.incoming;native_requests.append([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(r.registers),r.bp,r.carry]);returned=response(r,q.site,profile);result[0]=returned
    for at,v in mutations(ss,sp,q.stack_sp,returned,profile):memory[at]=v&255;memory[at+1]=v>>8
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,calllimit,farlimit,nearlimit,recordlimit,servicelimit,C.byref(r));require((r.status,r.current_sp,r.calls,r.child_far_calls,r.child_near_calls,r.services,r.records,r.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],active['far_calls'],active['child_calls'],len(active['requests']),active['records'],active['writes']),'Status/count '+label);require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'root_near_return']+=1;coverage['root_near_CALLs']+=r.calls;coverage['actual_far_CALLs']+=r.child_far_calls;coverage['actual_near_CALLs']+=r.child_near_calls;coverage['records']+=r.records;coverage['bus_write_events']+=r.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['metadata_DS_equals_SS_cases']+=same;coverage['minimumSP36_cases']+=int(sp==36);coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(cs,0x1111))
   require(r.flags_valid==int(root) and r.zero_flag==((ef>>6)&1 if root else 0),'RequiredZF '+label);coverage['initial_DS_equals_SS_cases']+=int(key==ss)
   if root:
    coverage['returned_ZF1' if r.zero_flag else 'returned_ZF0']+=1;coverage['root_success_ZF1_nonzeroAX']+=int(r.zero_flag and r.returned.registers.ax not in [0,0xffff]);coverage['root_final_CF1']+=r.returned.carry
   for q in active['requests']:coverage['syntheticDOS48' if q[1]==0x28a9 else 'syntheticDOS4A']+=1
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 dispositions=fence-(set(next(f for f in g['functions'] if f['entry']=='13A8:280E')['instructions'])|{0x2830,0x2831,0x2832,0x2834,0x2835,0x2836,0x2837,0x2838,0x283b,0x283c,0x283d,0x283e,0x2843,0x2846,0x2849,0x284a,0x284b,0x284c,0x284e,0x2850}|{0x2852,0x2853,0x2855,0x2856,0x2857,0x2858,0x285c,0x285e,0x2861,0x2864,0x2867,0x2868,0x286a,0x286d,0x286f,0x2896,0x2899,0x289a,0x28b9,0x28ba,0x28bb,0x28bc,0x28be,0x28bf}|set(next(f for f in g['functions'] if f['entry']=='13A8:28C0')['instructions']));require(len(dispositions)==29 and sites==fence-dispositions and coverage['returned_ZF1'] and coverage['returned_ZF0'],'Coverage '+str((fence-sites,dispositions)));record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x280e for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_block_tail.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'sites':[f'13A8:{ip:04X}' for ip in sorted(dispositions)],'scope':'2852 entered onlythroughliteral2830 farCALL withfixedmode1/highguard0 andnosourcewrites tothoseSSargumentwords beforeguard/modebranch','reason':'Parentmode1 takes286A only; secondchild/fallbackDOS48/cursorpaths cannotexecute inthiscomposition. Notglobaldead; standalone2852coversall53sites.'}],'fixture_coverage':dict(coverage),'limits':'Actual13A8:280E/2830/2852mode1/28C0 fullSS/currentDS/orderedmetadata/requiredZF. RootPUSHDX-CX/nearCALL2830 consumesexplicitZF; optionalPUSHDI/DI=SI/SI=childAX+actualchildDX/threewordstores/SUBDXDI-DECDX/actualPOPAX-CX-DX/nearRET. CFfromSUBpreservedDEC, ZFfromDEC onbodyorwrapperZF1onskip, explicitnormalflagsvalid. 29parentmode-specificsitesinfeasibleonlyfromliteral2830frame, standalone2852fullbodypassed. SyntheticDOS4Afullreturnedstate/bus/SS-SP-CSfixed/realINTframesomitted. Budgets/rawRETtargetsexposedafterinstructionneverfollowed. Actualhigher26F1/27D4/metadatawriters/domain/capacity/storage/lifetime/IRQ/core/resource/device/session/gameplay/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
