"""Compare2600 inheritedBP/actualDOS40/stackcarry/nonlocalfarreturn/094A mapper."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip','return_kind','return_valid']]+[(n,C.c_uint32) for n in ['calls','services','bus_writes']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_write_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());family=['13A8:2600','13A8:094A'];fence={ip for f in g['functions'] if f['entry'] in family for ip in f['instructions']};require(len(fence)==64,'Fence');mapper_high={0x94a,0x94d,0x94f,0x974,0x976,0x96f,0x970,0x973};excluded={ip for f in g['functions'] if f['entry']=='13A8:094A' for ip in f['instructions']}-mapper_high;require(len(excluded)==13,'MapperAHnonzerodisposition');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in [0x261e,0x943,0x973]:active['return']=ip;u.emu_stop();return
   if ip==0x939:
    if active['calls']==active['call_limit']:active['prefix']='mapper_call';u.emu_stop();return
    active['calls']+=1;active['frame']=(0x93c,u.reg_read(UC_X86_REG_SP))
   if ip==0x260e and len(active['requests'])==active['service_limit']:active['prefix']='service';u.emu_stop();return
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def response(r,profile):
   returned=StateRegisters.from_buffer_copy(bytes(r));mode=profile%7;returned.carry=int(mode in [1,2,4,6]);returned.registers.ax=[0,5,0xffff,7,0x1234,0x8000,0x0900][mode]
   if mode>=3:
    returned.registers.bx=4;returned.registers.cx=0xbada;returned.registers.dx=0x6d00;returned.registers.si=0x1357;returned.registers.di=0x2468;returned.registers.ds=ds+0x100;returned.registers.es=0x7654;returned.registers.interrupts_enabled=1-r.registers.interrupts_enabled;returned.registers.direction=1-r.registers.direction
    if mode==6:returned.bp=0xd000
   return returned
  def mutations(ss,sp,r,profile):
   kind=(profile//7)%4
   if kind==0:return []
   at=sp if kind==1 else r.bp if kind==2 else (r.bp-8)&65535
   return [((((ss<<4)+at)&0xfffff),0x1357)]
  def interrupt(cpu,number,unused):
   site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site==0x260e,'DOS40only');r=state(u);require(r.registers.ax>>8==0x40,'DOSidentity');qsp=u.reg_read(UC_X86_REG_SP);active['requests'].append([number,site,cs,active['ss'],qsp,*values(r.registers),r.bp,r.carry]);returned=response(r,active['profile'])
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
   for at,v in mutations(active['ss'],active['sp'],returned,active['profile']):u.mem_write(at,struct.pack('<H',v));active['service_writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=itertools.product(range(112),[0,1],[2,0x603],[0,6,0xe000,0xfffe,0xffff],range(3))
  for profile,same,flags,sp,kind in cases:
   data=bytearray(base);ss=ds if same else 0x9000;bp=[0x8000,0x6da0,0x6d99,(sp-8)&65535,(sp+4)&65535,0xd000][profile%6];dx=[0x3000,0,0xffff,0x6da0][profile%4];di=(dx+[0,1,2,0x200,0xffff][(profile//4)%5])&65535;handle=4;calls=0 if kind==1 else 1;services=0 if kind==0 else 1
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   def wb(sg,o,v):data[((sg<<4)+(o&65535))&0xfffff]=v&255
   for sg in [ds,ds+0x100]:
    wb(sg,0x6da4+handle,0x40 if profile%2 else 0);wb(sg,0x6d00,0x1a if profile%3 else 0);wb(sg,0x6d9d,profile%5)
    for i in range(20):wb(sg,0x6dda+i,(17*i+profile)&255)
   for parent in [bp,0xd000]:
    saved=0x6d93 if profile%8==0 else 0x9000
    for o,v in [(parent-8,saved),(parent-2,0x1234),(parent,0x5678),(parent+2,0x1111),(parent+4,0x2222),(parent+6,handle),(parent+8,0x6d00)]:put(ss,o,v)
    put(ss,saved,0x3456);put(ss,saved+2,0x4567)
   put(ss,sp,0x3333);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,dx,0x3456,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),bp,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2600),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(ss=ss,sp=sp,profile=profile,call_limit=calls,service_limit=services,calls=0,frame=None,requests=[],service_writes=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{kind}';u.emu_start(cs*16+0x2600,0,count=1000);raw=root=False;return_kind=0
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip in [0x261e,0x943]:root=True;return_kind=int(ip==0x943);break
    expected_ip,expected_sp=active['frame'];active['frame']=None
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,expected_ip,expected_sp):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=1000)
   require(active['prefix'] or raw or root,'Outcome '+label);native_requests=[]
   @Service
   def callback(context,memory,request_pointer,result):
    q=request_pointer.contents;r=q.incoming;native_requests.append([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(r.registers),r.bp,r.carry]);returned=response(r,profile);result[0]=returned
    for at,v in mutations(ss,sp,returned,profile):memory[at]=v&255;memory[(at+1)&0xfffff]=v>>8
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),calls,services,callback,None,C.byref(r));actual=(r.status,r.current_sp,r.return_kind,r.return_valid,r.calls,r.services,r.bus_writes);expected=(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),return_kind,int(root),active['calls'],len(active['requests']),active['writes']);require(actual==expected,'Status/count '+label+str((actual,expected)));require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_mapper_return' if raw else 'root_far_return' if return_kind else 'root_near_return']+=1;coverage['mapper_CALLs']+=r.calls;coverage['syntheticDOS40']+=r.services;coverage['bus_write_events']+=r.bus_writes;coverage['service_write_events']+=active['service_writes'];coverage['initial_DS_equals_SS_cases']+=same;coverage['SP_wrap_boundary_cases']+=int(sp in [0,0xfffe,0xffff]);coverage['stack_ADDSP8_carry_cases']+=int(0x2624 in active['sites']);coverage['ctrlZ_CLC_shared_exit_cases']+=int(0x2637 in active['sites']);coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=((0x2222,0x1111) if return_kind else (cs,0x3333)))
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites-excluded)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites-excluded)]}),flush=True)
 require(sites==fence-excluded and coverage['stack_ADDSP8_carry_cases'] and coverage['ctrlZ_CLC_shared_exit_cases'],'Coverage '+str(([f'{ip:04X}' for ip in sorted(fence-sites-excluded)],dict(coverage))));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x2600 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_write_span.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'sites':[f'13A8:{ip:04X}' for ip in sorted(excluded)],'scope':'094Aenteredonlythrough2600sharedSTC-AX1C00orstackcarry-AH09','reason':'AHnonzero at0939, actualMOVs-POPs-CALL do notchangeAH; mapperORAH-JNE selects8of21sites. Standalone094Aall21passed, notglobaldead.'}],'fixture_coverage':dict(coverage),'limits':'Actual13A8:2600 near/inheritedBP-DX-DI/fullSS/threeactualsaves/typedDOS40/currentreturnedGPR-BP-DS-IFDF/addactualcount/normalnearRET orADDSP8carry-replacesDOSCF/rawhandleflags-1A/sharednonlocalfarRET/actual094Anearframe-rawreturn. All16bitSPprofile inclwrap/wholebus/GPR-BP-CFIFDF/control/counts. OtherarithFLAGSunexposed/knowncallerslivenessreviewseparate. Serialized20bitRAM/noMEM_READhook/realDOS-INTframesunexercised/historicalCPU-A20unqualified. Nativebudgets/rawRETtargetsexposedafterinstructionneverfollowed. Whole2558/allwriters/storage/domains/capacity/lifetime/exclusion/core/resource/device/session/gameplay/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
