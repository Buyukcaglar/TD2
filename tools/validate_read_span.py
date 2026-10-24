"""Compare247C/actual094A/fullSS/DOS3F-4400-4201/currentDS-vs-SS/lookahead state."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from validate_write_span import Request,Service,state
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','services','steps','bus_writes']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def event(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_read_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];require(C.sizeof(Result)==48,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['13A8:247C','13A8:094A'] for ip in f['instructions']};require(len(fence)==118,'Fence');vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def make_response(q,c):
   r=StateRegisters.from_buffer_copy(bytes(q.incoming));writes=[];site=q.site;rr=r.registers;inc=q.incoming.registers;profile=c['profile'];r.carry=0
   if site==0x24a5:
    rr.ax=len(c['payload'])
    if c['primary_error']>=0:r.carry=1;rr.ax=c['primary_error']
    else:writes +=[((((inc.ds<<4)+((inc.dx+i)&65535))&0xfffff),v,1) for i,v in enumerate(c['payload'])]
    if profile==4:
     rr.bx=2;rr.cx=0xbada;rr.dx=0x7000;rr.si=0x1357;rr.di=0x2468;rr.ds=ds+0x100;rr.es=0x7654;rr.interrupts_enabled=1-inc.interrupts_enabled;rr.direction=1-inc.direction
    if profile in [6,7]:r.bp=c['altbp']
    if profile==8:rr.ax=0x8000
   elif site==0x2504:rr.ax=0x5507;rr.dx=c['ioctl'];r.carry=c['ioctl_error']
   elif site in [0x2511,0x2522]:
    rr.ax=0 if c['peek']==2 else 1
    if c['peek']==3:r.carry=1;rr.ax=c['peek_error']
    elif c['peek']!=2:writes.append(((((inc.ds<<4)+inc.dx)&0xfffff),0xa if c['peek']==0 else 0x41,1))
    if profile==5:rr.cx=2;rr.si=0x6001;rr.di=0x6000;rr.direction=1
   elif site==0x2538:rr.ax=0x1234;r.carry=c['seek_error']
   else:raise RuntimeError('UnexpectedDOSsite '+hex(site))
   return r,writes
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x943:
    if u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']=True;u.emu_stop();return
    active['return']=ip;u.emu_stop();return
   if ip==0x973:active['return']=ip;u.emu_stop();return
   if ip==0x939:
    if active['calls']==active['case']['calls']:active['prefix']='mapper';u.emu_stop();return
    active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip in [0x24a5,0x2504,0x2511,0x2522,0x2538] and len(active['requests'])==active['case']['services']:active['prefix']='service';u.emu_stop();return
   if ip==0x24d0:
    if active['steps']==active['case']['steps']:active['prefix']='LODS';u.emu_stop();return
    active['steps']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def interrupt(cpu,number,unused):
   site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site in [0x24a5,0x2504,0x2511,0x2522,0x2538],'DOSonly');r=state(u);require((r.registers.ax>>8)==0x3f if site in [0x24a5,0x2511,0x2522] else r.registers.ax==(0x4400 if site==0x2504 else 0x4201),'DOSAX');q=Request(number,site,cs,active['ss'],u.reg_read(UC_X86_REG_SP),r);active['requests'].append(event(q));returned,writes=make_response(q,active['case'])
   for at,v,size in writes:u.mem_write(at,bytes([v]));active['adapter_writes']+=1
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_MEM_WRITE,written)
  def case(**kw):
   c=dict(payload=b'A\r\nB',flag=0x80,peek=0,peek_error=1,primary_error=-1,ioctl=0,ioctl_error=0,seek_error=0,profile=0,requested=4,handle=0,version=3,ss=0x9000,sp=0xe000,flags=2,calls=1,services=8,steps=16,altbp=0x8000,buffer=0x6000);c.update(kw);return c
  payloads=[b'',b'A',b'\n',b'\r',b'\x1a',b'A\r\nB',b'A\nB',b'A\rB',b'\r\n',b'\n\r',b'AB\r',b'\r\r',b'\r\x1a',b'\xff\r\n',b'ABCD']
  cases=[case(payload=payload,flag=flag,peek=peek,requested=max(1,len(payload)),ss=ss,flags=f) for payload,flag,peek,ss,f in itertools.product(payloads,[0,2,0x80,0xc0],range(4),[0x9000,ds],[2,0x603])]
  cases +=[case(handle=1,calls=calls,services=0,ss=ss,flags=f) for calls,ss,f in itertools.product([0,1],[0x9000,ds],[2,0x603])]
  cases +=[case(payload=b'\r',requested=requested,flag=flag,peek=peek,ioctl=ioctl,ioctl_error=1,seek_error=1,ss=ss,flags=f) for requested,flag,peek,ioctl,ss,f in itertools.product([1,2],[0x80,0xc0],[0,1,2],[0,0x20],[0x9000,ds],[2,0x603])]
  cases +=[case(payload=b'\r',requested=1,flag=0x80,peek=3,peek_error=error,version=version,ss=ss,flags=f) for error,version,ss,f in itertools.product([0,1,0x13,0x14,0x20,0x21,0x22,0xff,0x8001],[2,3],[0x9000,ds],[2,0x603])]
  cases +=[case(payload=b'\r',requested=1,flag=flag,profile=profile,peek=peek,ss=ss,flags=f) for flag,profile,peek,ss,f in itertools.product([0,0x80,0xc0],[4,5,6,8],[0,1,3],[0x9000,ds],[2,0x603])]
  cases +=[case(primary_error=error,ss=ss,sp=sp,flags=f,calls=calls,services=services,steps=steps) for error,ss,sp,f,calls,services,steps in itertools.product([1,0x8001],[0x9000,ds],[0,0xe000],[2,0x603],[0,1],[0,1],[0,2])]
  cases +=[case(payload=b'\r',requested=2,peek=peek,flag=flag,services=services,steps=steps,ss=ss,flags=f) for peek,flag,services,steps,ss,f in itertools.product([0,1],[0x80,0xc0],range(4),[0,1,4],[0x9000,ds],[2,0x603])]
  cases +=[case(flag=0,profile=7,altbp=bp,ss=ss,flags=f) for bp,ss,f in itertools.product([0,1,0xfffb,0xfffc,0xfffd,0xfffe,0xffff],[0x9000,0xffff],[2,0x603])]
  cases +=[case(primary_error=1,ss=ds,sp=sp,flags=f) for sp,f in itertools.product([0x6d95,0x6d9b],[2,0x603])]
  cases +=[case(payload=b'\x34\x12',requested=2,flag=0,ss=ds,sp=sp,flags=f) for sp,f in itertools.product([0x6000,0x6002],[2,0x603])]
  for c in cases:
   data=bytearray(base);ss,sp=c['ss'],c['sp']
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   for sg in [ds,ds+0x100]:
    put(sg,0x6da2,1);data[((sg<<4)+0x6d9d)&0xfffff]=c['version']
    for h in [0,2]:data[((sg<<4)+0x6da4+h)&0xfffff]=c['flag']
    for i in range(20):data[((sg<<4)+0x6dda+i)&0xfffff]=(0x80+i*13)&255
    for o in [0x6000,0x7000]:
     for i,v in enumerate(c['payload']+b'\rZ'):data[((sg<<4)+o+i)&0xfffff]=v
   put(ss,sp,0x1111);put(ss,sp+2,0x2222)
   for i,v in enumerate([c['handle'],c['buffer'],c['requested']]):put(ss,sp+4+2*i,v)
   if c['profile'] in [6,7]:
    bp=c['altbp'];put(ss,bp,0x1357);put(ss,bp+2,0x2468);put(ss,bp+4,0x369c);put(ss,bp+6,c['handle']);put(ss,bp+8,c['buffer']);put(ss,bp+10,c['requested'])
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(c['flags']>>9)&1,(c['flags']>>10)&1),0x5678,c['flags']&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x247c),(UC_X86_REG_EFLAGS,c['flags'])]:u.reg_write(reg,v)
   active.update(case=c,ss=ss,sp=sp,calls=0,steps=0,requests=[],adapter_writes=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,qualification=False,**{'return':False});label=f'{load:x}/'+str({k:v.hex() if isinstance(v,bytes) else v for k,v in c.items()});u.emu_start(cs*16+0x247c,0,count=20000);root=raw=False
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip==0x943:root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x93c,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=20000)
   require(root or raw or active['prefix'] or active['qualification'],'Outcome '+label);native_requests=[]
   @Service
   def dos(context,memory,request,result):
    q=request.contents;native_requests.append(event(q));returned,writes=make_response(q,c);result[0]=returned
    for at,v,size in writes:memory[at]=v
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),c['calls'],c['services'],c['steps'],dos,None,C.byref(r));require((r.status,r.current_sp,r.calls,r.services,r.steps,r.bus_writes)==(0 if root else 1 if raw else 5 if active['qualification'] else 3,u.reg_read(UC_X86_REG_SP),active['calls'],len(active['requests']),active['steps'],active['writes']),'Status/counters '+label);require(native_requests==active['requests'],'DOSABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_far_return' if root else 'raw_mapper_return' if raw else 'preRET_qualification' if active['qualification'] else 'prefix_'+active['prefix']]+=1;coverage['mapper_CALLs']+=r.calls;coverage['DOS_services']+=r.services;coverage['LODS_steps']+=r.steps;coverage['CPU_bus_writes']+=r.bus_writes;coverage['adapter_byte_writes']+=active['adapter_writes'];coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['incomingDF1_cases']+=incoming.registers.direction;coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['IOCTL_requests']+=sum(q[1]==0x2504 for q in native_requests);coverage['lookahead_requests']+=sum(q[1] in [0x2511,0x2522] for q in native_requests);coverage['seek_back_requests']+=sum(q[1]==0x2538 for q in native_requests)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['raw_mapper_return']>0 and coverage['lookahead_requests']>0 and coverage['seek_back_requests']>0 and coverage['IOCTL_requests']>0,'Coverage '+str(fence-sites));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_write_span.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/intel-far-return-stack-reference-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x247c for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_read_span.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual247C/094A/fullSS/currentDSflags-nearbuffer-vs-SSlookaheadlocal/primary3F-fullstate/CR-firstLF-1A/bytestoresdefaultDS/currentDFLODS/4400-3F-4201lookahead-fullstate/actualAHmarker-CX-BP-DS-DI-SIreturns/CALL-service-LODSbudgets/rawmapperRETafterinstructionneverfollowed/actualrootfarRET-preRETqualification/fullbus-GPR-BP-CFIFDF. SyntheticDOSnoINTframes/returnprofilesnotrealDOSpreservationmodel. No actualfileI/O/fullresourcecodec/writers-bufferbounds-storage-lifetime-exclusion/historicalCPU-A20/core/CGA/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
