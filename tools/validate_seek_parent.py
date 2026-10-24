"""Compare2AD8 with actual225E/094A, nestedSS pools and ignoredrestore result."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_close_handle import Registers,StateRegisters,Request,Result,Service,state,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class ParentResult(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','services','error_calls','bus_writes']]+[('returned',StateRegisters)]
Result=ParentResult
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/freshpaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_seek_parent;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['13A8:2AD8','13A8:225E','13A8:094A'] for ip in f['instructions']};int_sites={0x2286,0x22aa,0x22bd,0x22cc};call_sites={0x2aeb,0x2b15,0x2b2d};excluded={0x227f,0x2281,0x2283,0x2286,0x2288,0x228a,0x228f,0x2291,0x2294,0x2297,0x229f,0x22a2,0x22a5,0x22a7,0x22aa,0x22ac,0x22af,0x22b2,0x22b4,0x22b7,0x22ba,0x22bd,0x22bf};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def signature(vector,site,segment,ss,sp,r):return [vector,site,segment,ss,sp,*values(r.registers),r.bp,r.carry]
  def response(incoming,site,seq):
   profile,pattern=active['profile'],active['pattern'];fail=(site==0x2286 and pattern==1) or (site==0x22aa and pattern==2) or (site==0x22cc and pattern in [1,3]);ax=[1,0x13,0x20,0x21,0x22,0x8000,0xff01][profile%7] if fail else 0 if pattern==3 else 1000 if site in [0x2286,0x22aa] else 0x500;dx=0 if site in [0x2286,0x22aa] else 0xd00d;bp=0xd000 if (profile>>3)&1 else incoming.bp;ret_ds=ds+0x100 if (profile>>2)&1 else ds;r=StateRegisters(Registers(ax,0xfff1 if (profile>>4)&1 else 0xbada,0x1f if pattern==2 else 0,dx,incoming.registers.si if profile&2 else 0x1234,0x4321,ret_ds,0x2468,1-incoming.registers.interrupts_enabled,1-incoming.registers.direction),bp,int(fail));writes=[]
   if (profile>>4)&1:writes.append((active['ss']*16+((bp+8)&65535),struct.pack('<H',(profile*257+seq)&65535)))
   return r,writes
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Seekescaped '+hex(address))
   if ip in [0x2b0b,0x2b3f,0x943,0x973]:active['return_kind']='mapper' if ip==0x973 else 'seek' if ip==0x943 else 'root';u.emu_stop();return
   if ip in call_sites:
    if active['calls']==active['limit']:active['prefix']='outer';u.emu_stop();return
    active['calls']+=1;active['child_services']=0;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip in int_sites and active['child_services']==active['child_limit']:active['prefix']='inner';u.emu_stop();return
   if ip==0x939:active['error_calls']+=1;active['mapper_sp']=u.reg_read(UC_X86_REG_SP)
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(cpu,number,unused):
   active['child_services']+=1;site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site in int_sites,'OnlyDOS42');r=state(u);require(r.registers.ax>>8==0x42,'DOS42AH');active['requests'].append(signature(number,site,cs,active['ss'],u.reg_read(UC_X86_REG_SP),r));returned,writes=response(r,site,len(active['requests']))
   for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
   for at,data in writes:u.mem_write(at,data);active['service_write_events']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(32),[0,1],[2,0x603],[48,0xe000,0x6da4],[0,1,3],[0,1,3],range(4)));cases +=[(seed,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,3,3,seed%4) for seed in range(10000,11000)]
  cases +=[(profile,same,flags,0x6d95,3,3,pattern) for profile,same,flags,pattern in itertools.product(range(8),[0,1],[2,0x603],range(4))]
  for profile,same,flags,sp,limit,child_limit,pattern in cases:
   rng=random.Random(0x225e0000+profile);data=bytearray(base);ss=ds if same else 0x9000;handle=[0,19,20,0xffff][profile%4];offset=[0,1,0xffff,0xffffffff,0xffff0000,0x80000000,0x7fffffff,0x8000ffff][profile%8];mode=[0,1,2,3,0x80,0x8000,0xffff,0xff02][(profile//4)%8]
   if profile>=10000:offset=rng.randrange(0x100000000);mode=rng.randrange(65536)
   for segment in [ds,ds+0x100]:
    data[segment*16+0x6d9d]=2+profile%2;struct.pack_into('<H',data,segment*16+0x6da2,20)
    for k in range(20):data[segment*16+0x6dda+k]=(0x80+7*k)&255
   frame=struct.pack('<3H',0x1111,0x2222,handle);data[ss*16+sp:ss*16+sp+len(frame)]=frame;struct.pack_into('<7H',data,ss*16+0xd000,0x7777,0x4444,0x5555,handle,offset&65535,offset>>16,mode);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2ad8),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(calls=0,child_services=0,child_limit=child_limit,profile=profile,pattern=pattern,ss=ss,limit=limit,error_calls=0,writes=0,service_write_events=0,instructions=0,sites=set(),requests=[],executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0x2ad8,0,count=1000);raw=root=False;raw_kind=None;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}/{pattern}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False;active['return_kind']=None
    if kind=='root':root=True;break
    expected=(cs,0x93c,active['mapper_sp']) if kind=='mapper' else (cs,active['site']+5,active['expected_sp'])
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=expected:raw=True;raw_kind=kind;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=1000)
   require(active['prefix'] or raw or root,'Outcome '+label);native_requests=[]
   @Service
   def callback(context,memory,request,out):
    q=request.contents;r=q.incoming;native_requests.append(signature(q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,r));returned,writes=response(r,q.site,len(native_requests));out[0]=returned
    for at,chunk in writes:
     for k,v in enumerate(chunk):memory[at+k]=v
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),callback,None,limit,child_limit,C.byref(out));require((out.status,out.current_sp,out.calls,out.services,out.error_calls,out.bus_writes)==(3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['calls'],len(active['requests']),active['error_calls'],active['writes']),'Status/count '+label);require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_nested_return' if raw else 'root_far_return']+=1;coverage['raw_root_returns']+=int(root and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['syntheticDOSservices']+=out.services;coverage['actual_error_calls']+=out.error_calls;coverage['bus_write_events']+=out.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['minimumSP48_cases']+=int(sp==48);coverage['actual_far_CALLs']+=out.calls;coverage['DS_equals_SS_cases']+=same
   if raw:coverage['raw_'+raw_kind+'_return']+=1
   for request in active['requests']:coverage[f'DOS_site_{request[1]:04X}']+=1
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-excluded and coverage['raw_root_returns']>0,'Coverage '+str((fence-sites,dict(coverage))));records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[r['id'] for r in records if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x2ad8 for e in r['entries'])];require(len(ids)==1,'ID');record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_seek_parent.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_close_handle.py','tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_excluded_sites':[f'13A8:{ip:04X}' for ip in sorted(excluded)],'fixture_coverage':dict(coverage),'limits':'Actual2AD8 oneSSword plus actual225E/094A, threefarCALLpools/twolayersactualSSlocals/saves/near-farframes/fullbus/GPR/BP/CFIFDF/control/writecount. SyntheticDOS42fullreturnedstate/busmutations/SS-SP-CS preserved, actualINTentryframes omitted. Rawmode/negativeoffset/query/end/restore/finalseek andignoredCF sourcepaths, unsignedhandlelimit/returnedDS-BXbyteflagclear retained. NativebeforeINT/adapterfailure/rawreturns distinct fromoriginalerrors/normalreturns, targetsexposedafterRET neverfollowed. Parentfirst-current(1)/second-end(2) pools havezerooffset; thirdrestore(0) rawsavedposition resultignored. Thuschildnegativequery/end/restorepreflight23sites unreachablefromtheseparentpools, notglobaldead. Actualcaller/record-handlewriters/capacity/lifetime/IRQ/core/actualDOS/resource/device/session/gameplay/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
