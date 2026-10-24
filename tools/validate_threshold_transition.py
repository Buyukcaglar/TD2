"""Compare4B9A signed thresholds/interpolation/pre-IDIV fault prefixes/actual45FC-fullSS."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Limits(C.Structure):_fields_=[('rows',C.c_uint32),('control_calls',C.c_uint32)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['rows','control_calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def signed(v,bits=16):return v if v<1<<(bits-1) else v-(1<<bits)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_threshold_transition;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];require(C.sizeof(Result)==48 and C.sizeof(Limits)==8,'Layout');gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());fs=[f for f in g['functions'] if f['entry'] in ['06C9:4B9A','06C9:45FC','06C9:4612']];fence={ip for f in fs for ip in f['instructions']};require(len(fence)==108,'Fence');returns={ip for ip in fence if image[0x6c90+ip]==0xc3};root_returns={ip for f in fs if f['entry']=='06C9:4B9A' for ip in f['instructions'] if image[0x6c90+ip]==0xc3};vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in returns:active['return']=ip;u.emu_stop();return
   if ip==0x4c3e:
    if active['rows']==active['limits'].rows:active['prefix']='rows';u.emu_stop();return
    if active['rows']==8192 and u.reg_read(UC_X86_REG_SI)==0:active['index_wrapped']=True
    active['rows']+=1
   if ip==0x4c81:active['frames'].append((0x4c84,u.reg_read(UC_X86_REG_SP),'control'));active['outer_calls']+=1
   if ip==0x460e:
    if active['control_calls']==active['limits'].control_calls:active['prefix']='control';u.emu_stop();return
    active['control_calls']+=1;active['frames'].append((0x4611,u.reg_read(UC_X86_REG_SP),'product'))
   if ip==0x4c68:
    numerator=signed((u.reg_read(UC_X86_REG_DX)<<16)|u.reg_read(UC_X86_REG_AX),32);denominator=signed(u.reg_read(UC_X86_REG_BP));quotient=0 if denominator==0 else abs(numerator)//abs(denominator)*(-1 if (numerator<0)!=(denominator<0) else 1)
    if denominator==0 or not -32768<=quotient<=32767:active['fault']='zero' if denominator==0 else 'overflow';u.emu_stop();return
    active['divides']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written)
  def case(**kw):
   c=dict(direction=0,mode=0,min=0,max=1000,x=1,table=[],rows=4,control=2000,multiplier=0x8000,selector=1,control_calls=1,same=False,sp=0xe000,flags=2,long=False);c.update(kw);return c
  bounds=[(0,0),(0,1000),(0xfc18,0),(0xfc18,1000),(0x7fff,0x7fff),(0x8000,0x8000)]
  cases=[case(direction=direction,mode=mode,min=minimum,max=maximum,same=same,flags=flags) for direction,mode,(minimum,maximum),same,flags in itertools.product([0,0x8000],range(256),bounds,[False,True],[2,0x603])]
  tables=[[],[(1,10,0,100)],[(100,200,300,500)],[(100,100,0,1)],[(1,0x8001,0,100)],[(1,0xffff,0,32767)],[(1,0xffff,0,0x8000)],[(1,2,0x8000,0x7fff)],[(1,2,0,10),(3,10,10,100),(11,100,100,200)]]
  cases += [case(x=x,table=table,min=minimum,same=same,flags=flags) for table,x,minimum,same,flags in itertools.product(tables,[0,1,2,5,9,10,11,50,100,150,200,500,0x7fff,0x8000,0xffff],[0,500,600,0x7fff,0x8000],[False,True],[2,0x603])]
  cases += [case(table=tables[8],x=x,rows=rows,same=same,flags=flags) for x,rows,same,flags in itertools.product([1,8,50,500],[0,1,2,3,4],[False,True],[2,0x603])]
  cases += [case(direction=0x8000,min=0xfc18,control=control,multiplier=mult,selector=selector,control_calls=cap,same=same,flags=flags) for control,mult,selector,cap,same,flags in itertools.product([0,1000,2000,2600,0xffff],[0,0x8000,0xffff],[0,1],[0,1],[False,True],[2,0x603])]
  cases += [case(direction=direction,mode=mode,min=0xfc18,max=1000,table=tables[1],x=5,same=True,sp=sp,flags=flags) for direction,mode,sp,flags in itertools.product([0,0x8000],[0,2,4,0x10,0x20,0x80],[0x3330,0x3332,0x3334,0x3336,0x33b2,0x336f,0x33ce,0x33d0,0x33d2,0x33d4,0x52cc,0x52ce,0x52d0],[2,0x603])]
  cases += [case(ds=ds,direction=direction,mode=mode,min=0xfc18,max=1000,same=same,sp=sp,flags=flags) for ds,direction,mode,same,sp,flags in itertools.product([0,0xffff],[0,0x8000],[0,4,0x80],[False,True],[20,0xffe0],[2,0x603])]
  cases += [case(long=True,rows=8193,x=1,multiplier=0)]
  for c in cases:
   data=bytearray(base);ds=c.get('ds',principal);ss=ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags']
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   def wb(sg,o,v):data[((sg<<4)+(o&65535))&0xfffff]=v&255
   if c['long']:
    for i in range(8192):put(ds,0x37a6+8*i,1);put(ds,0x37a8+8*i,0)
   else:
    for i,row in enumerate(c['table']+[(0,0,0,0)]):
     for j,v in enumerate(row):put(ds,0x37a6+8*i+2*j,v)
   for o,v in [(0x3332,c['direction']),(0x3334,c['min']),(0x3336,c['max']),(0x52ca,0x3b33+c['x']),(0x52ce,c['control']),(0x3328,c['multiplier']),(0x332c,0x1234)]:put(ds,o,v)
   wb(ds,0x5491,c['mode']);wb(ds,0x2f56,c['selector']);put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);limits=Limits(c['rows'],c['control_calls']);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x4b9a),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limits=limits,rows=0,control_calls=0,outer_calls=0,divides=0,index_wrapped=False,frames=[],writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,fault=False,**{'return':False});label=f'{load:x}/{ds:x}/'+str(c);u.emu_start(cs*16+0x4b9a,0,count=200000);root=raw=False;raw_kind=''
   while active['return']:
    ip=active['return'];active['return']=False;active['sites'].add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip in root_returns:require(not active['frames'],'Rootframe '+label);root=True;break
    nextip,nextsp,kind=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,nextip,nextsp):raw=True;raw_kind=kind;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=200000)
   require(root or raw or active['prefix'] or active['fault'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(limits),C.byref(r));status=0 if root else 1 if raw else 4 if active['fault'] else 3;require((r.status,r.current_sp,r.rows,r.control_calls,r.bus_writes)==(status,u.reg_read(UC_X86_REG_SP),active['rows'],active['control_calls'],active['writes']),'Status/counters '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);require((r.flags_valid,r.zero_flag)==(int(root),(ef>>6)&1 if root else 0),'RequiredZF '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_near_return' if root else 'raw_'+raw_kind+'_return' if raw else 'fault_'+active['fault'] if active['fault'] else 'prefix_'+active['prefix']]+=1;coverage['table_row_heads']+=r.rows;coverage['outer_45FC_CALLs']+=active['outer_calls'];coverage['control_4612_CALLs']+=r.control_calls;coverage['completed_IDIVs']+=active['divides'];coverage['CPU_bus_writes']+=r.bus_writes;coverage['DS_equals_SS_cases']+=int(ss==ds);coverage['raw_root_returns']+=int(root and r.next_ip!=0x1111);coverage['full_index_wrap_scans']+=int(active['index_wrapped'])
   if c['long']:require(r.status==3 and r.rows==8193 and r.returned.registers.si==8 and active['index_wrapped'],'ActualfullSIcycle '+label)
   coverage['normal_BP_changed']+=int(root and r.returned.bp!=incoming.bp)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites)}),flush=True)
 require(sites==fence and coverage['fault_zero']>0 and coverage['fault_overflow']>0 and coverage['full_index_wrap_scans']==2 and coverage['normal_BP_changed']>0,'Coverage '+str([f'{ip:04X}' for ip in sorted(fence-sites)]));f=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];id=next(v['id'] for v in f if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x4b9a for e in v['entries']));deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':[id],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_threshold_transition.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual4B9A/fullSS/currentDSsignedthresholds/orderedstatewrites/indexed8byte-rawrows/wordSIwrap/signedIMUL-IDIV-truncation/zero-overflowpreIDIVprefix/noexceptiondelivery/actual45FC-4612-globalrow-controlbudgets/wholebus-GPR-BP-CFIFDF-rootZF/control/counts. Actual48A8caller/full4674/alltablewriters-validbounds-units-storage-lifetime-IRQ-core open. NoDOSsession/device/audio/fullresourcecodec/complete-state-machine/gameplay/fidelity acceptance. Physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
