"""Compare8582 clipping, RAM planes and explicit synthetic OUT/device traces."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *


class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['kind','site','segment','offset','stack_segment','stack_sp','port','value']]+[('arguments',C.c_uint16*5),('address',C.c_uint32),('incoming',StateRegisters)]


class Response(C.Structure):
 _fields_=[('returned',StateRegisters),('value',C.c_uint16)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Response))


class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','fault_site','current_sp']]+[(n,C.c_uint32) for n in ['work','iterations','calls','writes']]+[('returned',StateRegisters)]


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_line_draw;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in g['functions'] if f['entry']=='06C9:8582');ips=set(f['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];heads={0x874d,0x877d,0x87b6,0x883a,0x88af,0x8936};outs={0x882b,0x882f,0x8835,0x8839,0x8872,0x8876,0x8894,0x8898,0x889e,0x88a2,0x8927,0x892b,0x8931,0x8935,0x896e,0x8972,0x8990,0x8994,0x899a,0x899e};reads={0x887a,0x8976};writes={0x887d,0x8979};ramwrites={0x87ff,0x8807,0x88f8,0x8901};far={0x8611:0x8616,0x867b:0x8680};sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();points=[(-8,-4),(-8,0),(0,-4),(0,0),(0,1),(1,0),(1,1),(7,3),(7,16),(8,7),(17,16),(17,31),(79,31),(80,32),(0xffff,0x8000),(0x7fff,0x7fff),(0x8000,0xffff)];clips=[(0,10,0,32),(1,9,1,31),(0xffff,10,0xffff,32),(10,0,32,0)];cases=[(p1,p2,mode,clip,4096) for p1,p2,mode,clip in itertools.product(points,points,range(4),range(4))];cases +=[(p1,p2,mode,0,budget) for p1,p2,mode,budget in itertools.product([(0,0),(1,1),(7,3)],[(17,16),(79,31),(7,3)],range(4),[0,1,2,4,8,16,32])]
 cases +=[(p1,p2,mode,clip,4096) for p1,p2 in [((17,31),(100,31)),((100,31),(17,31)),((0,31),(100,31))] for mode,clip in itertools.product(range(4),range(4))]
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;active={};u=None
  def read_regs():
   flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
  def event(q):return [q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,q.port,q.value,list(q.arguments),q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
  def request(kind,site,args=None):
   rr=read_regs();physical=((rr.registers.es<<4)+rr.registers.di)&0xfffff if kind in [2,3] else 0;value=(bytes(u.mem_read(physical,1))[0] if kind==2 else rr.registers.ax&255 if kind in [1,3] else 0);return Request(kind,site,cs,0x8a0c if kind==0 else 0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.registers.dx,value,(C.c_uint16*5)(*(args or [0]*5)),physical,rr)
  def tick(iteration):
   if active['work']==active['budget']:active['prefix']=True;u.emu_stop();return False
   active['work']+=1;active['iterations']+=int(iteration);return True
  def code(cpu,address,size,_):
   if active['expected'] and address==cs*16+0x8a0c:
    site,ret=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(current==sp-38 and bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Original8A0Cfarframe');args=struct.unpack('<5H',u.mem_read(active['ss']*16+current+4,10));q=request(0,site,list(args));active['pending']=(q,ret);active['expected']=None;u.emu_stop();return
   ip=address-cs*16;require(ip in ips,'Lineescapedfence '+hex(address))
   if ip in heads and not tick(True):return
   if ip in outs|reads|writes|far.keys():
    if not tick(False):return
    if ip in far:active['expected']=(ip,far[ip])
    else:
     q=request(1 if ip in outs else 2 if ip in reads else 3,ip);active['events'].append(event(q))
   if ip in [0x86eb,0x8730]:active['pre_divide_flags']=u.reg_read(UC_X86_REG_EFLAGS)
   active['instructions']+=1;active['sites'].add(ip)
  def memory_write(cpu,access,address,size,value,_):
   if u.reg_read(UC_X86_REG_IP) in ramwrites|writes:active['writes']+=1
  def out_hook(cpu,port,size,value,_):
   require(size==1 and port in [0x3ce,0x3cf,0x3c4,0x3c5] and active['events'][-1][6:8]==[port,value],'ActualOUTbyteevent');active['outs']+=1
  def interrupt(cpu,num,_):
   require(num==0 and u.reg_read(UC_X86_REG_IP) in [0x86eb,0x8730],'ActualDIVfaultonly');active['fault']=u.reg_read(UC_X86_REG_IP);u.emu_stop()
  for p1,p2,mode,clip,budget in cases:
   if u is None:u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,memory_write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,out_hook,None,1,0,UC_X86_INS_OUT)
   data=bytearray(base);ss=ds if vectors&1 else 0x9000;planes=[0x5000,0x6000,0x7000,0x8000] if mode==0 else [0,0x6000,0,0x8000] if mode==1 else [0xa000,0,0,0] if mode==2 else [ds]*4
   for i,v in enumerate(planes):struct.pack_into('<H',data,cs*16+0xaf3c+2*i,v)
   struct.pack_into('<H',data,cs*16+0xaf44,0xb000)
   for i,v in enumerate(clips[clip]):struct.pack_into('<H',data,cs*16+0xaf46+2*i,v&65535)
   for i in range(8):data[cs*16+0x857a+i]=128>>i
   for y in range(-64,128):struct.pack_into('<H',data,cs*16+((0xb000+2*y)&65535),(0x200+32*y)&65535)
   color=[0,1,15,0xffff][(vectors//8)%4];args=[p1[0]&65535,p1[1]&65535,p2[0]&65535,p2[1]&65535,color];frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+18]=b'\xa5'*64+frame+struct.pack('<5H',*args)+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x8582),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   def far_service(q):
    r=StateRegisters(Registers(*values(q.incoming.registers)),0x8123,1);rr=r.registers;rr.ax=0xa123;rr.bx=0xb234;rr.cx=0xc345;rr.dx=0xd456;rr.si=0xe567;rr.di=0xf678;rr.ds=0x5000;rr.es=0x6000;rr.interrupts_enabled=mode&1;rr.direction=(mode>>1)&1;return r
   active.update(ss=ss,budget=budget,work=0,iterations=0,writes=0,outs=0,expected=None,pending=None,prefix=False,fault=0,events=[],instructions=0,sites=set());u.emu_start(cs*16+0x8582,0x11210,count=1000000)
   if active['pending']:
    q,ret=active['pending'];active['pending']=None;active['events'].append(event(q));r=far_service(q);rr=r.registers
    for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+4),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
    u.emu_start(cs*16+ret,0x11210,count=128)
   label=f'{load:x}/{p1}/{p2}/{mode}/{clip}/{budget}';require(active['fault'] or active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'OriginalRETF/fault/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:
     q=q.contents;events.append(event(q))
     if q.kind==0:returned=far_service(q);C.memmove(C.byref(r.contents.returned),C.byref(returned),C.sizeof(returned))
     elif q.kind==2:r.contents.value=bus[q.address]
     elif q.kind==3:bus[q.address]=q.value
     return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(1 if active['fault'] else 3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.fault_site==active['fault'] and (out.work,out.iterations,out.calls,out.writes)==(active['work'],active['iterations'],len(active['events']),active['writes']) and events==active['events'],'Nativeoutcome/work/events '+label+str(errors)+str((out.status,out.work,out.iterations,out.calls,out.writes,active['work'],active['iterations'],len(active['events']),active['writes'])));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Fullnonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8],u.reg_read(UC_X86_REG_BP),r.bp)));f=u.reg_read(UC_X86_REG_EFLAGS);cf=active['pre_divide_flags']&1 if active['fault'] else f&1;require((cf,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF/preDIVCF '+label);require(bytes(u.mem_read(ss*16+sp,18))==frame+struct.pack('<5H',*args)+b'\xa5'*4,'Farrootframe/argsguard '+label);coverage['fault' if active['fault'] else 'prefix' if active['prefix'] else 'normal']+=1;coverage['far_8A0C_calls']+=sum(e[0]==0 for e in events);coverage['OUT_bytes']+=active['outs'];coverage['device_reads']+=sum(e[0]==2 for e in events);coverage['device_writes']+=sum(e[0]==3 for e in events);coverage['plane_writes']+=out.writes;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
   if active['fault']:u=None
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 missing=sorted(ips-sites);require(not missing,'Unexercisedlineinstructionlocations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_id':'FN-EGA-000217','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_line_draw.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'Actual8582body/SSargs andvirtualframeprofile/DS=CS/restoreDS-SI-DI-BP/plainRETF4, horizontalverticalfar8A0C ABI mocks, generalfixedpoint/unsignedDIVfaultprefixes/CLIP/RAMplane orderedmaskedwrites andexplicitOUT/MMIOread-write trace matched. SyntheticflatRAM/devicebus adapter only, no actualEGAsemantics/renderer/device/IRQ/session/callerbounds/resourceformat/core/game/fidelity. Workbudgetnativeprefix separate; DIVCFpreinstructiononly/freshCPUafterfault, no postDIVarithmeticflags. Native diagnostics separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
