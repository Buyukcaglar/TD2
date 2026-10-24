"""Compare C17 RAM plane writes/nonlocal continuation and D01 far-call ABI."""
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['site','segment','offset','stack_segment','stack_sp']]+[('arguments',C.c_uint16*5),('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_ip']]+[('writes',C.c_uint32),('calls',C.c_uint32),('returned',StateRegisters)]


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_plane_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.POINTER(Result)];fn.restype=None
 graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:0C17','06C9:0D01']];require(len(fenced)==2,'Twoentryfence');ips={ip for f in fenced for ip in f['instructions'] if 0xc17<=ip<=0xd12};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];bounds=[0,1,7,8,9,79,80,81,0x7fff,0x8000,0xffff];oldbounds=[0,1,7,8,79,80,0x7fff,0x8000,0xffff];cases=list(itertools.product([0],bounds,oldbounds,range(8),[2,0x203,0x402,0x603]));cases+=list(itertools.product([1],bounds,oldbounds,range(4),[2,0x203,0x402,0x603]));vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes([0x5a])*65536;active={}
  def read_regs():
   f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
  def code(cpu,address,size,_):
   if active['jump_pending']:
    require(address==cs*16+active['target'],'Actual JMPtarget');active['jumped']=True;u.emu_stop();return
   if active['expect_leaf'] and address==cs*16+0x8582:
    current=u.reg_read(UC_X86_REG_SP);require(current==sp-14 and bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',0xd0f,cs),'D01farframe');args=struct.unpack('<5H',u.mem_read(active['ss']*16+current+4,10));active['pending']=Request(0xd0a,cs,0x8582,active['ss'],current,(C.c_uint16*5)(*args),read_regs());active['expect_leaf']=False;u.emu_stop();return
   ip=address-cs*16;
   require(ip in ips,'Spanescapedfence '+hex(address));active['instructions']+=1;active['sites'].add(ip)
   if ip==0xcfd:active['jump_pending']=True;active['target']=struct.unpack('<H',u.mem_read(u.reg_read(UC_X86_REG_DS)*16+0x702,2))[0]
   if ip==0xd0a:active['expect_leaf']=True
  def write(cpu,access,address,size,value,_):
   active['write_ips'][hex(u.reg_read(UC_X86_REG_IP))]+=1
   if u.reg_read(UC_X86_REG_IP) in [0xc7d,0xc80,0xc87,0xc8a,0xc91,0xc94,0xc9b,0xc9e,0xcb5,0xcc1,0xccd,0xcd9]:active['writes']+=1
  def interrupt(*_):raise RuntimeError('Unexpectedinterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INTR,interrupt)
  for entry,value,previous,profile,flags in cases:
   data=bytearray(base);ss=ds if vectors&1 else 0x9000
   def put(at,v):struct.pack_into('<H',data,ds*16+(at&65535),v&65535)
   di=[0,1,0x5420,0x8ae,0x9be,0x9c0,0xffff,0x5438][profile];planes=[0x5000,0x6000,0x7000,0x8000]
   if profile>=2:planes=[ds,ds,ds,ds]
   if profile in [2,7] and entry==0:value,previous=8,0
   for i,v in enumerate(planes):put(0x5420+2*i,v)
   for row in range(4):
    for i in range(16):data[ds*16+0x5428+row*16+i]=(i*17+row*37+profile*11)&255
   for i in range(8):data[ds*16+0x5468+i]=[0xff,0x7f,0x3f,0x1f,0x0f,7,3,1][i]
   put(0x9be,profile if profile<7 else 0xffff);put(0x9c0,previous);put(0x5348,value if profile&1 else value^1);put(0x702,[0xb7b,0x28bd,0x1234,0xffff][profile%4]);frame=struct.pack('<H',0x100);data[ss*16+sp-32:ss*16+sp+6]=b'\xa5'*32+frame+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(value,0xfff0|profile,0xc456,previous,0x3456,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);entryip=0xc17 if entry==0 else 0xd01
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entryip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   def event(q):return [q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,list(q.arguments),values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
   def service(events,write,q):
    events.append(event(q));r=StateRegisters(Registers(*values(q.incoming.registers)),0x8123,1);r.registers.ax=0xa123;r.registers.bx=0xb234;r.registers.cx=0xc345;r.registers.dx=0xd456;r.registers.si=0xe567;r.registers.di=0xf678;r.registers.es=0x6000;r.registers.interrupts_enabled=profile&1;r.registers.direction=(profile>>1)&1;write(0x80000,struct.pack('<H',q.site));return r
   active.update(ss=ss,pending=None,expect_leaf=False,jump_pending=False,jumped=False,instructions=0,writes=0,write_ips=Counter(),sites=set(),events=[]);u.emu_start(cs*16+entryip,cs*16+0x100,count=10000)
   if active['pending']:
    q=active['pending'];r=service(active['events'],lambda at,b:u.mem_write(at,b),q);rr=r.registers
    for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xd0f),(UC_X86_REG_SP,sp-10),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
    u.emu_start(cs*16+0xd0f,cs*16+0x100,count=64)
   label=f'{load:x}/{entry}/{value:x}/{previous:x}/{profile}/{flags:x}';require(u.reg_read(UC_X86_REG_SP)==sp+2 and (active['jumped'] or u.reg_read(UC_X86_REG_IP)==0x100),'Originalreturn-or-jump '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:returned=service(events,lambda at,b:C.memmove(C.byref(bus,at),b,len(b)),q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,C.byref(out));require(not errors and out.status==int(active['jumped']) and out.current_sp==sp+2 and out.calls==len(events) and events==active['events'] and out.writes==active['writes'],'Nativeoutcome/frame/plane-writes '+label+str(errors)+str((out.status,active['jumped'],out.current_sp,out.calls,len(events),out.writes,active['writes'],events==active['events'],dict(active['write_ips']))));require(not active['jumped'] or out.next_ip==active['target'],'Rawdynamiccontinuation '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Fullnonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearframeguard '+label);coverage['D01' if entry else 'C17']+=1;coverage['near_jump' if active['jumped'] else 'near_return']+=1;coverage['plane_writes']+=out.writes;coverage['far_8582_calls']+=out.calls;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 missing=sorted(ips-sites);require(not missing,'Allbodylocations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000076','FN-EGA-000077'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_plane_span.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'ActualC17body throughnearRET ordiscardnearreturn/JMPDS0702 boundary, currentDS palette/plane words andSSBPmask andorderedmasked/REPbytewrites, unsignedCLcount/truncatedCH/signedSAR/DF/aliases/16bitDIwrap, GPR/BP/CFIFDF compared. D01actualbody withfar8582ordinaryreturnABImock/5words/callerADDSP10. SyntheticRAMplanes noEGAhardware/renderer, dynamiccontinuationtarget value notwriterdomain/reachability proof. LiveSSframes separate; no actualcaller/producer/capacity/resource/IRQ/core/game/fidelity. Native diagnostics separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
