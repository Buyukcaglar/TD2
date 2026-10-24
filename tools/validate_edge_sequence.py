"""Compare34DC prepared5word pools and ordinary far8582 ABI effects."""
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
from validate_draw_sequence import Registers,StateRegisters,Request,Service,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_edge_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in g['functions'] if f['entry']=='06C9:34DC');ips=set(f['instructions']);call_sites={int(c['site'][5:],16):int(c['site'][5:],16)+c['size'] for c in f['calls']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];bounds=[0,1,7,8,80,0x7fff,0x8000,0xffff];selectors=[0,2,48,0x8000,0xfffe,0xffff,0xd496,0xd5a2];cases=[(flag,v,p,3) for flag,v,p in itertools.product(range(256),bounds,range(3))]+list(itertools.product([0,1],bounds,range(3),[0,1,2]));vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes((i*37+11)&255 for i in range(65536));active={}
  def read_regs():
   f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
  def event(q):return [q.kind,q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
  def code(cpu,address,size,_):
   if active['expected'] and address==cs*16+0x8582:
    site,ret=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Originalfarframe');live=(sp-current-4)//2;require(live in [5,10,15],'Preparedpool');args=struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+4,live*2));active['pending']=Request(1,site,cs,0x8582,5,live,active['ss'],current,(C.c_uint16*16)(*(list(args)+[0]*(16-live))),read_regs());active['expected']=None;u.emu_stop();return
   ip=address-cs*16;require(ip in ips,'Edgeescapedfence')
   if ip in call_sites:
    if len(active['events'])==active['budget']:active['prefix']=True;u.emu_stop();return
    active['expected']=(ip,call_sites[ip])
   active['instructions']+=1;active['sites'].add(ip)
  def interrupt(*_):raise RuntimeError('Unexpectedinterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
  for flag,value,profile,budget in cases:
   data=bytearray(base);ss=ds if vectors&1 else 0x9000;si=selectors[(bounds.index(value)+profile)%8]
   def put(at,v):struct.pack_into('<H',data,ds*16+(at&65535),v&65535)
   put(si+0x2b26,value);put(si+0x275a,bounds[(bounds.index(value)+3)%8]);put(si+0x2a5e,value^0x5a5a);put(si+0x2ac2,value^0xa5a5);put(0x2c2a,value);data[ds*16+0x37f7]=flag;frame=struct.pack('<H',0x100);data[ss*16+sp-64:ss*16+sp+6]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,si,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x34dc),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   def service(events,write,q):
    index=len(events)+1;events.append(event(q));r=StateRegisters(Registers(*values(q.incoming.registers)),0x8123+index,index&1);rr=r.registers;rr.ax=0xa000+index;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.si=0xe000+index;rr.di=0xf000+index;rr.es=0x6000;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
    if profile==1:rr.ds=0x5000
    if profile==2 and index==1:write(ds*16+0x37f7,bytes([flag^255]));write(ds*16+((si+0x2a5e)&65535),b'\xad\xde')
    write(0x80000+2*index,struct.pack('<H',q.site));return r
   active.update(ss=ss,budget=budget,expected=None,pending=None,prefix=False,events=[],instructions=0,sites=set());u.emu_start(cs*16+0x34dc,cs*16+0x100,count=128)
   while active['pending']:
    q=active['pending'];active['pending']=None;r=service(active['events'],lambda at,b:u.mem_write(at,b),q);rr=r.registers;ret=call_sites[q.site]
    for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+4),(UC_X86_REG_EFLAGS,2|r.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
    u.emu_start(cs*16+ret,cs*16+0x100,count=128)
   label=f'{load:x}/{flag:x}/{value:x}/{profile}/{budget}';require(active['prefix'] or (u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x100,sp+2),'Originalnearreturn/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:returned=service(events,lambda at,b:C.memmove(C.byref(bus,at),b,len(b)),q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 0) and out.calls==len(events) and events==active['events'] and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.return_bytes==2,'Nativepool/frame/outcome '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Fullnonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearframeguard '+label);coverage['prefix' if active['prefix'] else 'normal']+=1;coverage['far_calls']+=out.calls;coverage['fifteen_live_words']+=sum(e[5]==15 for e in events);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 require(sites==ips,'Everyedgeinstructionlocation');record={'schema':1,'result':'pass','function_id':'FN-EGA-000097','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_edge_sequence.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in ['tools/validate_draw_sequence.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'Complete34DCnearRET body withordinaryfar8582ABImocks, all256flagbytes/currentDSwrappedselectors/unsignedhalfwidthwordmath andtwo-or-threepreprepared5wordpools.15/10/5livewords, source/flagmutationafterfirstcall leavespreparedargs, returnedDS/GPR/BP/CFIFDF andnear-vs-farframes compared. Nativebudgetprefix separate. Actual8582/2958caller/framecapacity/SS-DS/IRQ/resource/renderer/core/game/fidelity remainopen; native diagnostics separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
