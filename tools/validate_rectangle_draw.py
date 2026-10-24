"""Compare clipped/raw rectangle code, mutable SS args and synthetic device bus."""
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
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,receipt_path=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and receipt_path.is_relative_to(ROOT/'docs/recovery/evidence') and not receipt_path.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_rectangle_draw;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fs=[f for f in g['functions'] if f['entry'] in ['06C9:89A2','06C9:8A0C']];require(len(fs)==2,'Twosharedbodyentries');ips={ip for f in fs for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];heads={0x8a92,0x8aa5,0x8abc,0x8ad3,0x8ae6,0x8afe,0x8b0f,0x8b26,0x8b49,0x8b97,0x8bd7,0x8bfa,0x8c1e,0x8c44,0x8c66,0x8c69};reps={0x8b2d,0x8b50};outs={0x8b66,0x8b6a,0x8b70,0x8b74,0x8b84,0x8b88,0x8ba6,0x8baa,0x8bb0,0x8bb4,0x8bc4,0x8bc8,0x8be6,0x8bea,0x8c0b,0x8c0f,0x8c2d,0x8c31,0x8c53,0x8c57};reads={0x8b97,0x8bd7,0x8bfa,0x8c1e,0x8c44,0x8c69};device_writes={0x8b9a,0x8bda,0x8bfd,0x8c21,0x8c47,0x8c6c};ram_writes={0x8aa5,0x8abc,0x8ae6,0x8aea,0x8afe,0x8b02,0x8b26,0x8b2d,0x8b2f,0x8b49,0x8b50,0x8b52};xs=[0xffff,0,1,7,8,17,79,80];widths=[0,1,2,8,9,16,17,80,0x7fff,0x8000,0xffff];clips=[(0,10,0,32),(1,9,1,31),(10,0,32,0),(0xffff,10,0xffff,32)];cases=[(entry,mode,x,[0,1,31,32][widths.index(w)%4],w,h,clip,4096) for entry,mode,x,w,h,clip in itertools.product([0,1],range(4),xs,widths,[0,1,2,0x8000],range(3))];cases +=[(entry,mode,1,0,17,h,0,64) for entry,mode,h in itertools.product([0,1],range(4),[33,0x7fff,0xffff])];cases +=[(entry,mode,1,1,w,2,0,budget) for entry,mode,w,budget in itertools.product([0,1],range(4),[1,9,17],[0,1,2,4,8,16,32])];cases +=[(entry,mode,0xffff,0xffff,w,2,3,256) for entry,mode,w in itertools.product([0,1],range(4),[1,9,17])];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def read_regs():
   f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
  def event(q):return [q.kind,q.site,q.segment,q.offset,q.stack_segment,q.stack_sp,q.port,q.value,list(q.arguments),q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
  def tick():
   if active['work']==active['budget']:active['prefix']=True;u.emu_stop();return False
   active['work']+=1;return True
  def code(cpu,address,size,_):
   ip=address-cs*16;require(ip in ips,'Rectangleescapedfence '+hex(address))
   if ip in heads or (ip in reps and u.reg_read(UC_X86_REG_CX)!=0):
    if not tick():return
    active['iterations']+=1
   if ip in outs|reads|device_writes:
    if not tick():return
    rr=read_regs();kind=1 if ip in outs else 2 if ip in reads else 3;physical=((rr.registers.es<<4)+rr.registers.di)&65535 if False else ((rr.registers.es<<4)+rr.registers.di)&0xfffff if kind!=1 else 0;v=bytes(u.mem_read(physical,1))[0] if kind==2 else rr.registers.ax&255;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.registers.dx,v,(C.c_uint16*5)(),physical,rr);active['events'].append(event(q))
   active['instructions']+=1;active['sites'].add(ip)
  def memory_write(cpu,access,address,size,value,_):
   if u.reg_read(UC_X86_REG_IP) in ram_writes|device_writes:active['writes']+=1
  def out_hook(cpu,port,size,value,_):
   require(size==1 and active['events'][-1][6:8]==[port,value],'ActualOUTtrace');active['outs']+=1
  def interrupt(*_):raise RuntimeError('Unexpectedrectangleinterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,memory_write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,out_hook,None,1,0,UC_X86_INS_OUT)
  for entry,mode,x,y,w,h,clip,budget in cases:
   data=bytearray(base);ss=ds if vectors&1 else 0x9000;planes=[0x5000,0x6000,0x7000,0x8000] if mode==0 else [0,0x6000,0,0x8000] if mode==1 else [0xa000,0,0,0] if mode==2 else [ds]*4
   for i,v in enumerate(planes):struct.pack_into('<H',data,cs*16+0xaf3c+2*i,v)
   struct.pack_into('<H',data,cs*16+0xaf44,0xb000);struct.pack_into('<H',data,cs*16+0xaf4e,32)
   for i,v in enumerate(clips[clip]):struct.pack_into('<H',data,cs*16+0xaf46+2*i,v&65535)
   for i in range(8):data[ds*16+0x6838+i]=255>>i;data[ds*16+0x6840+i]=(255<<(7-i))&255
   for row in range(-32,65):struct.pack_into('<H',data,cs*16+((0xb000+2*row)&65535),(0x200+32*row)&65535)
   color=[0x5a00,0x5a01,0x5a0f,0xffff][(vectors//8)%4];args=[x,y,w,h,color];frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-32:ss*16+sp+18]=b'\xa5'*32+frame+struct.pack('<5H',*args)+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);entry_ip=0x89a2 if entry==0 else 0x8a0c
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry_ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   active.update(ss=ss,budget=budget,work=0,iterations=0,writes=0,outs=0,prefix=False,events=[],instructions=0,sites=set());u.emu_start(cs*16+entry_ip,0x11210,count=1000000);label=f'{load:x}/{entry}/{mode}/{x:x}/{y:x}/{w:x}/{h:x}/{clip}/{budget}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'OriginalRETF/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:
     q=q.contents;events.append(event(q));require(q.kind in [1,2,3],'Onlybytebusservices')
     if q.kind==2:r.contents.value=bus[q.address]
     elif q.kind==3:bus[q.address]=q.value
     return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.fault_site==0 and (out.work,out.iterations,out.calls,out.writes)==(active['work'],active['iterations'],len(active['events']),active['writes']) and events==active['events'],'Nativework/outcome/events '+label+str(errors)+str((out.status,out.work,out.iterations,out.calls,out.writes,active['work'],active['iterations'],len(active['events']),active['writes'])));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Fullnonframebusincludingcallerargs '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,4))==frame and bytes(u.mem_read(ss*16+sp+14,4))==b'\xa5'*4,'Farframe/argumentendguard '+label);coverage['clipped' if entry==0 else 'raw']+=1;coverage['prefix' if active['prefix'] else 'normal']+=1;coverage['OUT_bytes']+=active['outs'];coverage['device_reads']+=sum(e[0]==2 for e in events);coverage['device_writes']+=sum(e[0]==3 for e in events);coverage['plane_writes']+=out.writes;coverage['caller_arg_mutations']+=bytes(bus[ss*16+sp+4:ss*16+sp+14])!=struct.pack('<5H',*args);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 missing=sorted(ips-sites);require(not missing,'Unexercisedrectanglelocations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000218','FN-EGA-000219'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_rectangle_draw.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'Actual89A2clipping+8A0Csharedbody/plainRETF4, SSargumentmutationsincludingwideRAMcolorbyteSHR/highbytepreservation, DS6838/6840masks/currentCSlookup-plane-stride/RAMmasked-REPbytewrites andexplicitOUT/MMIOread/write/STOSBtraces matched. ClippedearlyDFversusrawCLD, REP0/LOOP0/rawword/SAR/signedOFbranches andnativeworkprefix retained. SyntheticflatRAM/devicebus only, no actualEGAdevice/renderer/producer/caller/local-framebounds/resourcefed/IRQ/state/core/game/fidelity. Native diagnostics separate.'};receipt_path.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
