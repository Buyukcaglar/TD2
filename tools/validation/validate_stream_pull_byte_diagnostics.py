"""Native0B42 interface, guards, allocator-reader budgets and ordered aliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_stream_pull_byte import Registers,StateRegisters,Request,Limits,BufferLimits,PublicLimits,WalkLimits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_stream_pull_byte;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,0);r=Result();vectors=0;null=Service();limits=Limits(2,8,1,32,BufferLimits(2,PublicLimits(2,WalkLimits(8,128,8,64,1,1,1,32,8))))
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,70,C.byref(s),C.byref(limits)),(bus,len(bus),69,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),70,C.byref(s),C.byref(limits)),(bus,len(bus),70,None,C.byref(limits)),(bus,len(bus),70,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,70,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,70,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(flags=9,channel=0,base=0x3002,ss=0x9000,sp=70):
  C.memset(bus,0,len(bus));limits.calls=2;limits.services=8;limits.read_mapper_calls=1;limits.read_steps=32;limits.buffer.calls=2
  for o,v in [(0x1200,0x4000),(0x1202,7),(0x1204,base),(0x6f26,0x3000),(0x6f28,0x3000),(0x6f2c,16),(0x6f2e,0),(0x6f30,0x2000),(0x6f36,0),(0x3000,0x405),(0x6d2a,16),(0x6d2c,0x2000),(0x6d24,0xffff),(0x6d9b,0x2000),(0x6da2,128)]:put(0x2000,o,v)
  bus[0x21206]=flags;bus[0x21207]=channel;bus[0x26d9d]=3
  idx=6*(channel if channel<128 else channel-256);put(0x2000,0x6e96+idx,4);bus[0x20000+0x6e94+idx]=0
  for i,v in enumerate([0x1111,0x2222,0x1200]):put(ss,sp+2*i,v)
 events=[];payload=b'\xff';error=False;deny=False;invalid=False
 @Service
 def dos(context,memory,request,result):
  q=request.contents;events.append((q.site,q.incoming.registers.ax,q.incoming.registers.cx,q.incoming.registers.dx));ret=StateRegisters.from_buffer_copy(bytes(q.incoming));ret.carry=0
  if q.site==0x24a5:
   ret.registers.ax=1 if error else len(payload);ret.carry=int(error)
   if not error:
    for i,v in enumerate(payload):memory[((q.incoming.registers.ds<<4)+((q.incoming.registers.dx+i)&65535))&0xfffff]=v
  elif q.site==0x2904:ret.carry=0
  else:raise RuntimeError('UnexpectedDOSsite')
  if invalid:ret.carry=2
  result[0]=ret;return int(not deny)
 def run(cb=dos,ss=0x9000,sp=70):
  events.clear();fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 for flag,zf,after in [(0,1,0),(0x41,0,0x41),(2,0,0x22)]:
  reset(flags=flag);run();require((r.status,r.returned.registers.ax,r.returned.carry,r.zero_flag,r.calls,r.bus_writes,bus[0x21206])==(0,0xffff,0,zf,0,3+int(flag==2),after),'Guard-specificZF '+hex(flag));vectors+=1
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ax,r.returned.carry,r.zero_flag,r.flags_valid,word(0x2000,0x1200),word(0x2000,0x1202),r.calls,r.buffer_calls,r.read_calls,r.services)==(0,74,0x2222,0x1111,0x5678,0x3456,0x4567,0xff,0,1,1,0x3003,0,1,0,0,1),'Unsignedbyte/fullSS/plainfarRET');vectors+=1
 payload=b'';reset();run();require((r.status,r.returned.registers.ax,r.zero_flag,bus[0x21206],word(0x2000,0x1202))==(0,0xffff,0,0x19,0),'EOFstreammark');vectors+=1
 payload=b'\xff';error=True;reset();run();require((r.status,r.returned.registers.ax,r.zero_flag,bus[0x21206],word(0x2000,0x6d95),r.read_calls)==(0,0xffff,0,0x29,9,1),'Readerror/actualmapper');vectors+=1;error=False
 reset(channel=128);run();require((r.status,r.returned.registers.ax,r.read_calls,r.services,word(0x2000,0x6d95))==(0,0xffff,1,0,9),'Signedchannelbecomesinvalidunsignedhandle');vectors+=1
 payload=b'\x00';reset(base=0x1200);run();require((r.status,r.returned.registers.ax,word(0x2000,0x1200))==(0,1,0x1201),'CursorINCbeforealiasedbytefetch');vectors+=1;payload=b'\xff'
 reset(flags=1,base=0);run();require((r.status,r.calls,r.buffer_calls,r.returned.registers.ax,word(0x2000,0x1200),events[-1][2:])==(0,2,1,0xff,0x3003,(0x200,0x3002)),'Actualallocator-then-reader/count0200');vectors+=1
 reset(flags=1,base=0);limits.calls=0;run();require((r.status,r.current_sp,r.next_ip,r.calls,r.flags_valid)==(3,62,0xb8f,0,0),'ParentnearCALLbudgetafterargumentPUSH');vectors+=1
 reset(flags=1,base=0);limits.buffer.calls=0;run();require((r.status,r.next_ip,r.calls,r.buffer_calls,r.flags_valid)==(3,0xbf0,1,0,0),'NestedallocatorCALLbudget');vectors+=1
 reset(flags=1,base=0);limits.calls=1;run();require((r.status,r.current_sp,r.next_ip,r.calls,r.buffer_calls,r.services,r.flags_valid)==(3,58,0xbb2,1,1,0,0),'SharedparentCALLlimit/afterallocator');vectors+=1
 reset();limits.services=0;run();require((r.status,r.next_ip,r.calls,r.services,r.flags_valid)==(3,0x24a5,1,0,0),'GlobalDOSbudget');vectors+=1
 reset();bus[0x26da4]=0x80;limits.read_steps=0;run();require((r.status,r.next_ip,r.read_steps,r.services)==(3,0x24d0,0,1),'ReaderLODSbudget');vectors+=1
 reset(channel=128);limits.read_mapper_calls=0;run();require((r.status,r.next_ip,r.read_calls,r.services)==(3,0x939,0,0),'ReadernearMapperbudget');vectors+=1
 for cb in [null,dos]:
  reset();deny=bool(cb);run(cb);require(r.status==4 and r.services==0 and r.flags_valid==0,'Adaptermissing-or-declined');vectors+=1
 deny=False;invalid=True;reset();run();require(r.status==4 and r.services==0,'AdapterinvalidreturnedCF');vectors+=1;invalid=False
 for sp in [70,0xffe0]:
  reset(sp=sp);run(sp=sp);require((r.status,r.current_sp,r.flags_valid)==(0,(sp+4)&65535,1),'AdmittedSPboundary');vectors+=1
 for sp,raw,expectedsp,expectedip in [(0x6dab,1,0x6d97,9),(0x6d95,0,0x6d99,9)]:
  reset(ss=0x2000,sp=sp);error=True;run(ss=0x2000,sp=sp);require((r.status,r.current_sp,r.next_ip)==(raw,expectedsp,expectedip),'Errorwordaliasesactualreturn '+hex(sp));vectors+=1
 error=False
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_stream_pull_byte.py','sha256':hashlib.sha256((ROOT/'tools/validate_stream_pull_byte.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/rawguardZF/actualheap-reader/signedchannel/cursorINCbeforealiasedbyte/globalandnestedbudgets/adapterfailure/actualSSnear-farreturnaliases only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified; callers-allwriters-bufferbounds-storage-capacity-ownership-lifetime-exclusion/core/resource/device/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
