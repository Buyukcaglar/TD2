"""Native18B0 fullSS/DEC-sign-bit/count-counter-cursor aliases/actual0B42 budgets."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_stream_next_byte import Registers,StateRegisters,Request,Limits,PullLimits,BufferLimits,PublicLimits,WalkLimits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_stream_next_byte;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,1);r=Result();vectors=0;null=Service();limits=Limits(1,PullLimits(2,8,1,32,BufferLimits(2,PublicLimits(2,WalkLimits(8,128,8,64,1,1,1,32,8)))))
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,78,C.byref(s),C.byref(limits)),(bus,len(bus),77,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),78,C.byref(s),C.byref(limits)),(bus,len(bus),78,None,C.byref(limits)),(bus,len(bus),78,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,78,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,78,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(count=1,flags=9,cursor=0x3002,ss=0x9000,sp=78):
  C.memset(bus,0,len(bus));limits.calls=1;limits.pull.calls=2;limits.pull.services=8;limits.pull.read_mapper_calls=1;limits.pull.read_steps=32;limits.pull.buffer.calls=2
  for o,v in [(0x1200,cursor),(0x1202,count),(0x1204,0x3002),(0x83ee,0xffff),(0x83f2,0x1200),(0x6da2,128),(0x6e96,4)]:put(0x2000,o,v)
  bus[0x21206]=flags;bus[0x21207]=0;bus[0x23002]=0xff;bus[0x26d9d]=3
  for i,v in enumerate([0x1111,0x2222]):put(ss,sp+2*i,v)
 events=[];altbp=False
 @Service
 def dos(context,memory,request,result):
  q=request.contents;events.append(q.site);require(q.site==0x24a5,'OnlyREAD');ret=StateRegisters.from_buffer_copy(bytes(q.incoming));ret.registers.ax=1;ret.carry=0
  if altbp:ret.bp=0xfffb
  memory[((q.incoming.registers.ds<<4)+q.incoming.registers.dx)&0xfffff]=0xfe;result[0]=ret;return 1
 def run(cb=dos,ss=0x9000,sp=78):
  events.clear();fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.ax,r.returned.registers.si,r.returned.bp,r.returned.carry,r.zero_flag,r.calls,r.bus_writes,word(0x2000,0x83ee),word(0x2000,0x1202),word(0x2000,0x1200))==(0,82,0x2222,0x1111,0xff,0x3456,0x5678,0,1,0,4,0,0,0x3003),'FastfullSS/globalwrap/unsignedAX');vectors+=1
 for count,slow,after in [(0,1,0xffff),(1,0,0),(0x8000,0,0x7fff),(0x8001,1,0x8000),(0xffff,1,0xfffe),(0x7fff,0,0x7ffe)]:
  reset(count=count,flags=0);run();require((r.status,r.calls,r.returned.registers.ax,r.zero_flag,r.returned.carry,word(0x2000,0x1202))==(0,slow,0xffff if slow else 0xff,0 if slow else 1,0,after),'LiteralDECSFguard '+hex(count));vectors+=1
 reset(cursor=0x1200);run();require((r.status,r.returned.registers.ax,word(0x2000,0x1200))==(0,1,0x1201),'INCcursorbeforealiasedbytefetch');vectors+=1
 reset(cursor=0xffff);bus[0x2ffff]=0xa5;run();require((r.status,r.returned.registers.ax,word(0x2000,0x1200))==(0,0xa5,0),'Fastcursorwordwrap');vectors+=1
 reset();put(0x2000,0x83f2,0x83ec);put(0x2000,0x83ec,0x3002);put(0x2000,0x83ee,0);run();require((r.status,r.calls,r.returned.registers.ax,word(0x2000,0x83ee))==(0,0,0xff,0),'GlobalINCthenaliasedcountDECcancel');vectors+=1
 reset(ss=0x2000,sp=0x83f4);put(0x2000,0x3456,0x7000);put(0x2000,0x3458,1);bus[0x27000]=0xa6;run(ss=0x2000,sp=0x83f4);require((r.status,r.returned.registers.ax,word(0x2000,0x83f2),word(0x2000,0x3458),word(0x2000,0x1202))==(0,0xa6,0x3456,0,1),'PUSHSIaliasesglobalstreambeforeselection');vectors+=1
 for sp,ip,cs in [(0x83ee,0x1112,0x2222),(0x83ec,0x1111,0x2223)]:
  reset(ss=0x2000,sp=sp);run(ss=0x2000,sp=sp);require((r.status,r.next_ip,r.next_segment)==(0,ip,cs),'CounterINCactualfarframealias '+hex(sp));vectors+=1
 reset(count=0);run();require((r.status,r.calls,r.pull_calls,r.buffer_calls,r.services,r.returned.registers.ax,r.zero_flag,r.returned.carry,r.current_sp)==(0,1,1,0,1,0xfe,0,0,82),'Actual0B42read/rootADDflags');vectors+=1
 reset(count=0);limits.calls=0;run();require((r.status,r.next_ip,r.current_sp,r.calls,r.flags_valid,r.returned.carry)==(3,0x18cc,74,0,0,1),'OuterbudgetafterargumentPUSH/DECpreservesCF');vectors+=1
 reset(count=0);limits.pull.calls=0;run();require((r.status,r.next_ip,r.calls,r.pull_calls,r.flags_valid)==(3,0xbb2,1,0,0),'ActualchildparentCALLbudget');vectors+=1
 reset(count=0);limits.pull.services=0;run();require((r.status,r.next_ip,r.services,r.flags_valid)==(3,0x24a5,0,0),'GlobalDOSbudgetinsideactualchild');vectors+=1
 reset(count=0);run(null);require(r.status==4 and r.services==0 and r.flags_valid==0,'Missingadapter');vectors+=1
 reset(count=0);altbp=True;run();require((r.status,r.next_ip,r.current_sp,r.services,r.flags_valid)==(5,0x943,0xfffd,1,0),'ActualreaderpreRETqualificationpropagated');vectors+=1;altbp=False
 for sp in [78,0xffe0]:
  reset(sp=sp);run(sp=sp);require((r.status,r.current_sp,r.flags_valid)==(0,(sp+4)&65535,1),'AdmittedSPboundary');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_stream_next_byte.py','sha256':hashlib.sha256((ROOT/'tools/validate_stream_next_byte.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/literalDECSFguard incl8000fast/unsignedAX/currentDScounter-stream/count-counter-cursor-savedSI-farframealiases/actual0B42read/outer-nested-globalbudgets/adapterfailure/readerqualification only. Originalcomparison separate; actualcallers-allwriters-bufferbounds-storage-capacity-ownership-lifetime-exclusion/historicalCPU-A20/core/resource/device/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
