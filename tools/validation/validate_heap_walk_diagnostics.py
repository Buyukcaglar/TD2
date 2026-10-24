"""Native26F1 guard/header/DS-ES/nearframe/returnedDF andpointer conventions."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_heap_walk import Registers,StateRegisters,Request,Limits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_heap_walk;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0x1200,4,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,0);r=Result();vectors=0;null=Service();limits=Limits(8,128,8,64,1,1,1,32,8)
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,42,C.byref(s),C.byref(limits)),(bus,len(bus),41,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),42,C.byref(s),C.byref(limits)),(bus,len(bus),42,None,C.byref(limits)),(bus,len(bus),42,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,42,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,42,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(request=4,header=9,key=0x2000,bx=0x1200,ss=0x9000):
  C.memset(bus,0,len(bus));s.registers.bx=bx;s.registers.cx=request;s.registers.ds=key;s.registers.direction=1
  for seg in [key,0x2100]:
   for o,v in [(bx,0x3000),(bx+2,0x3000),(bx+6,16),(bx+8,0),(0x3000,header)]:put(seg,o,v)
  put(0x4000,0x6f30,key);put(0x4000,0x6f34,0xa55a);put(0x4000,0x6f36,0);put(0x4000,0x6d2a,16);put(0x4000,0x6d2c,key);put(0x4000,0x6d24,0xffff);put(0x4000,0x6d9b,key);put(ss,42,0x1111)
 def run(calls=8,iterations=128,tail=1,services=8,cb=null,ss=0x9000):
  limits.calls=calls;limits.iterations=iterations;limits.tail_calls=tail;limits.services=services;fn(bus,len(bus),0x1000,ss,42,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 reset();run(iterations=0);require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes,r.returned.registers.si,r.returned.registers.direction,r.returned.carry,r.flags_valid)==(3,42,0x2700,0,0,0x3000,0,1,0),'CLDafterguards/beforeinitialLODSW');vectors+=1
 reset();run(iterations=1);require((r.status,r.next_ip,r.returned.registers.ax,r.returned.registers.si,r.returned.registers.di)==(3,0x2707,9,0x3002,0x3002),'InitialLODSWpostcursor/beforeheaderDEC');vectors+=1
 reset();run();require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.cx,r.returned.carry,r.zero_flag,r.flags_valid,word(0x2000,0x3000),word(0x2000,0x3006),word(0x2000,0x1202),word(0x4000,0x6f34))==(0,44,0x3002,0x2000,0x9000,1,0,1,4,3,0x3006,0x2000),'Split/sourceAXoffset-DXsegment/cursor-export');vectors+=1
 reset(request=0x104,header=0x105);run();require((r.status,word(0x2000,0x3000),word(0x2000,0x1202),r.bus_writes)==(0,0x104,0x3106,3),'ExactfitbyteDEC/highbytepreserved');vectors+=1
 reset(request=0);run();require((r.status,r.returned.registers.ax,r.returned.registers.dx,word(0x2000,0x3000),word(0x2000,0x3002))==(0,0x3002,0x2000,0,7),'Rawzerorequestnonnull/sourcepolicy');vectors+=1
 reset(request=0xffff);run(iterations=0);require((r.status,r.calls,r.iterations,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.direction,r.zero_flag)==(0,0,0,0,0,1,1),'INCwrapguard/failurebeforeCLD/wordCWD');vectors+=1
 reset(request=0xffee);run();require((r.status,r.iterations,r.returned.registers.ax,r.returned.registers.dx,r.zero_flag)==(0,0,0,0,1),'UnsignedFFEEguard/failurecursorreset');vectors+=1
 reset(ss=0x2000);run(ss=0x2000);require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.zero_flag,word(0x4000,0x6f34))==(0,0x3002,0x2000,0,1,0xa55a),'SuccessDS==SS/ZF1nonNULL/noESexportstore');vectors+=1
 reset(header=3);put(0x2000,0x3004,5);run();require((r.status,r.iterations,r.returned.registers.ax,word(0x2000,0x3000),word(0x2000,0x3006))==(0,3,0x3002,4,3),'Firstheadercoalescing/orderedmerge-split');vectors+=1
 reset(header=4);put(0x2000,0x3006,3);put(0x2000,0x300a,5);run();require((r.status,r.returned.registers.ax,word(0x2000,0x3006),word(0x2000,0x300c),bus[0x46f3a])==(0,0x3008,4,3,2),'Laterheadercoalescing/EScounterinitialization');vectors+=1
 reset(header=0xfffe);put(0x2000,0x1208,0x2100);put(0x2100,0x3000,9);run();require((r.status,r.returned.registers.ds,r.returned.registers.dx,bus[0x46f3a])==(0,0x2100,0x2100,2),'ExplicitDSlinkedsegmentswitch');vectors+=1
 reset(header=0xfffe);put(0x4000,0x6f30,0x2100);put(0x2100,0x3000,9);run();require((r.status,r.returned.registers.ds,bus[0x46f3a])==(0,0x2100,1),'ESfallbackDSload/counterdoesnotreset');vectors+=1
 reset(header=0xfffe,ss=0x2000);put(0x4000,0x6f30,0x2100);put(0x2100,0x3000,9);run(calls=0,ss=0x2000);require((r.status,r.next_ip,r.returned.registers.ds,bus[0x46f3a],r.flags_valid)==(3,0x27a1,0x2000,0,0),'DS==SSskipsfallbackload/two-sentinelgrowth');vectors+=1
 reset(header=0xfffe);run(tail=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.tail_calls,r.flags_valid)==(3,36,0x2810,1,0,0),'Actualrootnearframe/childtailCALLbudget');vectors+=1
 @Service
 def df1(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=0;result.contents.registers.direction=1;return 1
 reset(header=0xfffe);put(0x2000,0x8ffe,0);put(0x2000,0x8ffc,0xa5a5);put(0x4000,0x6d24,0);run(cb=df1);require((r.status,r.calls,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.direction,r.zero_flag,word(0x2000,0x1202))==(0,2,2,0x8ffa,0x2000,1,0,0x8ffe),'ActualreturnedDF1/LODSWbackwardafterchild/noCLDreapply');vectors+=1
 reset(header=0xfffe);put(0x4000,0x6d24,0);run();require((r.status,r.next_ip,r.services,r.flags_valid)==(4,0x2904,0,0),'Missingadapter/sourceprefixnotNULLfailure');vectors+=1
 @Service
 def raw(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=0;at=((q.stack_segment<<4)+q.stack_sp)&0xfffff;memory[at]=0xfe;memory[(at+1)&0xfffff]=0xff;return 1
 reset(header=0xfffe);put(0x4000,0x6d24,0);run(cb=raw);require((r.status,r.next_ip,r.flags_valid)==(1,0xfffe,0),'RawnestedchildRETexposedneverfollowed');vectors+=1
 reset(bx=40,ss=0x2000);put(0x2000,0x1111,9);run(ss=0x2000);require((r.status,r.current_sp,r.next_ip,r.returned.registers.ax,word(0x2000,42))==(0,44,0x1117,0x1113,0x1117),'Cursorfieldaliasesactualrootnearreturn');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_heap_walk.py','sha256':hashlib.sha256((ROOT/'tools/validate_heap_walk.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/root-childbudgets/guards-beforeCLD/word-byteheaders/coalescing-splitting/DS-ESsegmenttraversal/successAX-DXpointervsZF/actualreturnedDFLODSW/SSFNs/rawRET diagnostics only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, wholecaller/writers/capacity/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
