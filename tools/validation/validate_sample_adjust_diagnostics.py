"""Native4A2E/fullSS/IF1 samplecaller/orderedarithmetic/rawwriter-returnaliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,Limits,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_sample_adjust;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x5432,0,1),0x5678,1);r=Result();vectors=0;limits=Limits(3,1);ss=0x9000;sp=0xe000
 for memory,count,pointer,state,bounds in [(bus,len(bus)-1,20,C.byref(s),C.byref(limits)),(None,len(bus),20,C.byref(s),C.byref(limits)),(bus,len(bus),20,None,C.byref(limits)),(bus,len(bus),20,C.byref(s),None),(bus,len(bus),19,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits))]:
  fn(memory,count,0x1000,ss,pointer,state,bounds,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,20,C.byref(s),C.byref(limits),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,20,C.byref(s),C.byref(limits),None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def wb(sg,o,v):bus[((sg<<4)+(o&65535))&0xfffff]=v&255
 def b(sg,o):return bus[((sg<<4)+(o&65535))&0xfffff]
 def reset(before=0,counter=0,blocked=0,late=0,selector=1,field=0,threshold=255,cursor=1,stack=0x9000,pointer=0xe000,data_segment=0x2000,flags=0x402):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.ds=data_segment;s.registers.interrupts_enabled=(flags>>9)&1;s.registers.direction=(flags>>10)&1;s.carry=flags&1;limits.calls=3;limits.control_calls=1
  for o,v in [(0x52ce,2000),(0x3328,0x8000),(0x332c,0x1234),(0x8a9a,blocked),(0x33c8,field),(0x33ca,field),(0x33cc,field),(0x23b2,threshold),(0x66e6,cursor)]:put(data_segment,o,v)
  for o,v in [(0x2f56,selector),(0x337b,counter),(0x33c6,field),(0x2418,threshold),(0x90a8,late),(0x5490,0x55)]:wb(data_segment,o,v)
  for i in range(256):wb(data_segment,0x66e8+i,before)
  put(ss,sp,0x1111)
 def run():fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.control_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.si,r.returned.bp,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction,r.zero_flag,r.flags_valid)==(0,0xe002,0x16c9,0x1111,3,1,20,50,1600,0x1234,800,0x3456,0x5678,1,1,1,0,1),'Actualcontrol-setter-ring/sourceorderedGPR/fullSS/IF1');require((word(0x2000,0x5eee),word(0x2000,0x5ef0),b(0x2000,0x5efc),word(0x2000,0x66e6),b(0x2000,0x66e8),b(0x2000,0x337b),b(0x2000,0x33c6),word(0x2000,0x52ce),word(0x2000,0x332c))==(0x2000,0x5494,1,0,1,1,25,400,800),'Actualpointerpublication-ring-statewrites');vectors+=1
 for value in [0,1,25,26,50,51,75,76,77,100,101,127,128,255]:
  before=(value-1)//2 if value&1 else 0x80+value//2;reset(before=before,blocked=1);run();require((r.status,r.returned.registers.ax,b(0x2000,0x337b),r.returned.carry,r.zero_flag,r.returned.registers.interrupts_enabled)==(0,value,0,0,int(value==0),1),'UnsignedAX/signedALgate-and-blockedcaller '+str(value));vectors+=1
 reset(before=255,blocked=1,cursor=0xffff);run();require((r.status,word(0x2000,0x66e6),b(0x2000,0x67e6),r.returned.registers.ax)==(0,0xfffe,0xfe,0xfe),'Cursorhighwordretained/masklow8selectedFE');vectors+=1
 for counter,new,state in [(3,4,0x55),(4,5,8),(255,0,0x55),(127,128,8)]:
  reset(counter=counter);run();require((r.status,b(0x2000,0x337b),b(0x2000,0x5490))==(0,new,state),'Wrappedcounter/unsignedJA '+str(counter));vectors+=1
 for old,stored,tested,state in [(0,25,50,0x55),(25,75,100,5),(231,231,0,0x55),(255,23,48,0x55)]:
  reset(field=old,threshold=100);run();require((r.status,b(0x2000,0x33c6),r.returned.registers.ax,b(0x2000,0x5490))==(0,stored,tested,state),'Byte stored-vs-tested value '+str(old));vectors+=1
 for old,stored,tested,state in [(0,1000,2000,6),(0xffff,998,1998,0x55),(0xfc18,0xfc18,0,0x55)]:
  reset(before=141,field=old,threshold=2000);run();require((r.status,word(0x2000,0x33c8),r.returned.registers.ax,b(0x2000,0x5490))==(0,stored,tested,state),'Word stored-vs-tested value '+str(old));vectors+=1
 for old,new,state in [(74,0xffff,0x55),(75,0,7),(199,124,7),(200,125,0x55),(201,126,0x55)]:
  reset(before=25,field=old);run();require((r.status,word(0x2000,0x33ca),r.returned.registers.ax,b(0x2000,0x5490))==(0,new,new,state),'Unsigneddecrement-underflowguard '+str(old));vectors+=1
 for old,new,state in [(24,61,0x55),(25,62,7),(0x7fda,0x7fff,7),(0x7fdb,0x8000,0x55)]:
  reset(before=38,field=old);run();require((r.status,word(0x2000,0x33cc),r.returned.registers.bx,b(0x2000,0x5490))==(0,new,new,state),'POSTWRAPsignedpositiveguard '+str(old));vectors+=1
 for old,new,state in [(0xffe6,0xffc1,7),(0xffe7,0xffc2,7),(0xffe8,0xffc3,0x55),(0x8024,0x7fff,0x55),(0x8025,0x8000,7)]:
  reset(before=166,field=old);run();require((r.status,word(0x2000,0x33cc),r.returned.registers.bx,b(0x2000,0x5490))==(0,new,new,state),'POSTWRAPsignednegativeguard '+str(old));vectors+=1
 for offset in [0x3446,0x3456,0x3460]:
  for high in [0,1]:
   selector=offset-0x33bf+high;reset(before=50,selector=selector);put(0x2000,offset,0xabcd);run();require((r.status,r.returned.registers.bx,word(0x2000,offset),r.zero_flag)==(0,selector,0x01cd if high else 0xab01,1),'Rawlateindexonebyte-to-near-jumptable '+hex(offset+high));vectors+=1
 reset(before=50,selector=255);run();require((r.status,r.returned.registers.bx,b(0x2000,0x34be))==(0,255,1),'Rawselector255/no nominalarrayclamp');vectors+=1
 reset(before=50,selector=135,late=1);put(0x2000,0x3446,0xabcd);run();require((r.status,word(0x2000,0x3446),r.zero_flag)==(0,0xabcd,0),'Latebyteguardprecedesselectorwrite');vectors+=1
 for calls,site,pointer,IF in [(0,0x4a31,0xe000,0),(1,0x4a39,0xdffc,0),(2,0x4a41,0xe000,1)]:
  reset();limits.calls=calls;run();require((r.status,r.next_ip,r.current_sp,r.calls,r.returned.registers.interrupts_enabled,r.flags_valid)==(3,site,pointer,calls,IF,0),'ActualCALLbudget-order/CLI-STI '+str(calls));vectors+=1
 reset();limits.control_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.calls,r.control_calls,word(0x2000,0x52ce))==(3,0x460e,0xdffe,1,0,400),'NestedcontrolCALLbudgetafterpartialfieldstore');vectors+=1
 reset(stack=0x2000,pointer=0x3330);run();require((r.status,r.next_ip,r.current_sp,r.calls,r.control_calls,r.flags_valid)==(1,800,0x332e,1,1,0),'Actual4612nearframealiases332C');vectors+=1
 reset(stack=0x2000,pointer=0x52d0);run();require((r.status,r.next_ip,r.current_sp,r.calls,r.flags_valid)==(1,0x43f4,0x52d0,1,0),'Actual45FCnearframealiases52CE');vectors+=1
 reset(stack=0x2000,pointer=0x5ef8);run();require((r.status,r.next_ip,r.current_sp,r.calls,r.returned.bp,r.returned.registers.interrupts_enabled,r.flags_valid)==(1,0x5494,0x5ef4,2,0x2000,1,0),'Actual7977farframe-and-savedBPaliases');vectors+=1
 reset(stack=0x2000,pointer=0x5efa);run();require((r.status,r.next_ip,r.returned.bp,r.flags_valid)==(0,0x1111,0x5494,1),'Actual7977savedBPstore/ordinaryfarRET');vectors+=1
 reset(stack=0x2000,pointer=0x66ea);run();require((r.status,r.next_ip,r.current_sp,r.calls,r.flags_valid)==(1,0x4a45,0x66ea,3,0),'RingcursorDECaliasesactualfarIP');vectors+=1
 reset(stack=0x2000,pointer=0x67a0,cursor=0xb5);run();require((r.status,r.next_ip,r.returned.registers.ax,r.flags_valid)==(1,0x4a8d,0x8d,0),'RingselectedbytealiasesactualfarIP');vectors+=1
 reset(stack=0x2000,pointer=0x66e6);run();require((r.status,r.next_ip,r.current_sp)==(0,0x1110,0x66e8),'CursorDECaliasesrootnearIP');vectors+=1
 reset(stack=0x2000,pointer=0x66ec);run();require((r.status,word(0x2000,0x66e6),r.returned.registers.si)==(0,0x3455,0x3455),'RingPUSHSIaliasescursor/actualPOPchangedSI');vectors+=1
 reset(stack=0x2000,pointer=0x672b,cursor=0x3e);run();require((r.status,r.returned.registers.ax,r.returned.registers.si,b(0x2000,0x6725))==(0,0xad,0x34ad,0xad),'RingPUSHSIaliasesselectedbyte/actualPOPchangedSI');vectors+=1
 for flags in [2,0x203,0x402,0x603]:
  reset(flags=flags);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1,(flags>>10)&1),'NormalIF1/DFretained '+hex(flags));vectors+=1
 for pointer in [20,0xffe0]:
  reset(pointer=pointer);run();require((r.status,r.current_sp)==(0,pointer+2),'RootSPdomain '+str(pointer));vectors+=1
 for ds in [0,0xffff]:
  reset(data_segment=ds,stack=ds,pointer=20);run();require((r.status,r.current_sp,r.returned.registers.ds,r.returned.registers.interrupts_enabled,word(ds,0x5eee))==(0,22,ds,1,ds),'20bitzero-highDS/actualSSframes '+hex(ds));vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sample_adjust.py','sha256':hashlib.sha256((ROOT/'tools/validate_sample_adjust.py').read_bytes()).hexdigest()}],'limits':'Native4A2E/fullSS/actualcontrol-setter-ring/IF1caller/sourceorderedwrappedstate-arithmetic/rawselector-to-near-jumptable-onebytewriters/budgets/control-setter-ring-return-and-savedSIaliases/rootnearRET/zero-highDS only. Originalcomparison/staticproofseparate; serializednoIRQdelivery-exclusion-reset-sharedsource-lifetime/core/RNG-purpose/allwriters-validindices-resourcecodec/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
