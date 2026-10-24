"""Native4AFA signedCL/window/clamp and4B5D actualnear-sample ABI/budget/returnaliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_window_controllers import Registers,StateRegisters,ChildLimits,Limits,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_window_controllers;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x5432,0,1),0x5678,1);r=Result();limits=Limits(2,1,ChildLimits(3,1));ss=0x9000;sp=0xe000;entry=0;vectors=0
 for memory,size,pointer,index,state,bounds in [(None,len(bus),0,0,C.byref(s),C.byref(limits)),(bus,len(bus)-1,0,0,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,0,C.byref(s),C.byref(limits)),(bus,len(bus),21,1,C.byref(s),C.byref(limits)),(bus,len(bus),0xffe1,1,C.byref(s),C.byref(limits)),(bus,len(bus),22,2,C.byref(s),C.byref(limits)),(bus,len(bus),0,0,None,C.byref(limits)),(bus,len(bus),0,0,C.byref(s),None)]:
  fn(memory,size,0x1000,ss,pointer,index,state,bounds,C.byref(r));require((r.status,r.bus_writes,r.flags_valid)==(2,0,0) and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,22,1,C.byref(s),C.byref(limits),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,0,0,C.byref(s),C.byref(limits),None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def wb(sg,o,v):bus[((sg<<4)+(o&65535))&0xfffff]=v&255
 def b(sg,o):return bus[((sg<<4)+(o&65535))&0xfffff]
 def reset(index=0,window=50,cl=1,marked=0,high=0,trigger=1,bit=0,flag=0,minimum=0x8000,maximum=0x7fff,before=0,field=0,selector=1,cursor=1,stack=0x9000,pointer=0xe000,ds=0x2000,flags=0x402):
  nonlocal ss,sp,entry
  ss,sp,entry=stack,pointer,index;C.memset(bus,0,len(bus));s.registers.ds=ds;s.registers.interrupts_enabled=(flags>>9)&1;s.registers.direction=(flags>>10)&1;s.carry=flags&1;limits.guard_calls=2;limits.sample_calls=1;limits.child.calls=3;limits.child.control_calls=1
  for o,v in [(0x52cc,window),(0x3334,minimum),(0x3336,maximum),(0x52ce,2000 if index else (high<<8)|0x20),(0x3328,0x8000),(0x332c,0x1234),(0x33c8,field),(0x33ca,field),(0x33cc,field),(0x23b2,0xffff),(0x66e6,cursor)]:put(ds,o,v)
  for o,v in [(0x3371,cl),(0x33d5,marked),(0x533e,trigger),(0x5491,bit),(0x37f6,flag),(0x2f56,selector),(0x33c6,field),(0x2418,255),(0x5490,0x55)]:wb(ds,o,v)
  for i in range(256):wb(ds,0x66e8+i,before)
  put(ss,sp,0x1111)
 def run():fn(bus,len(bus),0x1000,ss,sp,entry,C.byref(s),C.byref(limits),C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_ip,r.guard_calls,r.sample_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.carry,r.zero_flag,b(0x2000,0x5490),word(0x2000,0x3332),word(0x2000,0x3334),word(0x2000,0x3336))==(0,0xe002,0x1111,0,0,4,90,180,0xc401,1,0,9,90,0,180),'Window-before-signedCL/state9/CHretained');vectors+=1
 for cl,carry in [(0,1),(128,0),(255,0)]:
  reset(cl=cl);run();require((r.status,r.bus_writes,r.returned.registers.cx,r.returned.carry,r.zero_flag,b(0x2000,0x5490))==(0,3,0xc400|cl,carry,0,0x55),'SignedCLless1 '+str(cl));vectors+=1
 for window,cl,marked,high,center,saved,state,writes,carry,zf in [(60,1,0,0,100,60,1,4,0,1),(559,1,0,0,599,559,1,4,0,0),(560,1,0,0,600,560,1,5,0,0),(561,1,0,0,601,560,1,5,0,0),(561,1,1,5,601,561,1,4,0,1),(50,1,1,0,90,50,1,4,1,0),(50,1,1,6,90,50,0x55,3,0,0),(50,2,0,0,90,50,4,4,0,1),(50,3,0,0,90,50,9,4,1,0),(32728,1,0,0,0x8000,32728,9,4,0,0),(65496,1,0,0,0,65496,9,4,1,0),(65535,1,0,0,39,65535,9,4,1,0)]:
  reset(window=window,cl=cl,marked=marked,high=high);run();require((r.status,r.returned.registers.ax,word(0x2000,0x3332),word(0x2000,0x52cc),b(0x2000,0x5490),r.bus_writes,r.returned.carry,r.zero_flag)==(0,center,center,saved,state,writes,carry,zf),'OriginalAX-after-clamp/signedword/state-flags '+str((window,cl,marked,high)));vectors+=1
 for pointer,ip in [(0x3332,90),(0x3334,0),(0x3336,180),(0x5490,0x1109),(0x52cc,560)]:
  reset(stack=0x2000,pointer=pointer);run();require((r.status,r.next_ip,r.current_sp,r.flags_valid)==(0,ip,(pointer+2)&65535,1),'WindowwritesaliasactualrootnearIP '+hex(pointer));vectors+=1
 for trigger in range(256):
  reset(index=1,trigger=trigger);run();eligible=trigger in range(1,256,16);require((r.status,r.guard_calls,r.sample_calls,r.child_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.interrupts_enabled)==(0,int(eligible),int(eligible),3 if eligible else 0,23 if eligible else 0,50 if eligible else 0xa500|((trigger-1)&255),int(eligible)),'ActualDEC-TESTgate/AHretained '+str(trigger));vectors+=1
 for bit,flag,minimum,maximum,guards,sample,ax in [(0,0,500,500,2,1,50),(0,0,0xfe0c,0xfe0c,1,1,50),(1,1,0xfc7c,0xfc7c,1,1,50),(1,0,900,900,2,1,50),(1,1,0xfe0c,0xfe0c,2,0,895)]:
  reset(index=1,bit=bit,flag=flag,minimum=minimum,maximum=maximum);run();require((r.status,r.guard_calls,r.sample_calls,r.returned.registers.ax)==(0,guards,sample,ax),'Negative-first-positive-secondcenters '+str((bit,flag,minimum,maximum)));vectors+=1
 reset(index=1);limits.guard_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.flags_valid)==(3,0x4b7e,sp,0,0),'Firstguardbudget');vectors+=1
 reset(index=1,minimum=0,maximum=0);limits.guard_calls=1;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.bus_writes,r.returned.registers.ax)==(3,0x4b90,sp,1,2,500),'Secondguardbudget');vectors+=1
 reset(index=1);limits.sample_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.sample_calls,r.bus_writes,r.returned.registers.ax)==(3,0x4b96,sp,1,0,2,0xfe07),'ParentnearCALLbudgetbeforeframe');vectors+=1
 reset(index=1);limits.child.calls=0;run();require((r.status,r.next_ip,r.current_sp,r.sample_calls,r.child_calls,r.bus_writes,r.returned.registers.dx)==(3,0x4a31,sp-2,1,0,3,1600),'Childbudgetafteractualparentnearframe');vectors+=1
 reset(index=1);limits.child.control_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.sample_calls,r.child_calls,r.control_calls,r.bus_writes)==(3,0x460e,sp-4,1,1,0,5),'Nestedcontrolbudget/actualthreelevels');vectors+=1
 for pointer,ip,cursor in [(0x3332,800,1),(0x52d2,0x43f4,1),(0x5efa,0x5494,1),(0x66ec,0x4a45,1),(0x67a2,0x4a8d,0xb5)]:
  reset(index=1,stack=0x2000,pointer=pointer,cursor=cursor);run();require((r.status,r.next_ip,r.sample_calls,r.flags_valid)==(1,ip,1,0),'InheritedchildRETframe-shift '+hex(pointer));vectors+=1
 for pointer,before,selector,ip in [(0x33c8,0,1,0x4b4b),(0x33ca,13,1,0x9b1a),(0x33cc,25,1,0x4b4e),(0x33ce,38,1,0x4bbe),(0x3448,50,135,0x4b01)]:
  reset(index=1,stack=0x2000,pointer=pointer,before=before,selector=selector);run();require((r.status,r.next_ip,r.sample_calls,r.child_calls,r.current_sp,r.flags_valid)==(1,ip,1,3,pointer,0),'Actual4A2ErootnearRETchanged-beforeparentcontinue '+hex(pointer));vectors+=1
 reset(index=1,stack=0x2000,pointer=0x5efc);run();require((r.status,r.next_ip,r.current_sp,r.returned.bp)==(0,0x1101,0x5efe,0x5494),'Setterflagaliasesparentroot/savedBP');vectors+=1
 reset(index=1,stack=0x2000,pointer=0x66ee);run();require((r.status,r.returned.registers.si,word(0x2000,0x66e6))==(0,0x3455,0x3455),'ChildringPUSHSIcursoralias');vectors+=1
 reset(index=1,stack=0x2000,pointer=0x672d,cursor=0x3e);run();require((r.status,r.returned.registers.si,r.returned.registers.ax)==(0,0x34ad,0xad),'ChildringPUSHSIselectedbytealias');vectors+=1
 for field,state in [(0xffe6,7),(0xffe7,7),(0xffe8,0x55),(0x8024,0x55),(0x8025,7)]:
  reset(index=1,before=166,field=field);run();require((r.status,b(0x2000,0x5490))==(0,state),'Inheritednegative-state7/postwrap '+hex(field));vectors+=1
 for index,flags,trigger in [(i,f,t) for i in [0,1] for f in [2,0x203,0x402,0x603] for t in ([1] if i==0 else [1,2])]:
  reset(index=index,flags=flags,trigger=trigger);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1 if index==1 and trigger==1 else (flags>>9)&1,(flags>>10)&1),'ConditionalIF1/DFretained');vectors+=1
 for index,pointer in [(0,0),(0,0xfffe),(1,22),(1,0xffe0)]:
  reset(index=index,pointer=pointer);run();require((r.status,r.current_sp)==(0,(pointer+2)&65535),'Entry-specificSPdomain/nearRETwrap');vectors+=1
 for index,ds in [(i,d) for i in [0,1] for d in [0,0xffff]]:
  reset(index=index,ds=ds,stack=ds,pointer=22);run();require((r.status,r.current_sp,r.returned.registers.ds)==(0,24,ds),'Zero-highDS/fullSS20bitRAM');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_window_controllers.py','sha256':hashlib.sha256((ROOT/'tools/validate_window_controllers.py').read_bytes()).hexdigest()}],'limits':'Native4AFAwindow-orderedwrites/signedCL/CHretained/clamp-originalAX/state-flags/rootaliases and4B5Dall256triggerbytes/actualguard-near-sample/globalCALLbudgets/changed4A2EnearRET-beforeparentcontinue/childfar-nearRETandSIaliases/conditionalIF1-DF/SPdomains/zero-highDS only. Originalcomparison/staticreviewseparate/no fullcaller-allwriters-validselectors-resourcecapacities-sharedsource-reset-IRQ-lifetime-core/DOSsession/renderer/audio/fullstate/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
