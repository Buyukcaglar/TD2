"""Native49E7-4A19 guard decisions/ZF/SS aliases/conditional sample budgets."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_guards import Registers,StateRegisters,SampleLimits,Limits,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_sample_guards;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0,0xc456,0xd789,0x3456,0x4567,0x2000,0x5432,0,1),0x5678,1);r=Result();limits=Limits(2,SampleLimits(3,1));ss=0x9000;sp=0xe000;entry=0;vectors=0
 for memory,size,pointer,index,state,bounds in [(None,len(bus),20,0,C.byref(s),C.byref(limits)),(bus,len(bus)-1,20,0,C.byref(s),C.byref(limits)),(bus,len(bus),19,0,C.byref(s),C.byref(limits)),(bus,len(bus),0xffe1,0,C.byref(s),C.byref(limits)),(bus,len(bus),20,2,C.byref(s),C.byref(limits)),(bus,len(bus),20,0,None,C.byref(limits)),(bus,len(bus),20,0,C.byref(s),None)]:
  fn(memory,size,0x1000,ss,pointer,index,state,bounds,C.byref(r));require((r.status,r.guard_calls,r.sample_calls,r.bus_writes,r.flags_valid)==(2,0,0,0,0) and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,20,0,C.byref(s),C.byref(limits),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,20,0,C.byref(s),C.byref(limits),None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def wb(sg,o,v):bus[((sg<<4)+(o&65535))&0xfffff]=v&255
 def b(sg,o):return bus[((sg<<4)+(o&65535))&0xfffff]
 def reset(index=0,bx=0,minimum=0x8000,maximum=0x7fff,bit=0,flag=0,stack=0x9000,pointer=0xe000,ds=0x2000,flags=0x402,before=0,counter=0):
  nonlocal entry,ss,sp
  entry,ss,sp=index,stack,pointer;C.memset(bus,0,len(bus));s.registers.bx=bx;s.registers.ds=ds;s.registers.interrupts_enabled=(flags>>9)&1;s.registers.direction=(flags>>10)&1;s.carry=flags&1;limits.guard_calls=2;limits.sample.calls=3;limits.sample.control_calls=1
  for o,v in [(0x3334,minimum),(0x3336,maximum),(0x52ce,2000),(0x3328,0x8000),(0x332c,0x1234),(0x23b2,0xffff),(0x66e6,1)]:put(ds,o,v)
  for o,v in [(0x5491,bit),(0x37f6,flag),(0x2f56,1),(0x337b,counter),(0x2418,255),(0x5490,0x55)]:wb(ds,o,v)
  for i in range(256):wb(ds,0x66e8+i,before)
  put(ss,sp,0x1111)
 def run():fn(bus,len(bus),0x1000,ss,sp,entry,C.byref(s),C.byref(limits),C.byref(r))
 for index,bx in [(0,0),(1,0),(1,2)]:
  reset(index=index,bx=bx);run();require((r.status,r.current_sp,r.next_ip,r.guard_calls,r.sample_calls,r.control_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.interrupts_enabled,r.returned.registers.direction,r.zero_flag,r.flags_valid)==(0,0xe002,0x1111,1,3,1,22,50,1600,0x1234,1,1,0,1),'Actualfirstguard-to-tail '+str((index,bx)));require((word(0x2000,0x52ce),word(0x2000,0x66e6),b(0x2000,0x66e8))==(400,0,1),'Actualtailstate');vectors+=1
 for bit,flag,minimum,maximum,guards,samples,ax in [(0,0,0,0,2,0,395),(0,0,400,400,2,3,50),(0,0,0xfe70,0xfe70,1,3,50),(1,0,0xfe70,0xfe70,1,3,50),(1,1,0xfce0,0xfce0,1,3,50),(1,0,800,800,2,3,50),(1,1,0xfe70,0xfe70,2,0,795)]:
  reset(bit=bit,flag=flag,minimum=minimum,maximum=maximum);run();require((r.status,r.guard_calls,r.sample_calls,r.returned.registers.ax,r.returned.registers.interrupts_enabled,r.zero_flag)==(0,guards,samples,ax,int(samples!=0),0),'Negative-first/positive-second/reloadedbit '+str((bit,flag,minimum,maximum)));vectors+=1
 for bx,minimum,maximum,ax,carry,samples in [(0,0,0,0x6fc1,0,0),(2,0,0,0x6f31,0,0),(0,208,0x7fff,0x6fc1,1,0),(0,0x8000,0xffff,0x6fc1,1,0),(2,0x8000,0x8000,0x6f31,0,0),(0,207,193,50,1,3),(2,0xff3f,0xff31,50,1,3)]:
  reset(index=1,bx=bx,minimum=minimum,maximum=maximum);run();require((r.status,r.returned.registers.ax,r.returned.carry,r.sample_calls,r.returned.registers.cx)==(0,ax,carry,samples,0x1234 if samples else 0xc456),'Signedbounds/unsignedCF/MOVAH-preservesZF '+str((bx,minimum,maximum)));vectors+=1
 reset();limits.guard_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.bus_writes,r.flags_valid)==(3,0x49fe,sp,0,0,0),'Firstguardbudget');vectors+=1
 reset(minimum=0,maximum=0);limits.guard_calls=1;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.sample_calls,r.bus_writes,r.returned.registers.ax)==(3,0x4a10,sp,1,0,2,400),'SecondguardbudgetafterfirstactualSSframe');vectors+=1
 for index,bx,ax in [(0,0,0xfe6b),(1,0,0x6fc1),(1,2,0x6f31)]:
  reset(index=index,bx=bx);limits.sample.calls=0;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.sample_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.interrupts_enabled)==(3,0x4a31,sp,1,0,2,ax,1600,0),'TailbudgetusesoriginalSP/MOVAH '+str((index,bx)));vectors+=1
 for pointer,samples,guards in [(0x3334,0,2),(0x3336,0,2),(0x3338,3,1),(0x333a,0,2)]:
  reset(stack=0x2000,pointer=pointer);run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.sample_calls)==(0,0x1111,pointer+2,guards,samples),'ActualguardSSframesaliasDSbounds '+hex(pointer));vectors+=1
 for pointer,ip,calls in [(0x3330,800,1),(0x52d0,0x43f4,1),(0x5ef8,0x5494,2),(0x66ea,0x4a45,3)]:
  reset(stack=0x2000,pointer=pointer);run();require((r.status,r.next_ip,r.guard_calls,r.sample_calls,r.flags_valid)==(1,ip,1,calls,0),'InheritedrawactualchildRET '+hex(pointer));vectors+=1
 reset(stack=0x2000,pointer=0x66ec);run();require((r.status,r.returned.registers.si,word(0x2000,0x66e6))==(0,0x3455,0x3455),'InheritedringPUSHSIcursoralias');vectors+=1
 for index,flags,sample in [(0,f,1) for f in [2,0x203,0x402,0x603]]+[(1,f,0) for f in [2,0x203,0x402,0x603]]:
  reset(index=index,flags=flags,minimum=0 if not sample else 0x8000,maximum=0 if not sample else 0x7fff);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1 if sample else (flags>>9)&1,(flags>>10)&1),'ConditionalIF1/DFretained '+str((index,flags)));vectors+=1
 for index,pointer in [(e,p) for e in [0,1] for p in [20,0xffe0]]:
  reset(index=index,pointer=pointer);run();require((r.status,r.current_sp)==(0,pointer+2),'RootSPdomain');vectors+=1
 for ds,index in [(d,e) for d in [0,0xffff] for e in [0,1]]:
  reset(index=index,ds=ds,stack=ds,pointer=20);run();require((r.status,r.current_sp,r.returned.registers.ds)==(0,22,ds),'Zero-highDS/fullSS20bitRAM');vectors+=1
 reset(counter=4);run();require((r.status,b(0x2000,0x337b),b(0x2000,0x5490))==(0,5,8),'Inheritedstate8path');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sample_guards.py','sha256':hashlib.sha256((ROOT/'tools/validate_sample_guards.py').read_bytes()).hexdigest()}],'limits':'Native49E7-4A19/fullSSguard-CXsave/requiredZF/negative-first-positive-second/MOVAH6F/rawsignedbounds-unsignedCF/actualSSboundsaliases/conditionalfrozen4A2E-tail/globalCALLbudgets/inheritedrawRETandSIaliases/IFconditional-DF/SPdomain/zero-highDS only. Originalcomparison/staticreviewseparate. No491Dvalidselector-allwriters/full4674/sharedsource-reset-lifetime-IRQexclusion/core/RNGpurpose/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
