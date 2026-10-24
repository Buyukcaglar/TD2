"""Native4C85 token/ES/byteDIV-AH/byteIMUL/BP-cached postchild/fullSS aliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_indexed_sample import Registers,StateRegisters,ChildLimits,Limits,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_indexed_sample;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x5432,0,1),0x5678,1);r=Result();limits=Limits(1,1,ChildLimits(3,1));ss=0x9000;sp=0xe000;vectors=0
 for memory,size,pointer,state,bounds in [(None,len(bus),22,C.byref(s),C.byref(limits)),(bus,len(bus)-1,22,C.byref(s),C.byref(limits)),(bus,len(bus),21,C.byref(s),C.byref(limits)),(bus,len(bus),0xffe1,C.byref(s),C.byref(limits)),(bus,len(bus),22,None,C.byref(limits)),(bus,len(bus),22,C.byref(s),None)]:
  fn(memory,size,0x1000,ss,pointer,state,bounds,C.byref(r));require((r.status,r.bus_writes,r.flags_valid)==(2,0,0) and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,22,C.byref(s),C.byref(limits),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,22,C.byref(s),C.byref(limits),None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def wb(sg,o,v):bus[((sg<<4)+(o&65535))&0xfffff]=v&255
 def b(sg,o):return bus[((sg<<4)+(o&65535))&0xfffff]
 def reset(selector=0,token=0,present=1,external=2,width=0,inline=0,coefficient=0,bit=0,flag=0,bp=0x5678,minimum=0x8000,maximum=0x7fff,before=0,field=0,raw_selector=1,cursor=1,stack=0x9000,pointer=0xe000,ds=0x2000,flags=0x402):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.ds=ds;s.bp=bp;s.registers.interrupts_enabled=(flags>>9)&1;s.registers.direction=(flags>>10)&1;s.carry=flags&1;limits.guard_calls=1;limits.sample_calls=1;limits.child.calls=3;limits.child.control_calls=1;index=selector&127
  for o,v in [(0x3334,minimum),(0x3336,maximum),(0x52ce,2000),(0x3328,0x8000),(0x332c,0x1234),(0x33c8,field),(0x33ca,field),(0x33cc,field),(0x23b2,0xffff),(0x66e6,cursor),(0x940e,0 if external==0 else 0x7000)]:put(ds,o,v)
  for o,v in [(0x533e,selector),(0x368a+index,token),(0x370a+index,coefficient),(0x5491,bit),(0x37f6,flag),(0x2f56,raw_selector),(0x33c6,field),(0x2418,255),(0x5490,0x55)]:wb(ds,o,v)
  if token<80:put(ds,0x1db4+4*token,present);wb(ds,0x337c+(token>>2),inline)
  if external and 30<=token<128:q,rem=divmod(token-30,5);put(0x7000,2*q+512*rem,0 if external==1 else 0x100);put(0x7000,0x100,width)
  for i in range(256):wb(ds,0x66e8+i,before)
  put(ss,sp,0x1111)
 def run():fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),C.byref(r))
 for token,state,writes,bp,di in [(0,0x55,23,0,0),(19,0x55,23,19,4),(20,2,24,20,5),(79,2,24,79,19)]:
  reset(token=token);run();require((r.status,r.current_sp,r.next_ip,r.guard_calls,r.sample_calls,r.child_calls,r.control_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.bp,r.returned.registers.di,r.returned.registers.es,r.returned.registers.interrupts_enabled,b(0x2000,0x5490))==(0,0xe002,0x1111,1,1,3,1,writes,50,1600,0x1234,800,bp,di,0x5432,1,state),'Inline-tokenBP/guard-low-high/actualchild '+str(token));vectors+=1
 for token,present,external,ax,bp,di,carry,zf in [(0,0,2,0,0,0,1,0),(19,0,2,19,19,76,1,0),(30,0,0,30,30,120,0,1),(80,0,0,80,0x5678,0x4567,0,1),(128,1,2,128,0x5678,0x4567,0,0),(255,1,2,255,0x5678,0x4567,0,0)]:
  reset(token=token,present=present,external=external);run();require((r.status,r.guard_calls,r.bus_writes,r.returned.registers.ax,r.returned.bp,r.returned.registers.di,r.returned.registers.es,r.returned.carry,r.zero_flag)==(0,0,0,ax,bp,di,0x5432,carry,zf),'Early-negative-lowtoken-zeroES/preservedBP '+str((token,present,external)));vectors+=1
 for selector in range(256):
  reset(selector=selector,token=128);run();require((r.status,r.returned.registers.ax,r.returned.registers.bx,r.returned.bp,r.bus_writes)==(0,128,selector&127,0x5678,0),'Maskedselector/wordCBW-AXzeroAH '+str(selector));vectors+=1
 for token in range(30,128):
  reset(token=token,present=0,width=7);q,rem=divmod(token-30,5)
  if rem:put(0x7000,2*q,0x3000);put(0x7000,0x3000,0xffff)
  limits.guard_calls=0;run();require((r.status,r.next_ip,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.es,r.returned.bp,r.bus_writes)==(3,0x4d0e,500,3,3,0x100,0x7000,token if token<80 else 0x5678,0),'BYTE-DIVAH-remainder-in-ESlookup/poisonquotientonly '+str(token));vectors+=1
 for token,di,bp in [(31,512,31),(124,2084,0x5678),(127,1062,0x5678)]:
  reset(token=token,present=0,external=1);run();require((r.status,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.es,r.returned.bp,r.returned.carry,r.zero_flag,r.bus_writes)==(0,0,0xc405,di,0x7000,bp,0,1,0),'ZeroESpointer-keepsAHindex-and-ES/CHCL5 '+str(token));vectors+=1
 for coefficient in [0,1,127,128,255]:
  for bit,flag in [(0,0),(0,1),(1,0),(1,1)]:
   reset(coefficient=coefficient,bit=bit,flag=flag);limits.guard_calls=0;run();signed=coefficient if coefficient<128 else coefficient-256;product=signed*50;center=product+500 if product>=0 else product-500;center+=400 if bit and center>=0 else -400 if bit and flag and center<0 else 0;require((r.status,r.next_ip,r.returned.registers.ax,r.returned.registers.bx,r.returned.bp,r.bus_writes)==(3,0x4d0e,center&65535,0,0,0),'BYTEsignedIMUL50/positive-negativecenters '+str((coefficient,bit,flag)));vectors+=1
 for width in [0,1,2,3,0x8000,0xffff]:
  reset(token=80,present=0,width=width);limits.guard_calls=0;run();require((r.status,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.es)==(3,width>>1,width>>1,0x7000),'Logicalwordwidth-half '+str(width));vectors+=1
 for width in [0,1,255]:
  reset(token=79,inline=width);limits.guard_calls=0;run();require((r.status,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.di,r.returned.bp)==(3,width,width,19,79),'Inlinebytewidth-XORCH/DIquarter');vectors+=1
 reset(token=80,present=0,bp=0,stack=0x2000,pointer=0x5efc);run();require((r.status,r.next_ip,r.returned.bp,b(0x2000,0x5490))==(0,0x1101,0x5494,0x55),'PrechildBPbelow20-no-force-afterBPbecomeshigh');vectors+=1
 reset(token=20,stack=0x2000,pointer=0x5f08);run();require((r.status,r.next_ip,r.returned.bp,b(0x2000,0x5490))==(0,0x1111,1,2),'PrechildBP20-force-afterflagaliasmakesBP1');vectors+=1
 reset(token=20,stack=0x2000,pointer=0x5490);run();require((r.status,r.next_ip,r.current_sp,b(0x2000,0x5490))==(0,0x1102,0x5492,2),'PostchildforcedbytealiasesparentrootnearIP');vectors+=1
 for token,site,carry in [(0,0x4d14,1),(20,0x4d1d,0),(80,0x4d14,1)]:
  reset(token=token,present=0 if token==80 else 1,bp=0);limits.sample_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.guard_calls,r.sample_calls,r.bus_writes,r.returned.carry)==(3,site,sp,1,0,2,carry),'PrechildunsignedBPbranch/budget '+str(token));vectors+=1
 reset();limits.guard_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.flags_valid)==(3,0x4d0e,sp,0,0),'Guardbudget');vectors+=1
 reset();limits.child.calls=0;run();require((r.status,r.next_ip,r.current_sp,r.sample_calls,r.child_calls,r.bus_writes,r.returned.registers.dx)==(3,0x4a31,sp-2,1,0,3,1600),'Childbudgetafteractualparentnearframe');vectors+=1
 reset();limits.child.control_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.control_calls,r.bus_writes)==(3,0x460e,sp-4,0,5),'Nestedcontrolbudget');vectors+=1
 for pointer,ip,cursor in [(0x3332,800,1),(0x52d2,0x43f4,1),(0x5efa,0x5494,1),(0x66ec,0x4a45,1),(0x67a2,0x4a8d,0xb5)]:
  reset(stack=0x2000,pointer=pointer,cursor=cursor);run();require((r.status,r.next_ip,r.flags_valid)==(1,ip,0),'Actualcontrol-setter-ringRETalias '+hex(pointer));vectors+=1
 for token,pointer,before,selector,ip in [(0,0x33c8,0,1,0x4d47),(20,0x33c8,0,1,0x4d59),(0,0x33ca,13,1,0x9e16),(20,0x33ca,13,1,0x9e28),(0,0x33cc,25,1,0x4ccc),(20,0x33cc,25,1,0x4cd5),(0,0x33ce,38,1,0x4d3c),(20,0x33ce,38,1,0x4d45),(20,0x3448,50,135,0x4d01)]:
  reset(token=token,stack=0x2000,pointer=pointer,before=before,raw_selector=selector);run();require((r.status,r.next_ip,r.current_sp,r.flags_valid,b(0x2000,0x5490))==(1,ip,pointer,0,7 if before==38 else 0x55),'ChangedchildnearRET-preventsforcedstore '+str((token,pointer)));vectors+=1
 reset(stack=0x2000,pointer=0x66ee);run();require((r.status,r.returned.registers.si)==(0,0x3455),'ChildringPUSHSIcursoralias');vectors+=1
 reset(stack=0x2000,pointer=0x672d,cursor=0x3e);run();require((r.status,r.returned.registers.si,r.returned.registers.ax)==(0,0x34ad,0xad),'ChildringPUSHSIselectedbytealias');vectors+=1
 for token,flags in [(t,f) for t in [0,20,128] for f in [2,0x203,0x402,0x603]]:
  reset(token=token,flags=flags);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,(flags>>9)&1 if token==128 else 1,(flags>>10)&1),'ConditionalIF1/DFretained');vectors+=1
 for pointer in [22,0xffe0]:
  reset(pointer=pointer);run();require((r.status,r.current_sp)==(0,pointer+2),'RootSPdomain');vectors+=1
 for ds in [0,0xffff]:
  reset(ds=ds,stack=ds,pointer=22);run();require((r.status,r.current_sp,r.returned.registers.ds)==(0,24,ds),'Zero-highDS/fullSS20bitRAM');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_indexed_sample.py','sha256':hashlib.sha256((ROOT/'tools/validate_indexed_sample.py').read_bytes()).hexdigest()}],'limits':'Native4C85all256maskedselectors/98BYTE-DIV-AHlookupcaseswithpoisonquotient-onlyslots/signedBYTEIMULcenters/inline-or-ESwidth/zeroESpointerflags/BPtoken-vs-preserved/cachedprechildBPforce-after-postBPchanges/actualSSnear-farRET-and-SIaliases/globalCALLbudgets/conditionalIF1-DF/SPdomains/zero-highDS only. Staticreview-originalcomparisonseparate; no actualobjects-capacities-table-allwriters-fieldunits-sharedsource-reset-IRQ-lifetime-fullcaller-core/DOSsession/renderer/audio/fullstate/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
