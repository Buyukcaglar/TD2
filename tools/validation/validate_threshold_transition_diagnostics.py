"""Native4B9A signed thresholds/literal transitions/interpolation/IDIV prefixes/SS/controlZF."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_threshold_transition import Registers,StateRegisters,Limits,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_threshold_transition;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x5432,0,1),0x5678,1);r=Result();limits=Limits(4,1);ss=0x9000;sp=0xe000;vectors=0
 for memory,size,pointer,state,bounds in [(None,len(bus),20,C.byref(s),C.byref(limits)),(bus,len(bus)-1,20,C.byref(s),C.byref(limits)),(bus,len(bus),19,C.byref(s),C.byref(limits)),(bus,len(bus),0xffe1,C.byref(s),C.byref(limits)),(bus,len(bus),20,None,C.byref(limits)),(bus,len(bus),20,C.byref(s),None)]:
  fn(memory,size,0x1000,ss,pointer,state,bounds,C.byref(r));require((r.status,r.rows,r.bus_writes,r.flags_valid)==(2,0,0,0) and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,20,C.byref(s),C.byref(limits),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,20,C.byref(s),C.byref(limits),None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def wb(sg,o,v):bus[((sg<<4)+(o&65535))&0xfffff]=v&255
 def b(sg,o):return bus[((sg<<4)+(o&65535))&0xfffff]
 def reset(direction=0,mode=0,minimum=0,maximum=1000,x=1,table=None,control=2000,multiplier=0x8000,selector=1,stack=0x9000,pointer=0xe000,ds=0x2000,flags=0x402,long=False):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.ds=ds;s.registers.interrupts_enabled=(flags>>9)&1;s.registers.direction=(flags>>10)&1;s.carry=flags&1;limits.rows=4;limits.control_calls=1
  if long:
   for i in range(8192):put(ds,0x37a6+8*i,1);put(ds,0x37a8+8*i,0)
  else:
   for i,row in enumerate((table or [])+[(0,0,0,0)]):
    for j,v in enumerate(row):put(ds,0x37a6+8*i+2*j,v)
  for o,v in [(0x3332,direction),(0x3334,minimum),(0x3336,maximum),(0x52ca,0x3b33+x),(0x52ce,control),(0x3328,multiplier),(0x332c,0x1234)]:put(ds,o,v)
  wb(ds,0x5491,mode);wb(ds,0x2f56,selector);put(ss,sp,0x1111)
 def run():fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_ip,r.rows,r.control_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.si,r.returned.bp,r.returned.carry,r.zero_flag,r.flags_valid)==(0,0xe002,0x1111,1,1,5,0,1000,0x1234,800,0,0x5678,1,0,1),'Zerohead-to-actualcontrol/defaultZF');vectors+=1
 for direction,mode,bx,state in [(0,4,570,2),(0,5,970,2),(0x8000,0x20,(-650)&65535,1),(0x8000,0x21,(-1050)&65535,1)]:
  reset(direction=direction,mode=mode,minimum=0xfc18);run();require((r.status,r.rows,r.bus_writes,b(0x2000,0x33d4),word(0x2000,0x33d0),word(0x2000,0x33d2),word(0x2000,0x33ce),b(0x2000,0x33b2),b(0x2000,0x336f),r.returned.registers.ax,r.returned.carry,r.zero_flag)==(0,0,6,state,bx,0,0,0,0,0,0,1),'Literaltransition/signextendedimmediate '+str((direction,mode)));vectors+=1
 for direction,mode,bx,carry in [(0,2,370,0),(0,3,770,0),(0,0x80,270,0),(0x8000,0x80,(-350)&65535,1),(0x8000,0x10,(-450)&65535,1),(0x8000,0x11,(-850)&65535,1)]:
  reset(direction=direction,mode=mode,minimum=0xfc18);run();require((r.status,r.rows,r.bus_writes,word(0x2000,0x52cc),b(0x2000,0x5490),r.returned.registers.bx,r.returned.carry,r.zero_flag)==(0,0,2,bx,2,bx,carry,0),'State2rawsignedbranch '+str((direction,mode)));vectors+=1
 for direction,minimum,maximum,carry,zf in [(0,0,500,0,1),(0,0,499,1,0),(0x8000,(-500)&65535,0,0,1),(0x8000,(-499)&65535,0,0,0),(0x8000,0,0,1,0)]:
  reset(direction=direction,minimum=minimum,maximum=maximum);run();require((r.status,r.rows,r.bus_writes,r.returned.carry,r.zero_flag)==(0,0,0,carry,zf),'Signedthreshold/unsignedCF earlyreturn');vectors+=1
 for row,x,minimum,bx,dx,cx,bp in [((1,10,0,100),5,600,588,4,0,9),((1,10,10,100),5,600,600,0,10,9),((1,10,100,0),5,700,612,0xfffc,100,9),((1,0x8001,0,100),1001,600,494,1696,0,0x8000)]:
  reset(table=[row],x=x,minimum=minimum);run();require((r.status,r.rows,r.bus_writes,b(0x2000,0x33d4),word(0x2000,0x33d0),r.returned.registers.dx,r.returned.registers.cx,r.returned.bp,r.returned.registers.si,r.returned.registers.ax,r.returned.carry,r.zero_flag)==(0,1,6,4,bx,dx,cx,bp,0,0,0,1),'SignedIMUL-IDIV-truncation/BPclobber '+str(row));vectors+=1
 reset(table=[(1,10,0,100)],x=5,minimum=500);run();require((r.status,r.rows,r.control_calls,r.returned.bp,r.returned.registers.si,r.returned.registers.dx)==(0,1,1,9,0,800),'Interpolationreject-retainsBP-beforecontrol');vectors+=1
 for row,x,ax,dx,bp,carry in [((100,100,0,1),100,0,0,0,0),((1,0xffff,0,32767),0x8000,1,0x3fff,0xfffe,1)]:
  reset(table=[row],x=x);run();require((r.status,r.next_ip,r.current_sp,r.rows,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx,r.returned.bp,r.returned.carry,r.flags_valid)==(4,0x4c68,sp,1,0,ax,dx,bp,carry,0),'PreIDIVzero-overflowprefix '+str(row));vectors+=1
 reset(table=[(1,10,0,100)],x=5);limits.rows=0;run();require((r.status,r.next_ip,r.rows,r.bus_writes,r.returned.registers.si,r.returned.registers.dx,r.returned.bp,r.flags_valid)==(3,0x4c3e,0,0,0,5,0x5678,0),'Firstrowbudgetaftercoordinatesubtract');vectors+=1
 reset(table=[(1,2,0,10),(3,10,10,100)],x=8);limits.rows=1;run();require((r.status,r.next_ip,r.rows,r.returned.registers.si,r.returned.registers.dx,r.returned.bp)==(3,0x4c3e,1,8,8,2),'SecondrowbudgetafterliteralSIadd');vectors+=1
 for control,selector,dx,zf,carry in [(0,1,1000,1,0),(1000,1,800,0,1),(2000,1,800,0,1),(2600,1,800,1,0),(2000,0,1000,1,0)]:
  reset(control=control,selector=selector);run();require((r.status,r.returned.registers.dx,r.zero_flag,r.returned.carry)==(0,dx,zf,carry),'Actual45FCzerochange-selector-MULCMP-ZF '+str((control,selector)));vectors+=1
 reset();limits.control_calls=0;run();require((r.status,r.next_ip,r.current_sp,r.rows,r.control_calls,r.bus_writes,word(0x2000,0x52ce),r.flags_valid)==(3,0x460e,sp-2,1,0,2,1000,0),'Nestedcontrolbudgetretainsouterframe-fieldstore');vectors+=1
 for pointer,ip in [(0x33d0,570),(0x33d2,0),(0x33ce,0),(0x33b2,0x1100),(0x336f,0x1100),(0x33d4,0x1102)]:
  reset(mode=4,stack=0x2000,pointer=pointer);run();require((r.status,r.next_ip,r.current_sp,r.flags_valid)==(0,ip,pointer+2,1),'Literaltransitionaliasesrootnearframe '+hex(pointer));vectors+=1
 reset(mode=2,stack=0x2000,pointer=0x52cc);run();require((r.status,r.next_ip,r.current_sp)==(0,370,0x52ce),'State2aliasesrootnearframe');vectors+=1
 for pointer,ip in [(0x3330,800),(0x52d0,0x489c)]:
  reset(direction=0x8000,minimum=0xfc18,stack=0x2000,pointer=pointer);run();require((r.status,r.next_ip,r.flags_valid)==(1,ip,0),'ActualcontrolRETalias '+hex(pointer));vectors+=1
 reset(long=True,multiplier=0);limits.rows=8193;run();require((r.status,r.next_ip,r.rows,r.returned.registers.si,r.returned.registers.dx,r.returned.bp,r.bus_writes)==(3,0x4c3e,8193,8,1,0,0),'Full8192indexcycle-plusone/rawtableheadbudget');vectors+=1
 for flags in [2,0x203,0x402,0x603]:
  reset(flags=flags);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,(flags>>9)&1,(flags>>10)&1),'IFDFpreserved');vectors+=1
 for pointer in [20,0xffe0]:
  reset(pointer=pointer);run();require((r.status,r.current_sp)==(0,pointer+2),'RootSPdomain');vectors+=1
 for ds in [0,0xffff]:
  reset(ds=ds,stack=ds,pointer=20);run();require((r.status,r.current_sp,r.returned.registers.ds)==(0,22,ds),'Zero-highDS/fullSS20bitbus');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_threshold_transition.py','sha256':hashlib.sha256((ROOT/'tools/validate_threshold_transition.py').read_bytes()).hexdigest()}],'limits':'Native4B9A/fullSS/signedthresholds/signextendedimmediates/orderedtransitionwrites/signedIMUL-IDIVtruncation-negativeproduct-negativeBP/preIDIVzero-overflowprefix/BP-SIclobbers/actual45FC-ZF/globalrow-controlbudgets/fullindexwrap/root-childRETaliases/IFDF/SPdomain/zero-highDS only. Staticreview-originalcomparison separate. No tablecapacity-allwriters-validresource-fields/fullcaller-storage-lifetime-IRQ-core/DOSsession/renderer/audio/fullstate/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
