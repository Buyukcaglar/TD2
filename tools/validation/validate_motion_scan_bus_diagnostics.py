"""Native interface rejection, far cleanup, undefined-MUL flags and raw dispatch."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_motion_scan_bus import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_motion_scan_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*4+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x8000,0,0),0x5678,0);r=Result();vectors=0
 for memory,count,sp,entry,state in [(None,len(bus),0xe000,0,C.byref(s)),(bus,len(bus)-1,0xe000,0,C.byref(s)),(bus,len(bus),0xe000,0,None),(bus,len(bus),0xe000,3,C.byref(s)),(bus,len(bus),19,0,C.byref(s)),(bus,len(bus),0xffe1,0,C.byref(s)),(bus,len(bus),0xffff,2,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid before effects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(s),1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid boolean');setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(s),1,None);require(not any(bus),'Null output');vectors+=1
 def put(sg,o,v):
  at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.flags_valid)==(3,0xdff2,0x16b3,0x114,0,8,0),'Actual args before farCALL budget');require(bytes(bus[0x9e000:0x9e004])==bytes.fromhex('11112222'),'Budget preserves root far frame');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes)==(0,0xe004,0x2222,0x1111,1,13),'Motion plain farRET after childRET8');require((r.returned.registers.ax,r.returned.registers.dx,r.returned.bp,r.returned.carry,r.flags_valid,r.zero_flag)==(0,0,0x5678,1,1,0),'Motion finalCMP carries raw flags');vectors+=1
 for hi in [0,0xffff]:
  for offset,value in [(4,0xffff),(6,hi),(8,0xffff),(10,hi)]:put(0x9000,0xe000+offset,value)
  fn(bus,len(bus),0x1000,0x9000,0xe000,1,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.returned.bp)==(0,0xe00c,0x2222,0x1111,1,0x5678),'Multiply literalRETF8');require(r.returned.registers.ax==1 and r.returned.registers.bx==0xffff and r.returned.carry==1,'Multiply word outputs/carry')
  if hi:require((r.returned.registers.dx,r.returned.registers.cx,r.flags_valid,r.zero_flag)==(0,2,1,1),'General finalADD-DX flags')
  else:require((r.returned.registers.dx,r.returned.registers.cx,r.flags_valid,r.zero_flag)==(0xfffe,0xc456,0,0),'FastMUL preservesCX/undefinedZF omitted')
  vectors+=1
 s.registers.ax=0;s.registers.direction=1;put(0x9000,0xfffe,0x1111);fn(bus,len(bus),0x1000,0x9000,0xfffe,2,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.returned.registers.direction,r.returned.carry,r.flags_valid,r.zero_flag)==(0,0,0x16c9,0x1111,0,1,0,1,1),'AX0 shortcut nearRETwrap/DF retained');require((r.returned.registers.cx,r.returned.registers.di,r.returned.registers.bx)==(0xc456,0x4567,0xb123),'AX0 shortcut leaves scanner registers');vectors+=1
 s.registers.ax=0xa501
 for i in range(5):bus[0x833da-i]=2
 bus[0x833d6]=1;put(0x5000,0x33dc,0xffff);fn(bus,len(bus),0x1000,0x9000,0xe000,2,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.unresolved_target,r.bus_writes,r.returned.registers.direction,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.bx)==(4,0xe000,0x16c9,0x44ba,0xffff,0,0,0,0x33d5,0),'Unknown scanner target beforeJMP/ESreverse scan');vectors+=1
 put(0x5000,0x33dc,0x44be);fn(bus,len(bus),0x1000,0x9000,0xe000,2,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.flags_valid,r.zero_flag)==(0,0xe002,0x16c9,0x1111,0,1,1),'Known bareRET tail/SHL-definedZF');vectors+=1
 deps=['tools/validate_motion_scan_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Native-only rejection-before-effects/nulloutput/actualargs-beforeCALLbudget/plainRETF-versusRETF8/general-finalADD-CFZF-versusundefinedfastMULZF/AX0DFshortcut-nearSPwrap/ESscan-beforeunknownJMP/knownbareRETtail. Separatefromoriginalcomparison/whole420A-403B/IRQ/core/game/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
