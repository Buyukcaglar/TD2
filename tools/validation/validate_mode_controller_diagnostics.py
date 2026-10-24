"""Native 53A6 interface, distinct budgets, raw jumps and actual SS unwinds."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_mode_controller import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');fn=C.CDLL(str(lib)).td2ega_mode_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,36,C.byref(s)),(bus,len(bus),35,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),36,C.byref(s)),(bus,len(bus),36,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,2,8,8,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid before effects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,36,C.byref(s),2,8,8,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,36,C.byref(s),2,8,8,None);require(not any(bus),'Null result');vectors+=1
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=(v>>8)&255
 def reset(b6=0,b7=0,sp=36,ss=0x9000):
  C.memset(bus,0,len(bus));put(0x52da,1);bus[0x433b6]=b6;bus[0x433b7]=b7;bus[(ss<<4)+sp]=0x11;bus[(ss<<4)+sp+1]=0x11
 def run(root=2,leaf=8,it=8,sp=36,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),root,leaf,it,C.byref(r))
 reset(1);run(root=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,36,0x54f4,0,4),'Root CALL budget after entry effects');vectors+=1
 reset(1);run(leaf=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.nested_calls,r.bus_writes)==(3,34,0x56fa,1,0,6),'Leaf CALL budget after actual outer frame');vectors+=1
 reset(1);run(it=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.nested_calls,r.iterations,r.bus_writes)==(3,30,0x52bf,1,1,0,10),'5299 loop budget after actual saves');vectors+=1
 reset(0,6);run();require((r.status,r.current_sp,r.next_ip,r.dispatch_site,r.dispatch_offset,r.raw_target)==(6,36,0x55a1,0x55a1,0x3450,0),'Unknown parent word before transfer');vectors+=1
 reset(1);run();require((r.status,r.current_sp,r.next_ip,r.dispatch_site,r.dispatch_offset)==(6,34,0x57a7,0x57a7,0x3460),'Unknown child word before transfer');vectors+=1
 reset(0,6);put(0x3450,0x5620);run();require((r.status,r.current_sp,r.next_ip,r.raw_target,bus[0x433bb])==(0,38,0x1111,0x5620,255),'Known raw parent target/ordinary nearRET');vectors+=1
 reset(0,1);put(0x3460,0x57b7);put(0x52ca,201);put(0x380d,1000);run();require((r.status,r.current_sp,r.next_ip,r.exit_kind,r.returned.registers.ax,bus[0x49258])==(0,38,0x1111,1,0x5584,1),'Nonlocal POP childreturn/RET root/noextraRET');vectors+=1
 reset(0,7);put(0x3452,0x5637);put(0x52da,4);run();require((r.status,r.current_sp,r.returned.registers.ax,bus[0x433b7])==(0,38,4,7),'Actual PUSHAX/POPAX ordinary save');vectors+=1
 reset(0,7,0x2f5d,0x4000);put(0x3452,0x5637);put(0x52da,4);run(sp=0x2f5d,ss=0x4000);require((r.status,r.current_sp,r.returned.registers.ax,bus[0x433b7])==(0,0x2f5f,1,6),'Postwrite2F5B changes saved AX before POP');vectors+=1
 reset(0,6,0x3374,0x4000);put(0x3450,0x5620);run(sp=0x3374,ss=0x4000);require((r.status,r.current_sp,r.next_ip)==(0,0x3376,0x1100),'Entry byteclear changes actual root return');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_mode_controller.py','sha256':hashlib.sha256((ROOT/'tools/validate_mode_controller.py').read_bytes()).hexdigest()}],'limits':'Native interface/budget/unknown-transfer/knownretarget/actualSSsavedAX andtwo-wordnonlocalparentreturn diagnostics only. Originalx86 comparison separate; noallwriters/domain/caller/core/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
