"""Native-only50A1 interface/earlypaths/root-childbudgets/zeroDIV/minimumSP34."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_secondary_fields import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/freshpaths');fn=C.CDLL(str(lib)).td2ega_secondary_fields;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,34,C.byref(s)),(bus,len(bus),33,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),34,C.byref(s)),(bus,len(bus),34,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,10,4,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),10,4,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),10,4,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),0,0,C.byref(r));require((r.status,r.current_sp,r.calls,r.bus_writes,r.returned.registers.ax)==(0,36,0,2,0xa55a),'Disabledpath bypassesbudgets');vectors+=1
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=(v>>8)&255
 bus[0x43379]=1;bus[0x43375]=2;fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),0,0,C.byref(r));require((r.status,r.calls,r.bus_writes,bus[0x43375],r.returned.registers.ax,r.returned.carry)==(0,0,2,1,0xa55a,0),'DECnonzero/CFpreserved');vectors+=1
 bus[0x43375]=1;put(0x52c8,1);fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),0,0,C.byref(r));require((r.status,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.carry)==(0,0,4,65535,0) and bus[0x452d4]==0x38 and bus[0x452d5]==0xff,'DECreacheszero/SBB/angle-200');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),0,4,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,34,0x50f7,0,1),'BeforefirstCALL');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),10,0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,30,0x52bf,1,5),'Actual5299loop/frame/saveAX prefix');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),10,4,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.returned.registers.di,r.returned.carry)==(5,32,0x5c79,2,0,0),'ActualzeroDIV beforeinstruction/faultdelivery');vectors+=1
 put(0x3318,0x100);put(0x52d2,0x8000);bus[0x433b6]=0;bus[0x433b7]=0;fn(bus,len(bus),0x1000,0x9000,34,C.byref(s),10,4,C.byref(r));require((r.status,r.current_sp,r.calls)==(0,36,6),'MinimumSP34 normalreturn/sixcalls');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_secondary_fields.py','sha256':hashlib.sha256((ROOT/'tools/validate_secondary_fields.py').read_bytes()).hexdigest()}],'limits':'Eightinvalid/noeffects/nullresult/disabled-DECearlypaths/rootCALL-childloopbudgets/actualzeroDIVbeforefaultdelivery/minSP34 normalreturn. Nativeonly, notcaller/tablewriters/lifetime/IRQ/core/resource/device/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
