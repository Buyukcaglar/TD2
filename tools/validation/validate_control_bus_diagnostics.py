"""Native-onlycontrolbusinterface/nestedSSRET/CFandminimumSP18 checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_control_bus import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/freshpaths');fn=C.CDLL(str(lib)).td2ega_control_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,entry,state in [(bus,len(bus)-1,18,0,C.byref(s)),(bus,len(bus),17,0,C.byref(s)),(bus,len(bus),0xffff,0,C.byref(s)),(bus,len(bus),18,5,C.byref(s)),(None,len(bus),18,0,C.byref(s)),(bus,len(bus),18,0,None)]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,18,0,C.byref(s),1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,18,0,C.byref(s),1,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=(v>>8)&255
 put(0x52ce,1600);fn(bus,len(bus),0x1000,0x9000,18,1,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,18,0x460e,0,1),'Before460E/52CEwrite');vectors+=1
 put(0x52ce,1600);fn(bus,len(bus),0x1000,0x9000,18,1,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.calls,r.bus_writes,r.returned.carry)==(0,20,1,2,0),'MinimumSP18 actualchildskip/nearframes');vectors+=1
 bus[0x42f56]=1;put(0x3328,0xffff);put(0x52ce,0xffff);fn(bus,len(bus),0x1000,0x9000,18,3,C.byref(s),1,C.byref(r));require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,1,0xfffe,0),'UnsignedMULhigh/lastCMPcarry');vectors+=1
 put(0x52ce,3200);fn(bus,len(bus),0x1000,0x4000,0x332e,1,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(1,0x332e,1599,1,4),'ChildnearRETwordoverwrittenbyproduct');vectors+=1
 put(0x3328,0);fn(bus,len(bus),0x1000,0x4000,0x332c,3,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.returned.carry)==(0,0x332e,800,1),'RootRETwordoverwritten/clampCMPcarry');vectors+=1
 put(0x332c,1000);fn(bus,len(bus),0x1000,0x9000,18,0,C.byref(s),1,C.byref(r));require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.bus_writes)==(0,800,1000,1,2),'4588CMPAXDXcarry');vectors+=1
 put(0x332c,800);fn(bus,len(bus),0x1000,0x9000,18,0,C.byref(s),1,C.byref(r));require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.bus_writes)==(0,800,800,0,0),'4588equality/nochange');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_control_bus.py','sha256':hashlib.sha256((ROOT/'tools/validate_control_bus.py').read_bytes()).hexdigest()}],'limits':'Nineinvalid/noeffects/nullresult/beforeCALL/minSP18/unsignedMUL-CMPcarry/actualchild-rootRETaliases/4588carry-equality checks. Nativeonly, notallcaller/writer/lifetime/IRQ/core/resource/device/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
