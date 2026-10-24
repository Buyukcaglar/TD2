"""Native-only record-kernel interface and saved-SI budget checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_math import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_record_math;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,entry,state in [(bus,len(bus)-1,16,0,C.byref(s)),(bus,len(bus),0,0,C.byref(s)),(bus,len(bus),0xffff,0,C.byref(s)),(None,len(bus),16,0,C.byref(s)),(bus,len(bus),16,0,None),(bus,len(bus),16,5,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,4,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,16,0,C.byref(s),4,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,16,0,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes)==(3,14,0x52bf,0,3),'5299 before-first-iteration with actual AXsave')
 fn(bus,len(bus),0x1000,0x9000,16,0,C.byref(s),4,C.byref(r));require((r.status,r.current_sp,r.iterations,r.returned.registers.ax,r.returned.registers.bx)==(0,18,4,0,0),'5299 minimumSP16 normal near return')
 s.bp=0x3813;s.registers.cx=8;bus[0x40000+0x33b9]=1
 fn(bus,len(bus),0x1000,0x9000,16,3,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes,r.returned.registers.dx)==(3,14,0x4fda,0,1,1),'4F92 updating-path saved SI before store budget')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_math.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_math.py').read_bytes()).hexdigest()}],'limits':'Nine invalid profiles before bus effects, actual AXsave budget, minimumSP16 near return and actual SIsave budget. Native-only; counters, source errors, source units/recordbounds/caller/writer/lifetime/core/device/session/gameplay/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
