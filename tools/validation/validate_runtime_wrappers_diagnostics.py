"""Native-only wrapper minimum-stack and distinct pre-call ownership checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_wrappers import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_runtime_wrappers;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,entry,state in [(bus,len(bus)-1,22,0,C.byref(s)),(bus,len(bus),21,0,C.byref(s)),(bus,len(bus),25,1,C.byref(s)),(bus,len(bus),0xffff,0,C.byref(s)),(None,len(bus),22,0,C.byref(s)),(bus,len(bus),22,0,None),(bus,len(bus),30,2,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,22,0,C.byref(s),1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 bus[0x46f57]=4;fn(bus,len(bus),0x1000,0x9000,22,0,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,20,0x185d,0,1),'Minimum22 beforePUSHCS nochildframe')
 bus[0x90000+30]=0;bus[0x90000+31]=0x12;bus[0x41206]=9;bus[0x41204]=0;bus[0x41205]=0x13;fn(bus,len(bus),0x1000,0x9000,26,1,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,20,0xe06,0,3),'Minimum26 beforefarCALL retainsonearg')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_runtime_wrappers.py','sha256':hashlib.sha256((ROOT/'tools/validate_runtime_wrappers.py').read_bytes()).hexdigest()}],'limits':'Teninvalid/noeffects profiles andtwo minimum-SP distinctCALL-prefix profiles. Native only; source record/handle/lifetime/core/session/gameplay/fidelity acceptance separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
