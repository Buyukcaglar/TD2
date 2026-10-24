"""Native-only first ring consumer interface, zero budget and raw child RET."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_ring_selection import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_ring_selection;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,state in [(bus,len(bus)-1,30,C.byref(s)),(bus,len(bus),29,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),30,C.byref(s)),(bus,len(bus),30,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),1,None);require(not any(bus),'Null result no effects')
 fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,22,0xa,0,1),'BeforeactualCALL prefix')
 fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.bus_writes)==(0,34,0x5000,0,1,9),'MinimumSP30 completecategory1')
 bus[0x466e6]=0;bus[0x466e7]=0;fn(bus,len(bus),0x1000,0x4000,0x67f2,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.ax)==(1,0x67ea,0x119e,0x10f,1),'Actualselectedbyte changeschildreturnhighbyte')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_ring_selection.py','sha256':hashlib.sha256((ROOT/'tools/validate_ring_selection.py').read_bytes()).hexdigest()}],'limits':'Eightinvalid/noeffects, nullresult, beforeCALL, minimumSP30normalcategory andrawchildRETafterselectedbyteoverwritesreturnhighbyte. Native only; sourceCtype/wholecaller/reset/writer/lifetime/IRQexclusion/core/runtime/gameplay/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
