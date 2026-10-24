"""Native-only invalid-input checks for eleven near-target bus views."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_sim_dispatch_bus import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 fn=C.CDLL(str(lib)).td2ega_sim_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*4+[C.POINTER(StateRegisters),C.c_uint16,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,entry,s,zf in [(None,len(bus),0,0,C.byref(state),0),(bus,len(bus)-1,0,0,C.byref(state),0),(bus,len(bus),0xffff,0,C.byref(state),0),(bus,len(bus),0,11,C.byref(state),0),(bus,len(bus),0,0,None,0),(bus,len(bus),0,0,C.byref(state),2)]:
  fn(memory,count,0x1000,0x9000,sp,entry,s,zf,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0,0,C.byref(state),0,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0,0,C.byref(state),0,None);require(not any(bus),'Nulloutputbeforeeffects');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sim_dispatch_bus.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_dispatch_bus.py').read_bytes()).hexdigest()}],'limits':'Ten native-only null/count/SP/entry/inputZF/booleanflag checks before effects. Notoriginalbehavior/caller-IRQ-core/game-fidelity evidence.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
