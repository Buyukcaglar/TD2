"""Native-only595F interface, beforeCALL and minimumSP checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_pair_controller import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/freshpaths');fn=C.CDLL(str(lib)).td2ega_pair_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,18,C.byref(s)),(bus,len(bus),17,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),18,C.byref(s)),(bus,len(bus),18,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,3,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,18,C.byref(s),3,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,18,C.byref(s),3,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,18,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.calls,r.bus_writes)==(0,20,0,0),'MinimumSP18 no-call rootreturn');vectors+=1
 bus[0x43379]=1;fn(bus,len(bus),0x1000,0x9000,18,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,18,0x5976,0,0),'BeforeCALL/noSSframe');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,18,C.byref(s),3,C.byref(r));require((r.status,r.current_sp,r.calls,r.bus_writes)==(0,20,1,2),'ActualchildminimumSP16/frame andparentCXstore');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_pair_controller.py','sha256':hashlib.sha256((ROOT/'tools/validate_pair_controller.py').read_bytes()).hexdigest()}],'limits':'Eightinvalid/noeffects, nullresult/minimumSP18 skiproot/beforeCALL/actualchildminimumSP16 andparentstore. Nativeonly, notwhole403B/caller/writer/lifetime/IRQ/fullstate/core/runtime/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
