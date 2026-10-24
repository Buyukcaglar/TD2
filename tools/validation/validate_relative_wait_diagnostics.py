"""Native-only relative-wait invalid interface and observer failure checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_relative_wait import Registers,StateRegisters,Result,Observer,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_relative_wait;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Observer,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();null=Observer()
 for memory,count,sp,s in [(bus,len(bus)-1,0xe000,C.byref(state)),(bus,len(bus),0,C.byref(state)),(bus,len(bus),31,C.byref(state)),(bus,len(bus),0xffff,C.byref(state)),(None,len(bus),0xe000,C.byref(state)),(bus,len(bus),0xe000,None)]:
  fn(memory,count,0x1000,0x9000,sp,s,null,None,2,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,32,C.byref(state),null,None,2,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,32,C.byref(state),null,None,0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.reads,r.bus_writes)==(3,26,0xc6cb,0,1),'Before-first-call prefix')
 @Observer
 def reject(context,memory,request):return 0
 fn(bus,len(bus),0x1000,0x9000,32,C.byref(state),reject,None,2,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.reads,r.bus_writes,r.returned.registers.interrupts_enabled)==(4,22,0xc692,1,3,0),'Observer rejection before CLI')
 fn(bus,len(bus),0x1000,0x9000,32,C.byref(state),null,None,2,C.byref(r));require((r.status,r.current_sp,r.reads,r.returned.registers.interrupts_enabled)==(0,36,2,1),'MinimumSP32 stable bus/IF1')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_relative_wait.py','sha256':hashlib.sha256((ROOT/'tools/validate_relative_wait.py').read_bytes()).hexdigest()}],'limits':'Nine invalid profiles without bus effects, before-call budget, observer rejection retaining actual child frame/before CLI and minimumSP32 normal IF1. Native diagnostics separate from original comparison totals, source errors, real counter writer/IRQ/timer/session/gameplay/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
