"""Native-only4D3F interface, minimumSP and root/child prefix checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_controller import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_record_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint16,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,state,af in [(bus,len(bus)-1,20,C.byref(s),0),(bus,len(bus),19,C.byref(s),0),(bus,len(bus),0xffff,C.byref(s),0),(None,len(bus),20,C.byref(s),0),(bus,len(bus),20,None,0),(bus,len(bus),20,C.byref(s),2)]:
  fn(memory,count,0x1000,0x9000,sp,state,af,64,128,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,64,128,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,64,128,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,0,128,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.steps,r.calls,r.bus_writes)==(3,20,0x4d41,0,0,0),'Before firstloop');vectors+=1
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=(v>>8)&255
 for o,v in [(0x5354,8),(0x5356,8)]:put(o,v)
 fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,1,128,C.byref(r));require((r.status,r.next_ip,r.steps,r.bus_writes)==(3,0x4da3,1,3),'Before secondloop withfirstupdates');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,2,128,C.byref(r));require((r.status,r.next_ip,r.steps,r.calls,r.bus_writes)==(3,0x4e1d,2,0,8),'Before firstCALL');vectors+=1
 put(0x3332,0xff38);fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),0,64,0,C.byref(r));require((r.status,r.next_ip,r.current_sp,r.calls,r.defined_mask)==(3,0x4fda,16,1,0x603),'Actual childprefix/realnearframe/saveSI');vectors+=1
 for o,v in [(0x3815,0x8000),(0x39a5,0x8000),(0x33b8,0),(0x3379,0)]:put(o,v)
 fn(bus,len(bus),0x1000,0x9000,20,C.byref(s),1,64,128,C.byref(r));require((r.status,r.current_sp,r.steps,r.calls,r.flag_words_written,r.defined_mask)==(0,22,5,3,1,0xed7),'MinimumSP20 normalreturn/actualPUSHF '+str((r.status,r.current_sp,r.steps,r.calls,r.flag_words_written,r.defined_mask)));vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_controller.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_controller.py').read_bytes()).hexdigest()}],'limits':'Nineinvalid/noeffects/nullresult, rootloop/CALL andactualchildprefix/minimumSP20/realSSflagword checks. Nativeonly, notCPUAFpolicy/allcaller/writer/lifetime/IRQ/fullstate/core/runtime/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
