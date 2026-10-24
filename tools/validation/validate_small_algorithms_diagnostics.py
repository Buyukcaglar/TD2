"""Native-only small algorithm profile, minimum-stack and budget checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_small_algorithms import Registers,StateRegisters,Result,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_small_algorithms;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result()
    for memory,count,sp,entry,s in [(bus,len(bus)-1,0xe000,0,C.byref(state)),(bus,len(bus),0,0,C.byref(state)),(bus,len(bus),31,0,C.byref(state)),(bus,len(bus),0xffff,0,C.byref(state)),(None,len(bus),0xe000,0,C.byref(state)),(bus,len(bus),0xe000,0,None),(bus,len(bus),0xe000,3,C.byref(state))]:
        fn(memory,count,0x1000,0x9000,sp,entry,s,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    bus[0x3133c]=0x80;state.registers.ax=0x7fff;fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(state),0,C.byref(r));require(r.status==0 and r.current_sp==34 and r.returned.registers.ax==320 and r.bus_writes==0,'Finiteclamp/minimumSP32/noiterationbudget')
    state.registers.ax=0;fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),0,C.byref(r));require(r.status==0 and r.returned.registers.ax==90 and r.current_sp==34,'Finitezero-difference ratio')
    state.registers.cx=3;fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),0,C.byref(r));require(r.status==0 and r.returned.registers.ax==76 and r.returned.carry==0,'GuardedbyteDIV384/5')
    fn(bus,len(bus),0x1000,0x9000,32,2,C.byref(state),0,C.byref(r));require(r.status==3 and r.next_ip==0x72 and r.current_sp==26 and r.bus_writes==3,'Beforelabelscanprefix')
    fn(bus,len(bus),0x1000,0x9000,32,2,C.byref(state),20,C.byref(r));require(r.status==0 and r.current_sp==36 and r.iterations==20 and r.bus_writes==40 and r.returned.registers.bx==18,'Nearoffsetzero/minimum18pad/fullstack')
    record={'schema':1,'result':'pass','vectors':15,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_small_algorithms.py','sha256':hashlib.sha256((ROOT/'tools/validate_small_algorithms.py').read_bytes()).hexdigest()}],'limits':'Teninvalidbus/count/SP/null/selector/boolean profiles, minimumSP32finiteclamp/ratio/guardedDIV, labelbudget/nearoffsetzero/minimum18pad. Nativeonly; actualcaller/fields/bounds/writers/lifetime/core/device/session/game/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':15}))
if __name__=='__main__':main()
