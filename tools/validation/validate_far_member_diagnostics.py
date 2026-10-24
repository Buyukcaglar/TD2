"""Native-only far-address interface and word-wrap convention checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_far_member import Registers,StateRegisters,Result,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_far_member;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
    for memory,count,sp,s in [(bus,len(bus)-1,0xe000,C.byref(state)),(bus,len(bus),0,C.byref(state)),(bus,len(bus),0xffff,C.byref(state)),(None,len(bus),0xe000,C.byref(state)),(bus,len(bus),0xe000,None)]:
        fn(memory,count,0x1000,0x9000,sp,s,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(state),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    def put(at,v):bus[at]=v&255;bus[at+1]=(v>>8)&255
    put(0x90000+16+6,0x3000);put(0x30006,10);fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),C.byref(r));require(r.status==0 and r.current_sp==20 and r.returned.registers.ax==0 and r.returned.registers.dx==0x3001 and r.bus_writes==2,'MinimumSP16offsetzero/nonzerosegment')
    put(0x30004,0x2000);put(0x38006,0);put(0x38008,0);fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),C.byref(r));require((r.returned.registers.ax,r.returned.registers.dx)==(6,0x3000),'Headerwordbasehighcarrytruncated')
    put(0x30004,0);put(0x90000+16+8,0x3ffe);put(0x3fffe,0);put(0x30000,1);put(0x40000,0x1357);fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),C.byref(r));require((r.returned.registers.ax,r.returned.registers.dx)==(6,0x4000),'Separatelywrappedtablehighword')
    put(0x90000+16+8,0);put(0x30006,7);put(0x30008,0);fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),C.byref(r));require(r.returned.registers.ax==13 and r.returned.carry==1,'FinalRCRcarrylinearbit3')
    record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_far_member.py','sha256':hashlib.sha256((ROOT/'tools/validate_far_member.py').read_bytes()).hexdigest()}],'limits':'Eightinvalidbus/count/SP/null/boolean profiles, minimumSP16zerooffset/nonzerosegment, wordbasecarrytruncation, separatelywrappedhighword andfinalRCRcarry. Nativeonly; actualcaller/resourcebounds/writers/lifetime/A20/device/session/game/core/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
