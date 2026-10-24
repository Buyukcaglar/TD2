"""Native-only state-loop argument/budget/unknown-target diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_loop import Registers,State,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_state_loop;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(State),C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;ds=0x278f;m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,ds,0,0,1),0x5678,1);code=State();code.returns_state=2;events=[];selected=[0];out=Result()
    def service(ctx,bus,q,r):
        events.append(q.contents.site);C.memmove(r,C.byref(q.contents.incoming),C.sizeof(StateRegisters))
        if q.contents.site==0x1b88:bus[ds*16+0x5490]=selected[0]
        return 1
    cb=Service(service);fn(m,len(m),0x1000,C.byref(code),C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid tail before effects');code.returns_state=1
    fn(m,len(m),0x1000,C.byref(code),C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.calls==0 and out.returned.registers.direction==0 and not any(m),'Zero budget retains entryCLD prefix')
    selected[0]=10;struct.pack_into('<H',m,ds*16+0x2316,0x1234);fn(m,len(m),0x1000,C.byref(code),C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and out.dispatch_target==0x1234 and out.returned.registers.ax==20 and out.returned.registers.bx==20,'Unknown dispatch is diagnostic without invented state fallback');events.clear();selected[0]=0
    fn(m,len(m),0x1000,C.byref(code),C.byref(incoming),cb,None,32,C.byref(out));require(out.status==3 and out.calls==32 and len(events)==32,'Zero-state wait bounded separately from successful original return')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'limits':'Four native-only state-loop diagnostics. No original instruction/IRQ/resource/game executes; excluded from original differential totals/error equivalence. Unknown targets remain open domains.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
