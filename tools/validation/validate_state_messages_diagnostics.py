"""Native-only state-message frame, budget and rejected-service diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_messages import Registers,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_state_message
    fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)]
    fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,0,1),0x5678,1)
    events=[];reject=[False];out=Result()
    def service(ctx,bus,q,r):
        events.append(q.contents.site)
        C.memmove(r,C.byref(q.contents.incoming),C.sizeof(StateRegisters))
        r.contents.registers.ax=1
        return 0 if reject[0] else 1
    cb=Service(service)
    for entry,sp in [(11,0xe000),(0,0xfff1)]:
        fn(m,len(m),0x1000,0x9000,sp,entry,C.byref(incoming),cb,None,32,C.byref(out))
        require(out.status==2 and not events and not any(m),'Invalid entry/frame before effects')
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,0,C.byref(out))
    require(out.status==3 and out.calls==0 and out.current_sp==0xdff6 and out.returned.registers.ax==0xaf54 and not events,'Zero budget retains nested-frame and argument prefix')
    fn(m,len(m),0x1000,0x9000,0xe000,9,C.byref(incoming),cb,None,4,C.byref(out))
    require(out.status==3 and out.calls==4 and out.current_sp==0xe000 and events==[0x3f0d]*4,'Continuous input never becomes a successful return')
    events.clear();reject[0]=True
    fn(m,len(m),0x1000,0x9000,0xe000,8,C.byref(incoming),cb,None,32,C.byref(out))
    require(out.status==4 and out.calls==1 and out.current_sp==0xdff4 and events==[0x5c9d] and out.returned.registers.ax==0xaf54,'Rejected leaf retains suspended far-frame prefix')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_messages.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_messages.py').read_bytes()).hexdigest()}],'limits':'Five native-only diagnostics, excluded from original differential totals. No original instruction execution or rendering/text/clock/input/IRQ/core/game/fidelity admission.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
