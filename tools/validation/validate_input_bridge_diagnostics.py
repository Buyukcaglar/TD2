"""Native-only input bridge argument/budget/service-domain diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_input_bridge import Registers,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_input_bridge;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result();events=[];mode=[0]
    def service(ctx,bus,q,r):
        events.append(q.contents.site);C.memmove(C.byref(r.contents.returned),C.byref(q.contents.incoming),C.sizeof(StateRegisters));r.contents.zero=2 if mode[0]==2 else 0
        return 0 if mode[0]==1 else 1
    cb=Service(service)
    fn(m,len(m),0x1000,0x9000,0xfff1,2,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid frame no effects')
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.current_sp==0xe000 and not events,'Zero far budget no call frame')
    fn(m,len(m),0x1000,0x9000,0xe000,4,C.byref(incoming),cb,None,4,C.byref(out));require(out.status==3 and out.current_sp==0xe000 and events==[0x6a3d,0x6a46]*2,'Continuous input does not invent successful drain');events.clear();mode[0]=1
    fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==4 and out.current_sp==0xdffa and events==[0x6a05],'Rejected BIOS retains suspended interrupt prefix');events.clear();mode[0]=2
    fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and out.current_sp==0xdffa and events==[0x6a05],'Nonboolean ZF outside adapter domain')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_input_bridge.py','sha256':hashlib.sha256((ROOT/'tools/validate_input_bridge.py').read_bytes()).hexdigest()}],'limits':'Five native-only diagnostics, excluded from original comparisons/error equivalence. No original instructions, actual BIOS/IRQ/inputsession/core/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':5}))


if __name__=='__main__':main()
