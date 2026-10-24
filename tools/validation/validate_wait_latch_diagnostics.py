"""Native-only global raw-deadline argument/progress/service diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_wait_control import Registers,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_wait_latch;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,0,1),0x5678,1);out=Result();events=[];reject=[False]
    def service(ctx,bus,q,r):events.append(q.contents.site);return 0 if reject[0] else 1
    cb=Service(service)
    fn(m,len(m),0x1000,0x9000,0xffff,0,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events,'Invalid frame before events')
    fn(m,len(m),0x1000,0x9000,0xe000,2,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events,'Invalid entry before events')
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.events==0 and out.returned.bp==0xdffe and not events,'Zero budget retainsPUSHBP/MOVBP prefix')
    struct.pack_into('<I',m,0x278f0+0x6818,1)
    fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,4,C.byref(out));require(out.status==3 and out.events==4 and events==[0x7a27]*4 and out.returned.registers.interrupts_enabled==1,'Frozen counter retains waiting state');events.clear();reject[0]=True
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==4 and out.events==1 and events==[0x7a13] and out.returned.registers.interrupts_enabled==0,'Rejected counter boundary before actualsnapshot prefix')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_wait_control.py','sha256':hashlib.sha256((ROOT/'tools/validate_wait_control.py').read_bytes()).hexdigest()}],'limits':'Five native-only diagnostics; excluded from original comparison/error equivalence. No original instructions, actualcounterIRQ/clock/input/device/core/game/fidelity admission.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':5}))


if __name__=='__main__':main()
