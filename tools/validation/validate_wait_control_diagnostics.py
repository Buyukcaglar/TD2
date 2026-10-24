"""Native-only wait frame/budget/stalled-counter/input-ABI/service diagnostics."""
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
    fn=C.CDLL(str(library)).td2ega_wait_control;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_int,C.c_uint32,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;ds=0x278f;m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,ds,0,0,1),0x5678,1);events=[];bad_bp=[False];reject=[False];out=Result()
    def service(ctx,bus,q,r):
        events.append(q.contents.kind);C.memmove(r,C.byref(q.contents.incoming),C.sizeof(StateRegisters))
        if reject[0]:return 0
        if q.contents.kind==0:struct.pack_into('<I',m,q.contents.incoming.registers.ds*16+0x5e8c,1)
        elif bad_bp[0]:r.contents.bp=(r.contents.bp+2)&65535;r.contents.registers.ax=1
        return 1
    cb=Service(service);fn(m,len(m),0x1000,0xffff,0,10,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid nonwrapping frame before effects')
    fn(m,len(m),0x1000,0xe000,0,10,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.events==0 and out.returned.bp==0xdffe and out.returned.carry==0 and not any(m),'Zero budget retains frame/SUBSP prefix')
    fn(m,len(m),0x1000,0xe000,0,10,C.byref(incoming),cb,None,4,C.byref(out));require(out.status==3 and out.events==4 and events==[0,0,0,0] and out.deadline_low==11,'Frozen counter does not become successful return');events.clear();bad_bp[0]=True
    fn(m,len(m),0x1000,0xe000,1,10,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and events==[0,1],'BP-changing input adapter outside frame profile');events.clear();bad_bp[0]=False;reject[0]=True
    fn(m,len(m),0x1000,0xe000,0,10,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==4 and out.events==1 and events==[0],'Rejected counter boundary outside original return equivalence')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_wait_control.py','sha256':hashlib.sha256((ROOT/'tools/validate_wait_control.py').read_bytes()).hexdigest()}],'limits':'Five native-only wait diagnostics. No original instructions/counterIRQ/clock/inputcallback execute; excluded from original differential totals/error equivalence. No actualtimerfrequency/086Cmeaning/session/game/fidelity claim.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
