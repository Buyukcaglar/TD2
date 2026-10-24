"""Native-only state-sequence budget/progress/frame/service diagnostics."""
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_state_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0x1234,0,0x278f,0,0,1),0x5678,1);events=[];mode=[0];out=Result()
    def service(ctx,bus,q,r):
        events.append(q.contents.site);C.memmove(r,C.byref(q.contents.incoming),C.sizeof(StateRegisters))
        if mode[0]==1 and q.contents.site==0x35c4:m[0x278f0+0x2e29]=2
        if mode[0]==2 and q.contents.site==0x5c9d:return 0
        return 1
    cb=Service(service)
    fn(m,len(m),0x1000,0x9000,0xffff,0,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid frame before effects')
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.current_sp==0xdffc and out.calls==0 and not events,'Zero budget retains initial argument prefix')
    mode[0]=1;m[0x90000+0x2e22]=1
    fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),cb,None,20,C.byref(out));require(out.status==3 and out.calls==20 and events.count(0x35c4)==8 and m[0x278f0+0x2e29]==1,'Counter writer can prevent sequence completion');events.clear();mode[0]=2
    fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==4 and out.calls==2 and events==[0x3648,0x5c9d] and out.current_sp==0xdff2 and m[0x278f0+0x2e29]==10,'Nested surface rejection keeps exact earlier effects');events.clear()
    fn(m,len(m),0x1000,0x9000,0xe000,2,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events,'Invalid entry no leaf')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_messages.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_messages.py').read_bytes()).hexdigest()}],'limits':'Five native-only diagnostics, excluded from original comparison/error equivalence. No original instructions/graphics/resources/device/IRQ/core/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':5}))


if __name__=='__main__':main()
