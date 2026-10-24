"""Native-only root-loop control frame/budget/near-far adapter diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_loop_controls import Registers,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_loop_control;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0x1234,0,0x278f,0,0,1),0x5678,1);out=Result();events=[];mode=[0]
    def service(ctx,bus,q,r):
        events.append(q.contents.site)
        if mode[0]==1 and q.contents.site==0x1f7d:return 0
        if mode[0]==2:r.contents.carry=2
        return 1
    cb=Service(service)
    fn(m,len(m),0x1000,0x9000,0xffff,0,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalidframe before effects')
    fn(m,len(m),0x1000,0x9000,0xe000,3,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalidentry before effects')
    fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.current_sp==0xdffa and out.calls==0 and not events and struct.unpack_from('<H',m,0x278f0+0x5348)[0]==80,'Zero budget keeps prior store/savedframe prefix')
    mode[0]=1;fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==4 and out.current_sp==0xdff8 and out.calls==2 and events==[0x1f7a,0x1f7d],'Rejected near leaf retains2byteframe');events.clear();mode[0]=2
    fn(m,len(m),0x1000,0x9000,0xe000,2,C.byref(incoming),cb,None,32,C.byref(out));require(out.status==2 and out.current_sp==0xdff2 and events==[0x1faa] and struct.unpack_from('<H',m,0x278f0+0x702)[0]==0x28bd,'Invalidfar response retains store/4byteframe prefix')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_loop_controls.py','sha256':hashlib.sha256((ROOT/'tools/validate_loop_controls.py').read_bytes()).hexdigest()}],'limits':'Five native-only frame/budget/near-far response checks, excluded from original differential/error equivalence. No originalinstructions/graphics/resources/device/IRQ/core/game/fidelity.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':5}))


if __name__=='__main__':main()
