"""Native-only BIOS block frame/budget/service diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_bios_block import Registers,StateRegisters,Service,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_bios_block;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result();events=[];bad=[False]
    def service(ctx,bus,q,r):
        events.append(q.contents.site)
        if bad[0]:r.contents.carry=2;return 1
        return 0
    cb=Service(service)
    fn(m,len(m),0x9000,0xffff,C.byref(incoming),cb,None,1,C.byref(out));require(out.status==2 and not events,'Invalidframe no service')
    fn(m,len(m),0x9000,0xe000,C.byref(incoming),cb,None,0,C.byref(out));require(out.status==3 and out.current_sp==0xdffe and out.returned.bp==0xdffe and out.returned.registers.ax==0x1002 and out.returned.registers.es==0x278f and not events,'Zero budget preserves preINT prefix')
    fn(m,len(m),0x9000,0xe000,C.byref(incoming),cb,None,1,C.byref(out));require(out.status==4 and out.current_sp==0xdff8 and out.calls==1 and events==[0xac08],'RejectedINT prefix');events.clear();bad[0]=True
    fn(m,len(m),0x9000,0xe000,C.byref(incoming),cb,None,1,C.byref(out));require(out.status==2 and out.current_sp==0xdff8 and events==[0xac08],'InvalidreturnedCF domain')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_bios_block.py','sha256':hashlib.sha256((ROOT/'tools/validate_bios_block.py').read_bytes()).hexdigest()}],'limits':'Four native-only diagnostics, excluded from original differential/error equivalence. No original instructions or BIOS/device/rendering/IRQ/core/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':4}))


if __name__=='__main__':main()
