"""Native-only line-step frame/flag domain diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_line_step import Registers,StateRegisters,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_line_step;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,2,17,0,0,0x278f,0x7000,1,1),0x5678,1);out=Result()
    fn(m,len(m),0x1000,0x9000,0xffff,0,17,1,C.byref(incoming),100,C.byref(out));require(out.status==2 and out.work==0 and out.words==0 and not any(m),'Invalid frame before output/code writes')
    incoming.registers.direction=2;fn(m,len(m),0x1000,0x9000,0xe000,0,17,1,C.byref(incoming),100,C.byref(out));require(out.status==2 and out.work==0 and out.words==0 and not any(m),'Invalid DF before output/code writes')
    record={'schema':1,'result':'pass','vectors':2,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_line_step.py','sha256':hashlib.sha256((ROOT/'tools/validate_line_step.py').read_bytes()).hexdigest()}],'limits':'Two native-only frame/DF-domain checks; excluded from original differential/error equivalence. Work/patch/innerloop prefixes compared separately inhelperreceipt. No originalinstructions/actualIRQ/reentrancy/renderer/resource/core/game/fidelity.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':2}))


if __name__=='__main__':main()
