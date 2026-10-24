"""Native-only loop preparation memory/flag domain diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_loop_prepare import Registers,StateRegisters,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_loop_prepare;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result()
    fn(m,0,C.byref(incoming),100,C.byref(out));require(out.status==2 and out.records==0 and not any(m),'Invalid memory extent before writes')
    incoming.carry=2;fn(m,len(m),C.byref(incoming),100,C.byref(out));require(out.status==2 and out.records==0 and not any(m),'Invalid CF before writes')
    record={'schema':1,'result':'pass','vectors':2,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_loop_prepare.py','sha256':hashlib.sha256((ROOT/'tools/validate_loop_prepare.py').read_bytes()).hexdigest()}],'limits':'Two native-only argument-domain checks, excluded from original comparisons/error equivalence. Budget-prefix instruction comparisons are separately counted inhelper receipt. No actualresources/graphics/device/IRQ/core/game/fidelity.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':2}))


if __name__=='__main__':main()
