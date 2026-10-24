"""Native-only invalid input checks for the limit-stage interfaces."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_view_limits import Registers,StateRegisters,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    dll=C.CDLL(str(library));finish=dll.td2ega_finish_limits;finish.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(Result)];finish.restype=None;value=dll.td2ega_limit_value;value.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(StateRegisters)];value.restype=C.c_uint16
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(1,2,3,4,5,6,0x278f,0,1,1),7,1);out=Result();returned=StateRegisters()
    finish(m,len(m)-1,C.byref(incoming),C.byref(out));require(out.status==2 and out.calls==0 and not any(m),'Short bus before effects')
    require(value(m,len(m)-1,C.byref(incoming),C.byref(returned))==2 and not any(m),'Readonly short bus')
    incoming.carry=2;finish(m,len(m),C.byref(incoming),C.byref(out));require(out.status==2 and out.calls==0 and not any(m),'Invalid carry before effects')
    require(value(m,len(m),C.byref(incoming),C.byref(returned))==2 and not any(m),'Readonly invalid carry')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_view_limits.py','sha256':hashlib.sha256((ROOT/'tools/validate_view_limits.py').read_bytes()).hexdigest()}],'limits':'Four native-only invalid bus/flag checks. Excluded from original differential and original error equivalence; no actual session, device, renderer, core or fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':4}))


if __name__=='__main__':main()
