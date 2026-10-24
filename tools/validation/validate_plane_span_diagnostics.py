"""Native-only plane-span invalid domain and missing-service checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_plane_span import Registers,StateRegisters,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');fn=C.CDLL(str(library)).td2ega_plane_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result();null=Service()
 fn(m,len(m)-1,0x1000,0x9000,0xe000,0,C.byref(incoming),null,None,C.byref(out));require(out.status==2 and out.writes==out.calls==0 and not any(m),'Short bus beforeeffects')
 fn(m,len(m),0x1000,0x9000,0xe000,1,C.byref(incoming),null,None,C.byref(out));require(out.status==2 and out.writes==out.calls==0 and not any(m),'Missing D01service beforeeffects')
 incoming.carry=2;fn(m,len(m),0x1000,0x9000,0xe000,0,C.byref(incoming),null,None,C.byref(out));require(out.status==2 and out.writes==out.calls==0 and not any(m),'Invalidcarry beforeeffects');record={'schema':1,'result':'pass','vectors':3,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_plane_span.py','sha256':hashlib.sha256((ROOT/'tools/validate_plane_span.py').read_bytes()).hexdigest()}],'limits':'Three native-only invalid input checks, no original error equivalence. ActualC17branches/D01ABI separatelycompared; no actualEGA/device/IRQ/core/game/fidelity.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':3}))
if __name__=='__main__':main()
