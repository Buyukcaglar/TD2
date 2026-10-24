"""Native-only line drawing interface rejection checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');fn=C.CDLL(str(library)).td2ega_line_draw;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result();calls=[]
 def callback(*_):calls.append(1);return 1
 cb=Service(callback);fn(m,len(m)-1,0x1000,0x9000,0xe000,C.byref(incoming),cb,None,4096,C.byref(out));require(out.status==2 and out.work==out.calls==out.writes==0 and not calls and not any(m),'Shortbus beforeeffects');fn(m,len(m),0x1000,0x9000,255,C.byref(incoming),cb,None,4096,C.byref(out));require(out.status==2 and out.work==out.calls==out.writes==0 and not calls and not any(m),'Invalidframe beforeeffects');incoming.carry=2;fn(m,len(m),0x1000,0x9000,0xe000,C.byref(incoming),cb,None,4096,C.byref(out));require(out.status==2 and out.work==out.calls==out.writes==0 and not calls and not any(m),'Invalidcarry beforeeffects');record={'schema':1,'result':'pass','vectors':3,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_line_draw.py','sha256':hashlib.sha256((ROOT/'tools/validate_line_draw.py').read_bytes()).hexdigest()}],'limits':'Three native-only invalidbus/frame/flagchecks; no originalerror equivalence oractualdevice/renderer/IRQ/core/game/fidelity admission.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':3}))
if __name__=='__main__':main()
