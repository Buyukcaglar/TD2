"""Native-only projection and signed lookup memory/flag domain diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_projection import Registers,StateRegisters,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    dll=C.CDLL(str(library));project=dll.td2ega_projection_step;project.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];project.restype=None;lookup=dll.td2ega_signed_byte_lookup;lookup.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(StateRegisters)];lookup.restype=C.c_uint16
    m=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);out=Result();returned=StateRegisters()
    project(m,len(m)-1,C.byref(incoming),100,C.byref(out));require(out.status==2 and out.work==0 and not any(m),'Invalidprojection extent before effects')
    incoming.carry=2;project(m,len(m),C.byref(incoming),100,C.byref(out));require(out.status==2 and out.work==0 and not any(m),'Invalidprojection carry before effects');incoming.carry=1
    require(lookup(m,len(m)-1,C.byref(incoming),C.byref(returned))==2 and not any(m),'Invalidlookup extent')
    incoming.registers.interrupts_enabled=2;require(lookup(m,len(m),C.byref(incoming),C.byref(returned))==2 and not any(m),'Invalidlookup flag domain')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_projection.py','sha256':hashlib.sha256((ROOT/'tools/validate_projection.py').read_bytes()).hexdigest()}],'limits':'Four native-only projection/lookup argument-domain checks; excluded from original differential/error equivalence. ActualIDIV/workprefixes separatelycounted inhelperreceipt, no post-IDIV arithmeticflagclaim. No originalinstructions/actualresource/renderer/device/IRQ/core/game/fidelity.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':4}))


if __name__=='__main__':main()
