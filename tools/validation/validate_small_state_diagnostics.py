"""Native-only small-helper profile rejection checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_small_state import Registers,StateRegisters,Result,require

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();library=args.library.resolve();output=args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths')
    dll=C.CDLL(str(library));fn=dll.td2ega_small_state
    fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0,0);out=Result()
    cases=[(bus,len(bus)-1,0xe000,0,C.byref(incoming)),(bus,len(bus),0xe000,14,C.byref(incoming)),(bus,len(bus),0,0,C.byref(incoming)),(bus,len(bus),0xffff,0,C.byref(incoming)),(None,len(bus),0xe000,0,C.byref(incoming)),(bus,len(bus),0xe000,0,None)]
    for memory,count,sp,entry,state in cases:
        fn(memory,count,0x1000,0x9000,sp,entry,state,C.byref(out));require(out.status==2 and out.writes==out.reads==0 and not any(bus),'Invalid profile before effects')
    incoming.carry=2;fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),C.byref(out));require(out.status==2 and out.writes==out.reads==0,'Invalid carry')
    incoming.carry=0;incoming.registers.direction=2;fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),C.byref(out));require(out.status==2 and out.writes==out.reads==0,'Invalid DF')
    record={'schema':1,'result':'pass','vectors':8,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_small_state.py','sha256':hashlib.sha256((ROOT/'tools/validate_small_state.py').read_bytes()).hexdigest()}],'limits':'Eight native-only invalid bus/count/entry/SP/null state/carry/DF profiles, no effects. Separate from original near/far returns, no IRQ/device/session/core/gameplay/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':8}))

if __name__=='__main__':main()
