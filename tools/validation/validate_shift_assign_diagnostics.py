"""Native-only near-pointer shift profile rejection checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_shift_assign import Registers,StateRegisters,Result,require

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');fn=C.CDLL(str(library)).td2ega_shift_assign;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0,0);out=Result()
    for memory,count,sp,state in [(bus,len(bus)-1,0xe000,C.byref(incoming)),(bus,len(bus),0,C.byref(incoming)),(bus,len(bus),0xffff,C.byref(incoming)),(None,len(bus),0xe000,C.byref(incoming)),(bus,len(bus),0xe000,None)]:
        fn(memory,count,0x1000,0x9000,sp,state,C.byref(out));require(out.status==2 and out.shift_count==out.bus_writes==0 and not any(bus),'Invalid profile before effects')
    for name in ['carry','direction','interrupts_enabled']:
        if name=='carry':incoming.carry=2
        else:setattr(incoming.registers,name,2)
        fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(incoming),C.byref(out));require(out.status==2 and out.shift_count==out.bus_writes==0 and not any(bus),'Invalid flag')
        if name=='carry':incoming.carry=0
        else:setattr(incoming.registers,name,0)
    record={'schema':1,'result':'pass','vectors':8,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_shift_assign.py','sha256':hashlib.sha256((ROOT/'tools/validate_shift_assign.py').read_bytes()).hexdigest()}],'limits':'Eightnativeinvalidbus/count/SP/null/carry/IF/DF profiles beforeeffects. SeparatefromoriginalRETFimm4/near-pointer/wrap/rawreturn behavior andactualcaller/FLAGS/bounds/core/game/fidelity.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':8}))

if __name__=='__main__':main()
