"""Native-only rejection checks for table/scalar interface."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_table_scalar import Registers,StateRegisters,Result,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_table_scalar;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0,0);r=Result()
    for memory,count,sp,entry,s in [(bus,len(bus)-1,0xe000,0,C.byref(state)),(bus,len(bus),0,0,C.byref(state)),(bus,len(bus),0xffff,0,C.byref(state)),(None,len(bus),0xe000,0,C.byref(state)),(bus,len(bus),0xe000,0,None),(bus,len(bus),0xe000,5,C.byref(state))]:
        fn(memory,count,0x1000,0x9000,sp,entry,s,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid before effects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    record={'schema':1,'result':'pass','vectors':9,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_table_scalar.py','sha256':hashlib.sha256((ROOT/'tools/validate_table_scalar.py').read_bytes()).hexdigest()}],'limits':'Nine native invalid bus/count/SP/null/selector/boolean-flag profiles before effects; separate from original semantics/caller/core/device/session/game/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':9}))
if __name__=='__main__':main()
