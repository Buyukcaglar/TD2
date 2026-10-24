"""Native-only record-preparation argument/budget/nontermination diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_prepare_records import Registers,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_prepare_records;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint32,C.POINTER(Result)];fn.restype=None;ds=0x278f;m=(C.c_uint8*0x100000)();r=Registers(0,0,0,0,0,0,ds,0,2,0);out=Result()
    fn(m,len(m),ds,C.byref(r),0x5678,32,C.byref(out));require(out.status==2 and not any(m),'Invalid flags before writes');r.interrupts_enabled=0
    m[ds*16+0x920c]=7;fn(m,len(m),ds,C.byref(r),0x5678,0,C.byref(out));require(out.status==3 and out.steps==0 and m[ds*16+0x1a70]==249 and out.registers.direction==0 and out.registers.es==ds,'Zero budget retains setup prefix')
    m[ds*16+0x920c]=1
    for i in range(50):m[ds*16+0x3813+i*8]=1
    fn(m,len(m),ds,C.byref(r),0x5678,32,C.byref(out));require(out.status==3 and out.steps==32 and out.samples==29 and out.deleted==29 and out.record_offset==24 and struct.unpack_from('<H',m,ds*16+0x5354)[0]==0,'Unterminated fulltable/FFthreshold repeats without successful return')
    record={'schema':1,'result':'pass','vectors':3,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_prepare_records.py','sha256':hashlib.sha256((ROOT/'tools/validate_prepare_records.py').read_bytes()).hexdigest()}],'limits':'Three native-only argument/budget/nontermination checks. No original instructions/IRQ/resources execute; excluded from original differential totals/error equivalence. No core/RNGmeaning/reset/game/fidelity claim.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
