"""Native-only adapter/budget diagnostics; no original instruction execution."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_find_nth import Registers,Result,Service,require


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    dll=C.CDLL(str(library));fn=dll.td2ega_find_nth;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint16,Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;rows=[]
    def success(ctx,request,response):response.contents.ax=0;response.contents.carry=0;return 1
    for name,budget,callback in [('missing_adapter',0,Service()),('budget_zero',0,Service(success)),('budget_one',1,Service(success))]:
        group=(C.c_uint8*65536)();incoming=Registers();r=Result();fn(group,65536,0,0,3,C.byref(incoming),0,0,callback,None,budget,C.byref(r));require(r.status==2,'Native diagnostic')
        if name!='missing_adapter':require(r.next_calls==budget and r.index==budget+1 and bytes(group[0x5dec:0x5dee])==b'\x88\x5d','Budget retains prefix/next count')
        rows.append({'case':name,'status':r.status,'next_calls':r.next_calls,'index':r.index})
    dependency=ROOT/'tools/validate_find_nth.py';record={'schema':1,'result':'pass','vectors':len(rows),'native_only':True,'original_instructions_executed':0,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'validator_dependencies':[{'path':dependency.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(dependency.read_bytes()).hexdigest()}],'native_libraries':[{'path':library.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(library.read_bytes()).hexdigest()}],'cases':rows,'limits':'Three native-only API diagnostic cases with allzero syntheticgroup/adapters; no original instructions/DOS/filesystem execute. Not included in original/native differential vector count; no original error equivalence or runtime/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
