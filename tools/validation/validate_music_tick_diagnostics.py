"""Native-only music API/budget/adapter diagnostics, outside original parity."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_music_tick import Registers,Port,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    dll=C.CDLL(str(library));fn=dll.td2ega_music_tick;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Port,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    load,ds=0x1000,0x278f;start=Registers(0,0,0,0,0,0,ds,0,0,0);m=(C.c_uint8*0x100000)();events=[]
    def reject(ctx,q,v):events.append(q.contents.port);return 0
    cb=Port(reject);out=Result()
    fn(m,len(m),load,C.byref(start),cb,None,0,C.byref(out));require(out.status==3 and not events and not any(m),'Zero budget has no effects')
    start.ds=0;fn(m,len(m),load,C.byref(start),cb,None,128,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid segment has no effects');start.ds=ds
    m[ds*16+0x5efc]=1;m[ds*16+0x65d2]=1;fn(m,len(m),load,C.byref(start),cb,None,128,C.byref(out));require(out.status==4 and events==[0x61] and m[ds*16+0x5efc]==0 and m[ds*16+0x65d2]==0,'Rejected adapter retains preceding publications');events.clear()
    m[ds*16+0x5efb]=3;m[ds*16+0x5efc]=1
    for at,value in [(0x65e1,2),(0x65e5,0),(0x65ff,0),(0x6603,0),(0x6607,0),(0x661f,0),(0x6621,1),(0x6623,0xffff)]:struct.pack_into('<H',m,ds*16+at,value)
    m[ds*16+0x6605]=1;m[ds*16+0x661d]=0
    fn(m,len(m),load,C.byref(start),cb,None,32,C.byref(out));require(out.status==3 and out.steps==32 and not events and struct.unpack_from('<H',m,ds*16+0x65e1)[0]==1,'Unbounded bounce is diagnostic, not normal completion')
    r={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'limits':'Four native-only diagnostics. No original instructions/device/IRQ executes; excluded from differential vectors and original error equivalence.'}
    output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))


if __name__=='__main__':main()
