"""Native-only key-action argument and rejected-UI prefix diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_key_actions import Registers,Result,Service,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_key_action_apply;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_int,C.POINTER(Registers),Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;load,ds=0x1000,0x278f;m=(C.c_uint8*0x100000)();start=Registers(0,0,0,0,0,0,ds,0,0,0);events=[];out=Result()
    def reject(ctx,bus,q,r):events.append(q.contents.offset);return 0
    cb=Service(reject)
    fn(m,len(m),load,6,C.byref(start),cb,None,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid action before effects')
    start.interrupts_enabled=2;fn(m,len(m),load,0,C.byref(start),cb,None,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid flags before effects');start.interrupts_enabled=0
    m[ds*16+0x5efe]=0x55;fn(m,len(m),load,0,C.byref(start),cb,None,C.byref(out));require(out.status==4 and events==[0xe] and m[ds*16+0x5efe]==1 and m[ds*16+0x6cfc]==1,'Rejected guarded UI retains published guard');events.clear()
    m[ds*16+0x5efb]=255;m[ds*16+0x5efc]=255;struct.pack_into('<H',m,ds*16+0x5eee,0x1234);fn(m,len(m),load,2,C.byref(start),cb,None,C.byref(out));require(out.status==4 and events==[0x220] and m[ds*16+0x5efb]==2 and m[ds*16+0x5efc]==0 and struct.unpack_from('<H',m,ds*16+0x5eee)[0]==0,'Rejected toggle UI retains exact mask/clear prefix')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_key_actions.py','sha256':hashlib.sha256((ROOT/'tools/validate_key_actions.py').read_bytes()).hexdigest()}],'limits':'Four native-only argument/rejected-UI diagnostics. No original instruction/UI/IRQ executes; excluded from original differential totals/error equivalence.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
