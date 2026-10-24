"""Native-only validation of explicit BIOS-response flag domains."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_input_poll import Registers,Result,BiosService,Services
from validate_key_dispatch import Callback,require
from validate_gameport import Service as PortService


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    fn=C.CDLL(str(library)).td2ega_input_poll;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Services),C.POINTER(Registers),C.POINTER(Result)];fn.restype=None;g=(C.c_uint8*65536)();incoming=Registers(0,0,0,0,0,0);errors=[];response=[0,0,0]
    def bios(ctx,q,r):r.contents.ax=0x1234;r.contents.zero=response[0];r.contents.interrupts_enabled=response[1];r.contents.direction=response[2];return 1
    def reject(*_):errors.append('Unexpected downstream service');return 0
    bs,ps,ks=BiosService(bios),PortService(reject),Callback(reject);services=Services(0x16c9,0x278f,0x9000,32,bs,None,ps,None,ks,None);out=Result()
    for i in range(3):
        response[:]=[0,0,0];response[i]=2;fn(g,len(g),C.byref(services),C.byref(incoming),C.byref(out));require(out.status==2 and not errors and not any(g) and out.bios_probes==0,'Invalid response before downstream effects')
    record={'schema':1,'result':'pass','vectors':3,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_input_poll.py','sha256':hashlib.sha256((ROOT/'tools/validate_input_poll.py').read_bytes()).hexdigest()}],'limits':'Three native-only BIOSresponse domain checks. No original instructions/BIOS/IRQ executes; excluded from original differential totals/error equivalence.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
