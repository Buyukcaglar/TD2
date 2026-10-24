"""Native-only invalid interface and service failure checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_small_platform import Registers,StateRegisters,Result,Request,Service,require

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths')
    dll=C.CDLL(str(library));fn=dll.td2ega_small_platform;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0x5678,0);out=Result();calls=[]
    def callback(ctx,m,q,r):calls.append(q.contents.site);return 0
    adapter=Service(callback)
    for memory,count,sp,entry,state,service in [(bus,len(bus)-1,0xe000,0,C.byref(incoming),adapter),(bus,len(bus),0xe000,5,C.byref(incoming),adapter),(bus,len(bus),0,0,C.byref(incoming),adapter),(bus,len(bus),0xffff,0,C.byref(incoming),adapter),(None,len(bus),0xe000,0,C.byref(incoming),adapter),(bus,len(bus),0xe000,0,None,adapter),(bus,len(bus),0xe000,0,C.byref(incoming),Service())]:
        fn(memory,count,0x1000,0x9000,sp,entry,state,service,None,2,C.byref(out));require(out.status==2 and out.calls==0 and not calls and not any(bus),'Invalid profile before effects')
    incoming.carry=2;fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),adapter,None,2,C.byref(out));require(out.status==2 and out.calls==0 and not calls,'Invalid carry');incoming.carry=0
    fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),adapter,None,2,C.byref(out));require(out.status==4 and out.calls==1 and out.current_sp==0xe000 and calls==[0x5d50] and out.returned.registers.ax==0x1900 and not any(bus),'Adapter failure distinct prefix')
    def invalid(ctx,m,q,r):C.memmove(r,C.byref(q.contents.incoming),C.sizeof(StateRegisters));r.contents.carry=2;return 1
    fn(bus,len(bus),0x1000,0x9000,0xe000,2,C.byref(incoming),Service(invalid),None,2,C.byref(out));require(out.status==2 and out.calls==1 and out.current_sp==0xdffe and out.returned.registers.ax==0x1900,'Invalid response prefix')
    record={'schema':1,'result':'pass','vectors':10,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_small_platform.py','sha256':hashlib.sha256((ROOT/'tools/validate_small_platform.py').read_bytes()).hexdigest()}],'limits':'Eight nativeinvalidprofile checks plusadapterfailure andinvalidreturnedflag prefixes. SeparatefromoriginalDOS/BIOSreturn/error behavior andactualplatform/IRQ/session/core/game/fidelity.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':10}))

if __name__=='__main__':main()
