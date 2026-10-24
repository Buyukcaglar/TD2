"""Native-only wait-root interface, observer and dynamic-frame checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_wait_roots import Registers,StateRegisters,Result,InputRequest,InputResponse,InputService,CounterRequest,Observer,require

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');fn=C.CDLL(str(library)).td2ega_wait_roots;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),InputService,Observer,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0,0,0,0),0,0);out=Result();calls=[]
    def input_callback(ctx,m,q,r):calls.append('input');return 0
    def observer_callback(ctx,m,q):calls.append('counter');return 0
    input_service=InputService(input_callback);observer=Observer(observer_callback)
    for memory,count,sp,entry,state,input_cb,observe in [(bus,len(bus)-1,0xe000,0,C.byref(incoming),input_service,observer),(bus,len(bus),0xe000,4,C.byref(incoming),input_service,observer),(bus,len(bus),256,0,C.byref(incoming),input_service,observer),(bus,len(bus),0xffff,0,C.byref(incoming),input_service,observer),(None,len(bus),0xe000,0,C.byref(incoming),input_service,observer),(bus,len(bus),0xe000,0,None,input_service,observer),(bus,len(bus),0xe000,0,C.byref(incoming),InputService(),observer),(bus,len(bus),0xe000,2,C.byref(incoming),input_service,Observer())]:
        fn(memory,count,0x1000,0x9000,sp,entry,state,input_cb,observe,None,2,C.byref(out));require(out.status==2 and out.events==out.bus_writes==0 and not calls and not any(bus),'Invalid profile before effects')
    incoming.carry=2;fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),input_service,observer,None,2,C.byref(out));require(out.status==2 and out.events==out.bus_writes==0 and not calls,'Invalid carry');incoming.carry=0
    fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),input_service,observer,None,2,C.byref(out));require(out.status==4 and out.events==out.input_calls==out.dynamic_calls==1 and out.bus_writes==4 and out.current_sp==0xdff8 and calls==['input'],'Input failure frame');calls.clear()
    fn(bus,len(bus),0x1000,0x9000,0xe000,2,C.byref(incoming),input_service,observer,None,2,C.byref(out));require(out.status==4 and out.events==out.counter_calls==1 and out.bus_writes==2 and out.current_sp==0xdffc and calls==['counter'],'Observer failure frame')
    def corrupt(ctx,m,q,r):C.memmove(C.byref(r.contents.returned),C.byref(q.contents.incoming),C.sizeof(StateRegisters));C.memmove(C.byref(bus,q.contents.stack_segment*16+q.contents.stack_sp),struct.pack('<H',0x9999),2);return 1
    fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),InputService(corrupt),observer,None,2,C.byref(out));require(out.status==2 and out.events==out.input_calls==out.dynamic_calls==1 and out.bus_writes==4 and out.current_sp==0xdff8,'Excluded dynamicframe mutation diagnosed')
    record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_wait_roots.py','sha256':hashlib.sha256((ROOT/'tools/validate_wait_roots.py').read_bytes()).hexdigest()}],'limits':'Nineinvalidprofile checks, inputfailure, observerfailure anddynamic-returnframe-preservation rejection. Nativeonly/outsideoriginalerror equivalence; noactualinputtarget/IRQ/device/core/game/fidelity.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))

if __name__=='__main__':main()
