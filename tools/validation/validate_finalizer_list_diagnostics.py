"""Native-only callback walker profile, budget and service diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_finalizer_list import Registers,StateRegisters,Request,Result,Service,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_finalizer_list;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0x1200,0x1204,0x3000,0,0,0),0,0);r=Result();null=Service()
    for memory,count,sp,s in [(bus,len(bus)-1,0xe000,C.byref(state)),(bus,len(bus),0,C.byref(state)),(bus,len(bus),0xffff,C.byref(state)),(None,len(bus),0xe000,C.byref(state)),(bus,len(bus),0xe000,None)]:
        fn(memory,count,0x1000,0x9000,sp,s,null,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid before effects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(state),null,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    state.registers.di=state.registers.si;fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null,None,0,C.byref(r));require(r.status==0 and r.current_sp==18 and r.calls==0 and r.iterations==0 and r.returned.carry==0,'Emptyspan noadapter/budgetneeded');state.registers.di=0x1204
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null,None,1,C.byref(r));require(r.status==0 and r.iterations==1 and r.calls==0 and r.bus_writes==0,'Zeroskip noadapter')
    bus[0x31200:0x31204]=[0,0x40,0,0x90];fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null,None,1,C.byref(r));require(r.status==4 and r.current_sp==12 and r.bus_writes==2 and r.calls==0,'Missingadapter afterfarframe')
    @Service
    def bad(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),bad,None,1,C.byref(r));require(r.status==4 and r.bus_writes==2 and r.calls==0,'Invalidreturnedflags')
    @Service
    def normal(context,memory,q,out):out[0]=q.contents.incoming;return 1
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),normal,None,1,C.byref(r));require(r.status==0 and r.current_sp==18 and r.calls==1 and r.bus_writes==2,'MinimumSP16 normalcallbackframe')
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null,None,0,C.byref(r));require(r.status==3 and r.current_sp==16 and r.calls==0 and r.bus_writes==0 and r.next_ip==0x611 and r.returned.carry==1,'Before-recordprefix')
    record={'schema':1,'result':'pass','vectors':14,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_finalizer_list.py','sha256':hashlib.sha256((ROOT/'tools/validate_finalizer_list.py').read_bytes()).hexdigest()}],'limits':'Eight invalid bus/count/SP/null/boolean profiles, empty/zero spans, missing/badadapter, minimumSP16 normalcallbackframe and before-recordbudget. Nativeonly; callbackbody/alltargets/writers/lifetime/core/device/session/game/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':14}))
if __name__=='__main__':main()
