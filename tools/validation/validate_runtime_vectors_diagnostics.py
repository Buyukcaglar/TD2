"""Native-only vector cleanup profile, budget and adapter checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_vectors import Registers,StateRegisters,Result,DOSService,CallbackService,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_runtime_vectors;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null_dos=DOSService();null_cb=CallbackService()
    for memory,count,sp,s in [(bus,len(bus)-1,0xe000,C.byref(state)),(bus,len(bus),0,C.byref(state)),(bus,len(bus),0xffff,C.byref(state)),(None,len(bus),0xe000,C.byref(state)),(bus,len(bus),0xe000,None)]:
        fn(memory,count,0x1000,0x9000,sp,s,null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(state),null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null_dos,null_cb,None,1,C.byref(r));require(r.status==4 and r.next_ip==0x5f5 and r.services==0 and r.bus_writes==1,'MissingDOSadapter')
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),null_dos,null_cb,None,0,C.byref(r));require(r.status==3 and r.next_ip==0x5f5 and r.bus_writes==1,'BeforefirstINTbudget')
    @DOSService
    def good_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=1;return 1
    @DOSService
    def bad_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    @CallbackService
    def good_cb(context,memory,q,out):out[0]=q.contents.incoming;return 1
    @CallbackService
    def bad_cb(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,null_cb,None,1,C.byref(r));require(r.status==0 and r.current_sp==18 and r.services==1 and r.returned.carry==0,'MinimumSP16guardzeroCFcleared')
    bus[0x36dc6]=1;bus[0x36dc7]=0x24;fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,null_cb,None,2,C.byref(r));require(r.status==0 and r.services==2 and r.returned.carry==1,'SecondserviceCFpreserved')
    bus[0x37076:0x3707a]=[0,0x40,0,0x90];fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,null_cb,None,3,C.byref(r));require(r.status==4 and r.callbacks==0 and r.services==0 and r.current_sp==12,'Missingcallbackafterframe')
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,bad_cb,None,3,C.byref(r));require(r.status==4 and r.callbacks==0,'Badcallbackflags')
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,good_cb,None,3,C.byref(r));require(r.status==0 and r.current_sp==18 and r.callbacks==1 and r.services==2,'MinimumSP16fullchain')
    fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),good_dos,null_cb,None,0,C.byref(r));require(r.status==3 and r.next_ip==0x5e9 and r.bus_writes==0,'Beforecallbackbudget')
    bus[0x37078]=bus[0x37079]=0;fn(bus,len(bus),0x1000,0x9000,16,C.byref(state),bad_dos,null_cb,None,3,C.byref(r));require(r.status==4 and r.services==0,'BadDOSflags')
    record={'schema':1,'result':'pass','vectors':17,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_runtime_vectors.py','sha256':hashlib.sha256((ROOT/'tools/validate_runtime_vectors.py').read_bytes()).hexdigest()}],'limits':'Eightinvalidbus/count/SP/null/boolean profiles, minimumSP16 one/twoDOS/optionalcallback chains, missing/badDOS/callbackadapters, beforeINT/CALLbudgets. Nativeonly; actualvectors/targets/writers/lifetime/IRQ/session/game/core/fidelity separate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':17}))
if __name__=='__main__':main()
