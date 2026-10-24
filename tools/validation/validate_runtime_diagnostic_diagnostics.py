"""Native-only runtime diagnostic minimum-stack, budget and adapter checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_diagnostic import Registers,StateRegisters,Result,DOSService,CallbackService,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_runtime_diagnostic;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null_dos=DOSService();null_cb=CallbackService()
    for memory,count,sp,entry,s in [(bus,len(bus)-1,0xe000,0,C.byref(state)),(bus,len(bus),0,0,C.byref(state)),(bus,len(bus),47,0,C.byref(state)),(bus,len(bus),0xffff,0,C.byref(state)),(None,len(bus),0xe000,0,C.byref(state)),(bus,len(bus),0xe000,0,None),(bus,len(bus),0xe000,2,C.byref(state))]:
        fn(memory,count,0x1000,0x9000,sp,entry,s,null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    bus[0x30000]=0x55;fn(bus,len(bus),0x1000,0x9000,48,1,C.byref(state),null_dos,null_cb,None,66,C.byref(r));require(r.status==0 and r.current_sp==52 and r.returned.registers.ax==0 and r.services==0 and r.callbacks==0 and r.returned.registers.direction==0,'MinimumSP48XORzero/noadapters')
    fn(bus,len(bus),0x1000,0x9000,48,1,C.byref(state),null_dos,null_cb,None,65,C.byref(r));require(r.status==3 and r.next_ip==0x677 and r.operations==65,'Beforechecksumbyteprefix')
    bus[0x382c4:0x382cc]=[0xfc,0,0,0xff,0,0,0xff,0xff];fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),null_dos,null_cb,None,32,C.byref(r));require(r.status==4 and r.next_ip==0x8d9 and r.services==0,'MissingDOSadapter')
    bus[0x36dcc:0x36dd0]=[0,0x40,0,0x90]
    @DOSService
    def good_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.registers.ax=0;out.contents.carry=0;return 1
    @DOSService
    def bad_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    @CallbackService
    def good_cb(context,memory,q,out):out[0]=q.contents.incoming;return 1
    @CallbackService
    def bad_cb(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),good_dos,null_cb,None,32,C.byref(r));require(r.status==4 and r.callbacks==0 and r.next_segment==0x9000 and r.next_ip==0x4000,'Missingcallbackafterfarframe')
    fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),good_dos,bad_cb,None,32,C.byref(r));require(r.status==4 and r.callbacks==0,'Badcallbackflags')
    fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),good_dos,good_cb,None,32,C.byref(r));require(r.status==0 and r.current_sp==52 and r.callbacks==1 and r.services==2,'MinimumSP48actualmessagechain/callback')
    fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),good_dos,null_cb,None,3,C.byref(r));require(r.status==3 and r.next_ip==0x633 and r.services==1 and r.callbacks==0,'BeforecallbackCALLbudget')
    fn(bus,len(bus),0x1000,0x9000,48,0,C.byref(state),bad_dos,good_cb,None,32,C.byref(r));require(r.status==4 and r.services==0,'BadDOSflags')
    record={'schema':1,'result':'pass','vectors':18,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_runtime_diagnostic.py','sha256':hashlib.sha256((ROOT/'tools/validate_runtime_diagnostic.py').read_bytes()).hexdigest()}],'limits':'Teninvalidbus/count/SP/null/selector/boolean profiles, minimumSP48XOR/message/callback chain, checksum/CALLbudgets, missing/badDOS/callbackadapters. Nativeonly, separatefromoriginalsource/callbackbody/writers/lifetime/catalog/realDOS/device/session/game/core/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':18}))
if __name__=='__main__':main()
