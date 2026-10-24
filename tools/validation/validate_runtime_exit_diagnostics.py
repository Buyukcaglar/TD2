"""Native-only exit interface, boundary, budgets and adapter diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_exit import Registers,StateRegisters,Result,DOSService,CallbackService,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_runtime_exit;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null_dos=DOSService();null_cb=CallbackService()
    for memory,count,sp,s in [(bus,len(bus)-1,0xe000,C.byref(state)),(bus,len(bus),0,C.byref(state)),(bus,len(bus),79,C.byref(state)),(bus,len(bus),0xffff,C.byref(state)),(None,len(bus),0xe000,C.byref(state)),(bus,len(bus),0xe000,None)]:
        fn(memory,count,0x1000,0x9000,sp,s,null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(state),null_dos,null_cb,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    @DOSService
    def good_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.registers.ax=0;out.contents.carry=0;return 1
    @DOSService
    def bad_dos(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    @CallbackService
    def good_cb(context,memory,q,out):out[0]=q.contents.incoming;return 1
    @CallbackService
    def bad_cb(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    @CallbackService
    def raw_cb(context,memory,q,out):out[0]=q.contents.incoming;at=q.contents.stack_segment*16+q.contents.stack_sp;memory[at]=0x44;memory[at+1]=0x44;return 1
    bus[0x30000]=0x55;fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,null_cb,None,83,C.byref(r));require(r.status==5 and r.current_sp==78 and r.operations==83 and r.services==1 and r.close_iterations==15 and r.exit_request.incoming.registers.ax==0x4c00,'MinimumSP80preparedexit/noactualexit')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,null_cb,None,82,C.byref(r));require(r.status==3 and r.next_ip==0x5de and r.exit_request.vector==0,'Beforeexitbudget/noevent')
    bus[0x36da9]=1;fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),null_dos,null_cb,None,68,C.byref(r));require(r.status==4 and r.next_ip==0x5d1 and r.close_requests==0,'Missingcloseadapter')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),null_dos,null_cb,None,67,C.byref(r));require(r.status==3 and r.next_ip==0x5d1 and r.close_iterations==1,'BeforecloseINTbudget')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),bad_dos,null_cb,None,128,C.byref(r));require(r.status==4 and r.close_requests==0,'BadDOSreturnedflags');bus[0x36da9]=0
    bus[0x37076:0x3707a]=[0,0x40,0,0x90];fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,null_cb,None,128,C.byref(r));require(r.status==4 and r.callbacks==0 and r.next_segment==0x9000,'Missingcallback')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,good_cb,None,128,C.byref(r));require(r.status==5 and r.callbacks==1 and r.services==1,'Fullminimumstackchain')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,bad_cb,None,128,C.byref(r));require(r.status==4 and r.callbacks==0,'Badcallbackflags')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),good_dos,raw_cb,None,128,C.byref(r));require(r.status==1 and r.next_ip==0x4444 and r.exit_request.vector==0,'Rawcallbackreturnnotexit')
    fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),null_dos,null_cb,None,0,C.byref(r));require(r.status==3 and r.next_ip==0x677 and r.operations==0,'Beforechecksumbytebudget')
    bus[0x37078]=bus[0x37079]=0;fn(bus,len(bus),0x1000,0x9000,80,C.byref(state),null_dos,null_cb,None,128,C.byref(r));require(r.status==4 and r.next_ip==0x5f5 and r.exit_request.vector==0,'Missingvectoradapternotexit')
    record={'schema':1,'result':'pass','vectors':20,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_runtime_exit.py','sha256':hashlib.sha256((ROOT/'tools/validate_runtime_exit.py').read_bytes()).hexdigest()}],'limits':'Nineinvalidbus/count/SP/null/boolean profiles, minimumSP80preparedexit/actualhelperchain, exit/checksum/closebudgets, missing/badDOS/callback/vectoradapters andrawcallbackreturn. Nativeonly; noactualDOS4C/process exit/device/session/game/core/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':20}))
if __name__=='__main__':main()
