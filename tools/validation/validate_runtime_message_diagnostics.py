"""Native-only message interface, minimum stack, adapter and budget checks."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_message import Registers,StateRegisters,Request,Result,Service,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_runtime_message;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null=Service()
    for memory,count,sp,entry,s in [(bus,len(bus)-1,0xe000,0,C.byref(state)),(bus,len(bus),0,0,C.byref(state)),(bus,len(bus),31,0,C.byref(state)),(bus,len(bus),0xffff,0,C.byref(state)),(None,len(bus),0xe000,0,C.byref(state)),(bus,len(bus),0xe000,0,None),(bus,len(bus),0xe000,2,C.byref(state))]:
        fn(memory,count,0x1000,0x9000,sp,entry,s,null,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid before effects')
    for field in ['carry','interrupts_enabled','direction']:
        target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),null,None,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
    bus[0x382c4]=bus[0x382c5]=255;fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(state),null,None,1,C.byref(r));require(r.status==0 and r.current_sp==38 and r.returned.registers.ax==0 and r.bus_writes==4,'MinimumSP32missingID/RETF2/noadapter')
    bus[0x382c4]=bus[0x382c5]=0;fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),null,None,3,C.byref(r));require(r.status==4 and r.services==0 and r.bus_writes==9 and r.next_ip==0x8d9,'Missingadapter afteractualnestedlookup')
    @Service
    def bad(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
    fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),bad,None,3,C.byref(r));require(r.status==4 and r.services==0 and r.bus_writes==9,'Invalidreturnedflags')
    @Service
    def good(context,memory,q,out):out[0]=q.contents.incoming;out.contents.registers.ax=0;out.contents.carry=0;return 1
    fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),good,None,3,C.byref(r));require(r.status==0 and r.current_sp==38 and r.services==1 and r.bus_writes==9,'MinimumSP32actualnestedRETF2')
    fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(state),null,None,2,C.byref(r));require(r.status==3 and r.next_ip==0x8d9 and r.services==0 and r.bus_writes==9,'BeforeINTbudget separate')
    record={'schema':1,'result':'pass','vectors':15,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_runtime_message.py','sha256':hashlib.sha256((ROOT/'tools/validate_runtime_message.py').read_bytes()).hexdigest()}],'limits':'Teninvalidbus/count/SP/null/selector/boolean profiles, minimumSP32lookup/outputRETF2, missing/badadapter andbeforeINTbudget. Nativeonly, separatefromoriginalcatalog/endmarker/caller/key/realDOS/device/session/game/core/fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':15}))
if __name__=='__main__':main()
