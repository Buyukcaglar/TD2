"""Native callback metadata invalid/budget/publication/fatal diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_callback_bus import Result,Registers,StateRegisters,ww,rw,require
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_timer_callback_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x278f,0x8000,0,0),0x5678,0);r=Result();checks=0
    def reset(sp=0xe000,ss=0x9000,occupied=False,offset=0x1234,segment=0x5678):
        C.memset(bus,0,len(bus))
        for i in range(6):ww(bus,0x278f,0x5f12+4*i,0x100+i);ww(bus,0x278f,0x5f14+4*i,0x16c9 if occupied or i else 0)
        ww(bus,ss,sp,0x1111);ww(bus,ss,sp+2,0x2222);ww(bus,ss,sp+4,offset);ww(bus,ss,sp+6,segment)
    def run(entry=0,sp=0xe000,ss=0x9000,flags=2,mask=65535,steps=16):fn(bus,len(bus),0x1000,ss,sp,entry,flags,mask,C.byref(s),steps,C.byref(r))
    reset();before=bytes(bus)
    for kw in [dict(entry=2),dict(sp=0),dict(sp=1),dict(flags=0),dict(flags=3),dict(flags=0x1000),dict(mask=0),dict(mask=1),dict(mask=0x600)]:run(**kw);require(r.status==2 and not r.bus_writes and bytes(bus)==before,'Invalidbeforeeffects');checks+=1
    for entry in range(2):run(entry=entry,steps=0,mask=0xf72a);require((r.status,r.current_sp,r.flags_word,r.flags_mask,r.bus_writes)==(3,0xe000,2,0xf72a,0) and bytes(bus)==before,'Beforeentrypartialmask');checks+=1
    reset();run(steps=5,flags=2);require((r.status,r.halt_site,r.current_sp,r.bus_writes)==(3,0x6179,0xdffe,4) and rw(bus,0x278f,0x5f14)==0x5678 and rw(bus,0x278f,0x5f18)==0x16c9,'Unmaskedpublicationprefix');checks+=1
    reset();s.registers.interrupts_enabled=1;run(steps=5,flags=0x202);require(r.status==3 and r.returned.registers.interrupts_enabled==1 and rw(bus,0x278f,0x5f18)==0x16c9,'PublicationIF1retained');checks+=1;s.registers.interrupts_enabled=0
    reset(sp=0x5f0c,ss=0x278f);run(sp=0x5f0c,ss=0x278f);require(r.status==0 and rw(bus,0x278f,0x5f14)==0x1234 and r.returned.registers.ax==0x1234,'Segmentargumentrereadafteroffsetstore');checks+=1
    reset(occupied=True);run();require((r.status,r.halt_site,r.current_sp,r.bus_writes,r.call_segment,r.call_offset,r.returned.registers.ax)==(6,0x6164,0xdffc,2,0x26a7,2,0x5fe8) and rw(bus,0x9000,0xdffc)==0x5fe8,'FatalpreCALLretainsPUSHAXtarget');checks+=1
    for slot in range(5):
        reset(occupied=True,offset=0x100+slot,segment=0x16c9);run(entry=1);require((r.status,r.slot,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.interrupts_enabled)==(0,slot,0xe004,0x2222,0x1111,1) and rw(bus,0x278f,0x5f22)==rw(bus,0x278f,0x5f24)==0,'MatchedremoveSTI-and-lastpairzero');checks+=1
    reset();run(entry=1);require(r.status==0 and r.slot==5 and r.returned.registers.interrupts_enabled==0 and r.bus_writes==1,'UnmatchedremoveIFpreserved');checks+=1
    reset(sp=0xffff);run(sp=0xffff);require(r.status==5 and r.halt_site==0x617f and r.current_sp==0xffff and r.bus_writes==5,'PreRETafteractualmetadataandPOP');checks+=1
    deps=['tools/validate_timer_callback_bus.py','analysis/history/timer-callback-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-callback-bus-context-v1.json']
    record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_callback_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'limits':'Nativeonly invalid/budget/unmaskedpublication/liveSSargument/fatalpreCALL/matchedremoveSTI/preRET diagnostics. No actualIRQfeasibility orhistoricalfailure/fatalcallee/core/game acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
