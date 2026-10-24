"""Native-only startup timer boundary, port failure and FLAGS diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_control_bus import Result,Registers,StateRegisters,PortService,ww,rw,require

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();lib=args.library.resolve();out=args.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_timer_control_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),PortService,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x278f,0x8000,0,0),0x5678,0);r=Result();events=[];mode={'fail':0};checks=0
    def service(ctx,qptr,value):
        q=qptr.contents;events.append((q.operation,q.port,q.value,q.interrupts_enabled));value.contents.value=0xa5 if q.port==0x21 else 0xa7;return int(len(events)!=mode['fail'])
    port=PortService(service)
    def reset(divisor=3):
        C.memset(bus,0,len(bus));events.clear();ww(bus,0x9000,0xe000,0x1111);ww(bus,0x9000,0xe002,0x2222);ww(bus,0x9000,0xe004,divisor);ww(bus,0,0x20,0x61bf);ww(bus,0,0x22,0x16c9);ww(bus,0x278f,0x5e88,0x1234);ww(bus,0x278f,0x5e8a,0x5678)
    def run(entry=0,mask=65535,flags=2,sp=0xe000,steps=41,ports=9,service_pointer=None):
        fn(bus,len(bus),0x1000,0x9000,sp,entry,flags,mask,C.byref(s),port if service_pointer is None else service_pointer,None,steps,ports,C.byref(r))
    reset();before=bytes(bus)
    for kw in [dict(entry=3),dict(sp=0),dict(sp=1),dict(mask=0),dict(mask=1),dict(mask=0x600),dict(flags=0),dict(flags=3),dict(flags=0x1000),dict(service_pointer=PortService())]:
        run(**kw);require(r.status==2 and not r.bus_writes and not events and bytes(bus)==before,'Invalidbeforeeffects '+str(kw));checks+=1
    for entry in range(3):
        reset();before=bytes(bus);run(entry=entry,steps=0);require(r.status==3 and r.current_sp==0xe000 and not r.bus_writes and bytes(bus)==before,'Beforeentry');checks+=1
    reset();run(entry=1,ports=0);require((r.status,r.halt_site,r.current_sp,r.flags_mask,r.initial_divisor,r.quotient,r.bus_writes)==(3,0x60a7,0xdffe,0xf72a,3,21845,7) and not events and rw(bus,0x278f,0x5e98)==21845,'SuccessfulIDIVprefixhasunknownCFandliveeffects');checks+=1
    for divisor in [0,1,2,0xffff]:
        reset(divisor);run(entry=1);require((r.status,r.halt_site,r.current_sp,r.bus_writes,r.initial_divisor,r.quotient,r.flags_mask)==(6,0x6061,0xdffe,1,divisor,0,0xffef) and not events,'PreIDIVprefix '+str(divisor));checks+=1
    for entry,count in [(0,9),(1,9),(2,8)]:
        for failure in range(1,count+1):
            reset();mode['fail']=failure;run(entry=entry);require(r.status==4 and r.ports==len(events)==failure and r.current_sp==(0xe000 if entry==2 else 0xdffe) and r.next_segment==0x16c9,'Portfailureprefix');checks+=1
    mode['fail']=0
    for entry in range(3):
        reset();run(entry=entry);require((r.status,r.current_sp,r.next_segment,r.next_ip)==(0,0xe004,0x2222,0x1111),'Retiredfarrootnofollow');checks+=1
    reset();run(sp=0xfffd);require(r.status==5 and r.current_sp==0xfffd and r.halt_site==0x6109 and len(events)==9,'PreRETretainsbodyeffects');checks+=1
    deps=['tools/validate_timer_control_bus.py','analysis/history/timer-control-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-control-bus-context-v1.json']
    record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_control_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'limits':'Native-only invalidargument/budget/portfailure/preIDIV/preRET and partialFLAGS diagnostics; no source errors/historical exceptions/actualIRQ/core/game acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
