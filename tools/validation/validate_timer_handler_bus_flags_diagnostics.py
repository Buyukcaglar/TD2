"""Native partial-FLAGS child prefix and flag-regaining diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_handler_bus import Registers,StateRegisters,PortService,Call,Services,Limits,Result,ww,rw,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_timer_handler_bus_flags;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x5000,0x8000,0,0),0x5678,0);caps=Limits(4,4,4);r=Result();mode={'kind':'normal'};calls=[]
    def port_ok(ctx,q,value):value.contents.value=0xa7;return 1
    def child(ctx,memory,count,qptr,rptr):
        q=qptr.contents;calls.append((q.kind,q.segment,q.offset,q.current_sp));o=rptr.contents;o.returned=q.registers;o.flags_word=0x402;o.flags_mask=0xf72b;o.returned.carry=0;o.returned.registers.interrupts_enabled=0;o.returned.registers.direction=1
        if mode['kind']=='prefix':o.status=3;o.current_sp=q.current_sp;o.next_segment=q.segment;o.next_ip=q.offset;return 1
        o.current_sp=(q.current_sp+4)&65535;o.next_segment=rw(bus,q.ss,q.current_sp+2);o.next_ip=rw(bus,q.ss,q.current_sp)
        if mode['kind']=='raw':o.next_segment=0x4444
        if mode['kind']=='cycle':o.returned.registers.di=(o.returned.registers.di-4)&65535
        return 1
    port=PortService(port_ok);call=Call(child);services=Services(port,call,None,0);vectors=0
    def clear():C.memset(bus,0,len(bus));calls.clear();ww(bus,0x9000,0xe000,0x1111);ww(bus,0x9000,0xe002,0x2222);ww(bus,0x9000,0xe004,0x643);ww(bus,0x278f,0x5e9a,2);ww(bus,0x278f,0x5f12,0x403b);ww(bus,0x278f,0x5f14,0x16c9)
    def run(mask=0xf72b):fn(bus,len(bus),0x1000,0x9000,0xe000,0,2,mask,C.byref(s),C.byref(caps),C.byref(services),C.byref(r))
    clear();before=bytes(bus)
    for mask in [0,1,0x600,0xffff^0x601]:run(mask);require(r.status==2 and r.bus_writes==0 and bytes(bus)==before,'Invalidpartialmaskbeforeeffects');vectors+=1
    caps.steps=0;run();require((r.status,r.current_sp,r.next_ip,r.flags_word,r.flags_mask)==(3,0xe000,0x61bf,2,0xf72b) and bytes(bus)==before,'IncomingpartialbeforeCLI');vectors+=1;caps.steps=4
    clear();mode['kind']='prefix';run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.flags_word,r.flags_mask)==(3,0xe000-22,0x16c9,0x403b,0x402,0xf72b) and r.callbacks==1 and len(calls)==1,'Childprefixkeepspartialword-and-entrycoordinates');vectors+=1
    clear();mode['kind']='raw';run();require(r.status==1 and r.next_segment==0x4444 and r.flags_mask==0xf72b and r.current_sp==0xe000-18,'Rawchildkeepspartialwithoutfollowing');vectors+=1
    clear();mode['kind']='normal';run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.flags_word,r.flags_mask,r.callbacks)==(0,0xe006,0x2222,0x1111,0x643,65535,1),'Normalcallbackregainsflags/finalactualIRET');vectors+=1
    clear();mode['kind']='cycle';caps.steps=3;run();require((r.status,r.next_ip,r.flags_word,r.flags_mask,r.callbacks)==(3,0x620e,0x457,65535,2),'ADDDI4definesarithmeticafterpartialcallback');vectors+=1
    deps=['tools/validate_timer_handler_bus.py','analysis/history/timer-handler-bus-flags-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-handler-bus-flags-context-v1.json']
    record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_handler_bus_flags.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonly invalidpartialmasks/incomingpartialprefix/retiredchildprefix-rawreturn/normalIRETflagrestore/ADDDI4arithmeticmask-regaining. ExplicitABIprofilediagnostics, not sourceerror or actualchildbody/IRQ/core/game-fidelity acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':vectors}))
if __name__=='__main__':main()
