"""Native registration-tail actualframes and child-stop diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_startup_tail_bus import Result,Limits,Registers,StateRegisters,PortService,ww,rw,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_timer_startup_tail_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.POINTER(Limits),PortService,C.c_void_p,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x278f,0x8000,0,0),0x5678,0);r=Result();caps=Limits(3,41,9,16);events=[];mode={'kind':'normal'};checks=0
    def service(ctx,qptr,value):
        q=qptr.contents;events.append((q.operation,q.port,q.value,q.interrupts_enabled));value.contents.value=0xa5 if q.port==0x21 else 0xa7
        if len(events)==1 and mode['kind']=='raw':ww(bus,0x9000,0xdffc,0x3333);ww(bus,0x9000,0xdffe,0x4444)
        return int(mode['kind']!='fail')
    port=PortService(service)
    def reset():
        C.memset(bus,0,len(bus));events.clear()
        for i in range(6):ww(bus,0x278f,0x5f12+4*i,0x100+i);ww(bus,0x278f,0x5f14+4*i,0x16c9)
        ww(bus,0,0x20,0x1234);ww(bus,0,0x22,0x5678);ww(bus,0x9000,0xe000,0x1111);ww(bus,0x9000,0xe002,0x2222)
    def run(sp=0xe000,flags=2,mask=65535):fn(bus,len(bus),0x1000,0x9000,sp,flags,mask,C.byref(s),C.byref(caps),port,None,C.byref(r))
    reset();before=bytes(bus)
    for kw in [dict(sp=9),dict(sp=0xffe1),dict(mask=0),dict(mask=1),dict(mask=0x600),dict(flags=0),dict(flags=3),dict(flags=0x1000)]:run(**kw);require(r.status==2 and not r.bus_writes and not events and bytes(bus)==before,'Invalidbeforeeffects');checks+=1
    caps.calls=0;run(mask=0xf72a);require((r.status,r.current_sp,r.next_ip,r.flags_mask,r.bus_writes,r.calls)==(3,0xe000,0x3fd9,0xf72a,0,0) and bytes(bus)==before,'BeforefirstCALL');checks+=1
    reset();caps.calls=1;run();require((r.status,r.stage,r.current_sp,r.next_ip,r.calls,r.ports,r.returned.registers.ax)==(3,0,0xdffc,0x3fe3,1,9,0x6269) and rw(bus,0x9000,0xdffc)==0x6269 and rw(bus,0x9000,0xdffe)==0x16c9,'SecondCALLprefixretainsactualarguments');checks+=1
    reset();caps.calls=3;caps.callback_steps=6;run();require((r.status,r.stage,r.next_ip,r.calls,r.ports)==(3,3,0x6179,3,9) and rw(bus,0x278f,0x5f16)==0x403b and rw(bus,0x278f,0x5f18)==0x16c9 and rw(bus,0x278f,0x5f1c)==0x16c9,'Secondaddpublicationprefixbeforefollowingclear');checks+=1
    reset();caps.callback_steps=16;mode['kind']='fail';run();require((r.status,r.stage,r.current_sp,r.next_ip,r.calls,r.ports)==(4,1,0xdffa,0x60a7,1,1),'Portfailurewithinactualtimerframe');checks+=1
    reset();mode['kind']='raw';run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.calls)==(1,1,0xe000,0x4444,0x3333,1),'Rawfirstchildstopsbeforearguments');checks+=1
    reset();mode['kind']='normal';run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.calls,r.ports)==(0,0,0xe004,0x2222,0x1111,3,9) and [rw(bus,0x278f,o) for o in [0x5f12,0x5f14,0x5f16,0x5f18,0x5f1c]]==[0x6269,0x16c9,0x403b,0x16c9,0],'Nativeactualregisteredorderandrootretirement');checks+=1
    deps=['tools/validate_timer_startup_tail_bus.py','analysis/history/timer-startup-tail-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-startup-tail-bus-context-v1.json']
    record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_startup_tail_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'limits':'Nativeonlyinvalid/CALLbudget/actualarguments/secondpublicationprefix/portfailure/rawchildstop/nativepublishedorder diagnostics, notwhole3F40/actualIRQ-lifetime/core/gameacceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
