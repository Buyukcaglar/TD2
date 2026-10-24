"""Native invalid/service/budget prefixes for fullSS61BF/6230, not source errors."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_handler_bus import Registers,StateRegisters,Request,Response,PortService,Call,Services,Limits,Result,ww,rw,require

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
    fn=C.CDLL(str(lib)).td2ega_timer_handler_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x5000,0x8000,1,1),0x5678,1);caps=Limits();r=Result();seen=[]
    def port_ok(ctx,q,value):value.contents.value=0xa7;return 1
    def call_reject(ctx,memory,count,q,response):seen.append(bytes(q.contents));return 0
    port=PortService(port_ok);call=Call(call_reject);services=Services(port,call,None,0);vectors=0
    def run(memory=bus,count=len(bus),load=0x1000,ss=0x9000,sp=0xe000,entry=0,flags=0x643,mask=65535,state=C.byref(incoming),limits=C.byref(caps),adapter=C.byref(services),output=C.byref(r)):
        fn(memory,count,load,ss,sp,entry,flags,mask,state,limits,adapter,output)
    for kw in [{'memory':None},{'count':len(bus)-1},{'sp':67},{'sp':0xffe1},{'entry':2},{'flags':0x100},{'flags':0},{'mask':0},{'state':None},{'limits':None},{'adapter':None},{'entry':1,'sp':5},{'entry':1,'sp':0xfffb}]:
        run(**kw);require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
    for target,name in [(incoming,'carry'),(incoming.registers,'interrupts_enabled'),(incoming.registers,'direction')]:
        old=getattr(target,name);setattr(target,name,2);run();require(r.status==2 and not any(bus),'Invalidflagboolean');setattr(target,name,old);vectors+=1
    services.undefined_af=2;run();require(r.status==2 and not any(bus),'InvalidAF');services.undefined_af=0;vectors+=1
    old=services.port;services.port=PortService();run();require(r.status==2 and not any(bus),'Nullport');services.port=port;vectors+=1
    old=services.call;services.call=Call();run();require(r.status==2 and not any(bus),'Nullcall');services.call=call;vectors+=1
    run(output=None);require(not any(bus),'Nulloutput');vectors+=1
    run();require((r.status,r.current_sp,r.next_ip,r.steps,r.calls,r.ports,r.bus_writes,r.flags_word)==(3,0xe000,0x61bf,0,0,0,0,0x643),'BeforeCLIbudget');vectors+=1
    run(entry=1);require((r.status,r.current_sp,r.next_ip,r.steps,r.bus_writes)==(3,0xe000,0x6230,0,0),'BeforebridgeCMPbudget');vectors+=1
    caps.steps=1
    for load in [0x1000,0x2345]:
        for ss,sp in [(0x9000,68),(load+0x178f,0xe000)]:
            C.memset(bus,0,len(bus));run(load=load,ss=ss,sp=sp)
            require((r.status,r.current_sp,r.next_ip,r.steps,r.ports,r.bus_writes)==(3,sp-18,0x61cb,1,0,9),'BeforeEOIfullSSprefix')
            require([rw(bus,ss,sp-2*i) for i in range(1,10)]==[0x5000,0x8000,0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x5678],'Allninesavedwords')
            require(r.returned.registers.ax==0xa520 and r.returned.registers.ds==0x5000 and r.returned.registers.interrupts_enabled==0,'CLIandALonlybeforeEOI');vectors+=1
    caps.ports=8
    for af in [0,1]:
        services.undefined_af=af;C.memset(bus,0,len(bus));ww(bus,0x278f,0x5e88,0x1234);ww(bus,0x278f,0x5e8a,0x5678);incoming.registers.ds=0x278f
        run(entry=1);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,0xe000,0x6259,0,2),'INTbudgetafterIVTwrites');require((r.flags_word,r.flags_mask)==(0x646+(af<<4),0xffef),'XORundefinedAFstorageprofile');vectors+=1
        caps.calls=1;seen.clear();run(entry=1)
        require((r.status,r.current_sp,r.next_ip,r.calls,r.old_interrupts,r.bus_writes)==(4,0xdffa,0x6259,1,1,5),'RejectedoldINTafterframe')
        q=Request.from_buffer_copy(seen[0]);require((q.kind,q.segment,q.offset,q.current_sp,q.flags_word,q.flags_mask)==(1,0x5678,0x1234,0xdffa,0x446+(af<<4),0xffef),'OldINTentryIF0-DFretained')
        require([rw(bus,0x9000,0xdffa+2*i) for i in range(3)]==[0x625b,0x16c9,0x646+(af<<4)],'ExplicitFLAGS-CS-IPframe');vectors+=1;caps.calls=0
    services.undefined_af=0;incoming.registers.ds=0x5000;caps.calls=1;caps.steps=4;seen.clear();C.memset(bus,0,len(bus));ww(bus,0x278f,0x5f12,0x100);ww(bus,0x278f,0x5f14,0x7000);run()
    require(r.status==4 and r.callbacks==1 and r.current_sp==0xe000-22 and r.next_ip==0x6217,'Rejectedfarcallbackprefix')
    q=Request.from_buffer_copy(seen[0]);require((q.kind,q.segment,q.offset,q.current_sp)==(0,0x7000,0x100,0xe000-22),'Farcallbackrequestcoordinates');require([rw(bus,0x9000,q.current_sp+2*i) for i in range(2)]==[0x621b,0x16c9],'ActualfarCALLframe');vectors+=1
    deps=['tools/validate_timer_handler_bus.py','analysis/history/timer-handler-bus-build-setup-v3.json','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json','analysis/history/timer-handler-bus-diagnostics-refinement-v2.json','analysis/history/validate_timer_handler_bus_diagnostics_attempt_v1.py']
    record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_handler_bus.c').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonly invalid-beforeeffects/null-interface/beforeCLI-beforeEOI-nineSSsaves/beforeINTpostIVTwrites/undefinedAF0-1storedFLAGS/rejectedoldINTandfarcallbackactualframes. Diagnosticbudgets-servicefailures distinctfromsourceerrors. No actualcallbackbody/IRQdelivery/lifetime/core/gameplay/fidelity.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':vectors}))
if __name__=='__main__':main()
