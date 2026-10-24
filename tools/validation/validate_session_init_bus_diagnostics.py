"""Native complete initialization prefixes, aliases and return diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_session_init_bus import Result,Limits,TailLimits,Registers,StateRegisters,PortService,ww,rw,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_session_init_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),PortService,C.c_void_p,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x278f,0x8000,0,0),0x5678,0);r=Result();caps=Limits(120,3,TailLimits(3,41,9,16));events=[];mode={'fail':False};checks=0
    def service(ctx,qptr,value):q=qptr.contents;events.append((q.operation,q.port,q.value,q.interrupts_enabled));value.contents.value=0xa5 if q.port==0x21 else 0xa7;return int(not mode['fail'])
    port=PortService(service)
    def reset(sp=0xe000,ss=0x9000):
        C.memset(bus,0,len(bus));events.clear();s.carry=s.registers.interrupts_enabled=s.registers.direction=0
        for o in range(0x335d,0x3365):bus[0x278f0+o]=0xa5
        for i in range(71):bus[0x278f0+0x3b51+i]=1
        for i in range(512):bus[0x278f0+0x347e+i]=i&255
        ww(bus,0x278f,0x3811,0xffff);ww(bus,0x278f,0x23c6,0x1234);ww(bus,0x278f,0x23c8,0x5678);ww(bus,0x278f,0x66e6,0x1357)
        for i in range(6):ww(bus,0x278f,0x5f12+4*i,0x100+i);ww(bus,0x278f,0x5f14+4*i,0x16c9)
        ww(bus,0,0x20,0x1234);ww(bus,0,0x22,0x5678);ww(bus,ss,sp,0x1111);ww(bus,ss,sp+2,0x2222)
    def run(entry=0,sp=0xe000,ss=0x9000,flags=2,mask=65535,service_pointer=None):fn(bus,len(bus),0x1000,ss,sp,entry,flags,mask,C.byref(s),C.byref(caps),port if service_pointer is None else service_pointer,None,C.byref(r))
    reset();before=bytes(bus)
    for kw in [dict(entry=5),dict(sp=9),dict(sp=0xffe1),dict(entry=1,sp=1),dict(entry=3,sp=5),dict(mask=0),dict(mask=1),dict(mask=0x600),dict(flags=0),dict(flags=3),dict(flags=0x1000),dict(service_pointer=PortService())]:run(**kw);require(r.status==2 and not r.bus_writes and not events and bytes(bus)==before,'Invalidbeforeeffects');checks+=1
    caps.steps=0
    for entry in range(5):run(entry=entry,mask=0xf72a);require((r.status,r.current_sp,r.flags_word,r.flags_mask,r.bus_writes)==(3,0xe000,2,0xf72a,0) and bytes(bus)==before,'Beforebodypartialmask');checks+=1
    reset();s.carry=s.registers.interrupts_enabled=s.registers.direction=1;caps.steps=1;run(flags=0x643);require((r.status,r.next_ip,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.es,r.returned.registers.direction,r.returned.registers.interrupts_enabled,r.bus_writes)==(3,0x3f4d,8,0x335d,0x278f,0,1,0),'BeforeREPCLD-and-liveGPR');checks+=1
    reset();caps.steps=4;run();require((r.status,r.next_ip,r.returned.registers.cx,r.returned.registers.di,r.bus_writes)==(3,0x3f4d,5,0x3360,3) and bytes(bus[0x278f0+0x335d:0x278f0+0x3365])==bytes(3)+bytes([0xa5])*5,'PartialREPexactstores');checks+=1
    reset();caps.steps=38;run();require((r.status,r.next_ip,r.returned.registers.si,r.returned.registers.cx,r.steps,r.bus_writes)==(3,0x3fbf,0x3b51,71,38,37),'Beforefoldhead');checks+=1
    reset();caps.steps=39;run();require((r.status,r.next_ip,r.returned.registers.si,r.returned.registers.cx,r.returned.registers.bx,r.returned.registers.ax)==(3,0x3fbf,0x3b52,70,4,0x0404),'Onefolditeration-liveAX-BX-SI-CX');checks+=1
    reset();caps.steps=120;caps.tail.calls=0;run();require((r.status,r.stage,r.next_ip,r.tail_calls,r.flags_mask)==(3,100,0x3fd9,0,65535) and rw(bus,0x278f,0x3811)==0x3b32 and bus[0x278f0+0x33bd]==4,'Live3811wrap-and-frozentailexactentry');checks+=1;caps.tail.calls=3
    for entry,sp,cursor in [(0,0x66ea,0x403b),(1,0x66e8,0x403a),(3,0x66ec,0x403a)]:
        reset(sp,0x278f);run(entry=entry,sp=sp,ss=0x278f);require(r.status==0 and rw(bus,0x278f,0x66e6)==cursor,'ConditionalSSringstackwriter');checks+=1
    reset(0x52dc,0x278f);run(entry=1,sp=0x52dc,ss=0x278f);require((r.status,r.stage,r.next_segment,r.next_ip,r.current_sp,r.init_calls)==(1,2,0x16c9,0,0x52dc,1),'Nearreturnoverwrittenbyactualclear');checks+=1
    reset(0x52dc,0x278f);run(entry=3,sp=0x52dc,ss=0x278f);require((r.status,r.stage,r.next_segment,r.next_ip,r.init_calls)==(1,1,0,0x1e36,2),'Farreturnoverwrittenstopsbefore38F2');checks+=1
    reset(0x23cc,0x278f);run(entry=3,sp=0x23cc,ss=0x278f);require(r.status==0 and rw(bus,0x278f,0x2f4c)==0x403a and rw(bus,0x278f,0x2f4e)==0x1e58,'CurrentDSboundsrereadaftercallerframewrites');checks+=1
    reset();run(entry=2,service_pointer=PortService());require(r.status==0 and not events and rw(bus,0x278f,0x2f4c)==0x1234 and rw(bus,0x278f,0x2f4e)==0x5678,'Nonportrootallowsnullservice');checks+=1
    reset(0xfffe);run(entry=4,sp=0xfffe);require((r.status,r.current_sp,r.next_segment,r.next_ip)==(0,0,0x16c9,0x1111),'NearRETword-endwrap');checks+=1
    reset(0xffff);run(entry=4,sp=0xffff);require((r.status,r.current_sp,r.next_ip,r.bus_writes)==(5,0xffff,0x5438,5),'QualifiednearRETafterleafwrites');checks+=1
    reset(0xfffc);run(entry=2,sp=0xfffc);require((r.status,r.current_sp,r.next_segment,r.next_ip)==(0,0,0x2222,0x1111),'FarRETendwrap');checks+=1
    reset(0x942e,0x278f);run(sp=0x942e,ss=0x278f);require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0),'BSS942Eoverwritesactualrootword');checks+=1
    reset();mode['fail']=True;run();require((r.status,r.stage,r.current_sp,r.next_ip,r.tail_calls,r.ports,r.bus_writes)==(4,101,0xdffa,0x60a7,1,1,48),'Portfailureaftercompleteprefixwithactualtimerframe');checks+=1
    deps=['tools/validate_session_init_bus.py','analysis/history/session-init-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-session-init-bus-context-v1.json']
    record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_session_init_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'limits':'Nativeonlyinvalid/budget/partialREP-fold/current3811-wrap/delegatedtail/ringstackaliases/near-farrawreturns/livebounds/BSS942E/preRET/portfailure diagnostics. Conditionalstackwrites are not intentionalreset/seeding oractualcaller-domain/IRQ-lifetime/core/game acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
