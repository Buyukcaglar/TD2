"""Native interface/service/cycle/rawtarget prefixes for fullSS6269."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_effect_tick_bus import Registers,StateRegisters,PortService,Result,ww,rw,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
    fn=C.CDLL(str(lib)).td2ega_effect_tick_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),PortService,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x278f,0x8000,1,1),0x5678,1);r=Result();events=[];vectors=0
    def service(ctx,qptr,value):q=qptr.contents;events.append((q.operation,q.port,q.value,q.interrupts_enabled));value.contents.value=0xa7;return 1
    def rejected(ctx,qptr,value):events.append(('rejected',qptr.contents.port));return 0
    port=PortService(service);reject=PortService(rejected)
    def run(memory=bus,count=len(bus),load=0x1000,ss=0x9000,sp=0xe000,flags=0x643,mask=65535,incoming=C.byref(s),adapter=port,steps=128,ports=8,output=C.byref(r)):
        fn(memory,count,load,ss,sp,flags,mask,incoming,adapter,None,steps,ports,output)
    def clear():C.memset(bus,0,len(bus));events.clear();ww(bus,0x9000,0xe000,0x1111);ww(bus,0x9000,0xe002,0x2222)
    clear();before=bytes(bus)
    for kw in [{'memory':None},{'count':len(bus)-1},{'incoming':None},{'adapter':PortService()},{'flags':0},{'flags':0x100},{'flags':0x1000},{'mask':0},{'flags':2}]:
        run(**kw);require(r.status==2 and r.bus_writes==0 and bytes(bus)==before and not events,'Invalidbeforeeffects');vectors+=1
    for target,name in [(s,'carry'),(s.registers,'interrupts_enabled'),(s.registers,'direction')]:
        old=getattr(target,name);setattr(target,name,2);run();require(r.status==2 and bytes(bus)==before,'Invalidboolean');setattr(target,name,old);vectors+=1
    run(output=None);require(bytes(bus)==before and not events,'Nulloutput');vectors+=1
    run(steps=0);require((r.status,r.current_sp,r.next_ip,r.steps,r.ports,r.bus_writes,r.flags_word)==(3,0xe000,0x6269,0,0,0,0x643) and bytes(bus)==before,'BeforeTESTbudget');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;run(steps=1);require((r.status,r.next_ip,r.steps,r.bus_writes)==(3,0x62b7,1,0) and r.flags_word==0x646 and r.flags_mask==65535,'BeforeeventCMPflags');vectors+=1
    clear();ww(bus,0x278f,0x5eee,0x6000);ww(bus,0x278f,0x5ef6,2);bus[0x278f0+0x5efc]=1;run(ports=0)
    require((r.status,r.next_ip,r.steps,r.ports,r.bus_writes)==(3,0x6281,1,0,3) and rw(bus,0x278f,0x5eee)==rw(bus,0x278f,0x5ef6)==0 and bus[0x278f0+0x5efc]==0,'BeforeINpartialpublications');vectors+=1
    clear();run(adapter=reject);require((r.status,r.next_ip,r.ports,r.bus_writes)==(4,0x6281,1,3) and events==[('rejected',0x61)],'RejectedINretainsstores');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;ww(bus,0x278f,0x5ef6,2);ww(bus,0x278f,0x5ef8,3);run(ss=0x278f,sp=0x5ef6)
    require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.ax,r.returned.carry,r.bus_writes)==(0,0x5efa,3,1,2,1,1),'OldAXthresholdCF1/actualaliasedfarwords');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;ww(bus,0x278f,0x5ef6,2);run(sp=65535)
    require((r.status,r.current_sp,r.next_ip,r.halt_site,r.bus_writes)==(5,65535,0x6287,0x6287,1),'PreRETqualificationafterDEC');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;bus[0x278f0+0x5efd]=1;run(steps=32)
    require((r.status,r.next_ip,r.steps,r.ports,r.bus_writes)==(3,0x62b7,32,0,93),'Queuedzerosegmentcyclebudget');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;ww(bus,0x278f,0x5eee,0x6000);ww(bus,0x278f,0x5ef0,0x1000);bus[0x61000]=0xff;ww(bus,0x16c9,0x6336,0x1234);run()
    require((r.status,r.next_ip,r.raw_target,r.steps,r.ports,r.bus_writes,r.returned.registers.bx)==(6,0x632f,0x1234,2,0,0,2),'UnknownliteralCSwordbeforeJMP');vectors+=1
    clear();bus[0x278f0+0x5efb]=1;ww(bus,0x278f,0x5eee,0x6000);ww(bus,0x278f,0x5ef0,0x1000)
    for i,b in enumerate([0xff,5,65,2,0]):bus[0x61000+i]=b
    ww(bus,0x16c9,0x6336,0x634c);run()
    require((r.status,r.steps,r.ports,r.bus_writes,r.raw_target,r.halt_site)==(0,3,4,5,0x634c,0x62fc) and bus[0x278f0+0x5efa]==5,'Swappedrecognizedtargetexecutesactualcommand');vectors+=1
    deps=['tools/validate_effect_tick_bus.py','analysis/history/effect-tick-bus-build-setup-v2.json','docs/recovery/evidence/td2ega-effect-tick-bus-context-v1.json']
    record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_effect_tick_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonly invalid/null/flag profiles, beforeTEST-event-IN budgets, rejectedINpartialpublications, oldAX-CF1/aliasedfarword, preRETafterDEC, queuedzerosegmentcycle andliteralunknown/swappedcommand-target checks. Excludedfromoriginalvectors; no sourceerror/realIRQ/audio/core/game-fidelity equivalence.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':vectors}))
if __name__=='__main__':main()
