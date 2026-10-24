"""Whole420A native rejection, actualnearroot and beforeCALL prefix diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_input_update_bus import Registers,StateRegisters,State,Limits,Services,Result,require

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 fn=C.CDLL(str(lib)).td2ega_input_update_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.POINTER(State),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
 bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x8000,0,0),0x5678,0);state=State();state.branch_42ad=1;limits=Limits(16,2,1,5000);services=Services();r=Result();vectors=0
 def run(memory=bus,count=len(bus),sp=0xe000,flags=2,mask=0xffff,incoming=C.byref(s),code=C.byref(state),caps=C.byref(limits),adapter=C.byref(services),output=C.byref(r)):
  fn(memory,count,0x1000,0x9000,sp,flags,mask,incoming,code,caps,adapter,output)
 for kw in [{'memory':None},{'count':len(bus)-1},{'sp':23},{'sp':0xffe1},{'flags':0},{'flags':0x102},{'flags':0x1002},{'mask':0xffdf},{'flags':3},{'flags':0x202},{'flags':0x402},{'incoming':None},{'code':None},{'caps':None},{'adapter':None}]:
  run(**kw);require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for name,value in [('branch_424a',1),('branch_4275',1),('branch_42ad',0)]:
  old=getattr(state,name);setattr(state,name,value);run();require(r.status==2 and not any(bus),'Invalidbranchform');setattr(state,name,old);vectors+=1
 services.undefined_af=2;run();require(r.status==2 and not any(bus),'InvalidundefinedAFchoice');services.undefined_af=0;vectors+=1
 run(output=None);require(not any(bus),'Nulloutput');vectors+=1
 def put(sg,o,v,width=2):
  at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255
  if width==2:bus[(at+1)&0xfffff]=(v>>8)&255
 put(0x9000,0xe000,0x1111);put(0x5000,0x33d4,1,1);limits.calls=0
 run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bios_calls,r.bus_writes,r.flags_word,r.flags_mask)==(3,2,0xe000,0x16c9,0x4266,0,0,0,2,0xffff),'Pausedbefore6601CALL/fullinitialCMP');vectors+=1
 put(0x5000,0x33d4,0,1);run();require((r.status,r.stage,r.next_ip,r.bus_writes,r.flags_word)==(3,1,0x4211,0,0x46),'Activebefore6620CALL');vectors+=1
 put(0x5000,0x33d4,1,1);limits.calls=1;run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bios_calls,r.bus_writes,r.flags_word,r.flags_mask)==(3,3,0xe000,0x16c9,0x427d,1,1,8,0x246,0xffef),'Before44A6CALL afteractualINT-handler/PUSH-POPAX');vectors+=1
 limits.calls=2;run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bios_calls,r.callback_calls,r.port_reads,r.bus_writes,r.flags_valid,r.zero_flag)==(0,3,0xe002,0x16c9,0x1111,2,1,0,0,9,1,1),'ActualnearrootRET afterfar6601andnear44A6');require(r.returned.bp==0x5678 and r.returned.registers.ax==0 and r.returned.registers.interrupts_enabled==1 and r.flags_word==0x246 and r.flags_mask==0xf76b,'PausednormalactualhandlerSTI/scannerAX0/conservativeflags');vectors+=1
 put(0x9000,24,0x3333);run(sp=24,mask=0xffef);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes)==(0,26,0x16c9,0x3333,9),'MinimumSP24/currentnearrootword');vectors+=1
 # PreparedJNE skipswrite whenactivity!=1; originalJBE skipswhenactivity<=1.
 for branch,activity,should_write in [(0,1,False),(0,2,True),(2,1,True),(2,2,False)]:
  C.memset(bus,0,len(bus));put(0x9000,0xe000,0x1111);put(0x5000,0x33d4,1,1);put(0x278f,0x62b6,1);put(0x5000,0x8a9a,activity);state.branch_4275=branch;limits.calls=2
  run();require(r.status==0 and bus[0x55490]==(0xff if should_write else 0) and r.bus_writes==(10 if should_write else 9),'LiteralJBE-vs-JNEpublicationpolarity');vectors+=1
 deps=['tools/validate_input_update_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonlyrejection-beforeeffects/branchprofiles/FLAGSmask-Stateconsistency/nulloutput/rootbeforefarCALL/actualmodeledINT-69B7/ownPUSH-POPAX/before44A6/actualnearRET-minSP24/conservativeCFZFflagsmask. Originalequivalence separate; whole403B/caller-allwriters-capacity-lifetime-IRQ-core/game/fidelity open.'}
 out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
