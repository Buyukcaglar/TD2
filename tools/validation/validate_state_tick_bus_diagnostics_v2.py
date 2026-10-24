"""403B native interface and before-first-CALL stack prefix, not full recovery."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_input_poll_bus import Registers,StateRegisters,Limits as InputLimits,Services,require
from validate_mutable_control import State
class SimLimits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['iterations','rows','ring_calls','guard_calls','sample_calls','child_calls','control_calls','dispatch_calls']]
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['root_calls','control_calls','control_nested_calls','math_calls','math_iterations','mode_calls','mode_nested_calls','mode_iterations','record_steps','record_calls','pair_calls']]+[('simulation',SimLimits),('input',InputLimits)]
class Result(C.Structure):_fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['root_calls','bus_writes']]+[(n,C.c_uint16) for n in ['stage','raw_target','mode_exit_kind','reserved']]+[('returned',StateRegisters)]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require(C.sizeof(Limits)==92 and C.sizeof(Result)==48,'Layout')
 fn=C.CDLL(str(lib)).td2ega_state_tick_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(State),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
 bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x8000,0,0),0x5678,0);code=State();code.branch_42ad=1;limits=Limits();services=Services();r=Result();vectors=0
 def run(memory=bus,count=len(bus),load=0x1000,ss=0x9000,sp=0xe000,incoming=C.byref(s),state=C.byref(code),caps=C.byref(limits),adapter=C.byref(services),output=C.byref(r)):
  fn(memory,count,load,ss,sp,incoming,state,caps,adapter,output)
 for kw in [{'memory':None},{'count':len(bus)-1},{'sp':45},{'sp':0xffe1},{'incoming':None},{'state':None},{'caps':None},{'adapter':None}]:
  run(**kw);require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);run();require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,0);vectors+=1
 for field,bad in [('branch_424a',1),('branch_4275',1),('branch_42ad',0)]:
  before=getattr(code,field);setattr(code,field,bad);run();require(r.status==2 and not any(bus),'Invalidcodeform');setattr(code,field,before);vectors+=1
 services.undefined_af=2;run();require(r.status==2 and not any(bus),'InvalidAFprofile');services.undefined_af=0;vectors+=1;run(output=None);require(not any(bus),'Nulloutput');vectors+=1
 for load in [0x1000,0x2345]:
  for sp in [46,0xe000,0xffe0]:
   for same in [False,True]:
    C.memset(bus,0,len(bus));ss=load+0x178f if same else 0x9000;s.carry=1;s.registers.interrupts_enabled=1;s.registers.direction=1
    run(load=load,ss=ss,sp=sp);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.root_calls,r.bus_writes,r.stage)==(3,sp-8,load+0x6c9,0x4046,0,4,0x4046),'BeforefirstnearCALLprefix')
    require((r.returned.registers.ax,r.returned.registers.ds,r.returned.registers.es,r.returned.registers.di,r.returned.bp,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(load+0x178f,load+0x178f,load+0x178f,0x4567,0x5678,1,1,1),'PrincipalDS-ESassignment/flagsnotyetCLD')
    def word(o):
     at=((ss<<4)+o)&0xfffff;return bus[at]|(bus[(at+1)&0xfffff]<<8)
    require([word(sp-d) for d in [2,4,6,8]]==[0x5000,0x8000,0x4567,0x5678],'ActualPUSHDS-ES-DI-BPorder')
    expected=bytearray(len(bus))
    for d,v in zip([2,4,6,8],[0x5000,0x8000,0x4567,0x5678]):
     at=((ss<<4)+sp-d)&0xfffff;expected[at:at+2]=v.to_bytes(2,'little')
    require(bytes(bus)==expected,'OnlyfoursavedwordsbeforeCALL');vectors+=1
 deps=['tools/validate_input_poll_bus.py','tools/validate_mutable_control.py','analysis/history/state-tick-diagnostics-preparation-v2.json','analysis/history/validate_state_tick_bus_diagnostics_attempt_v1.py','docs/recovery/evidence/td2ega-state-tick-bus-native-diagnostics-v1.json'];record={'schema':1,'result':'pass','image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_state_tick_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonlyinterface/prefix beforefirst403B4046CALL/actualfourSSsavedwords/principalDS-ESloadrelocation/retainedCFIFDF-beforeCLD/twoloads-SP46-FFE0/DS-SScontrast. No actualcallee/rootRET/originalcomparison/fullfunctionregistration/wholecore/FN3lifetime-IRQ/game/fidelity acceptance.'}
 out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(json.dumps({'result':'pass','native_prefix_checks':vectors,'whole403B':'unverified'}))
if __name__=='__main__':main()
