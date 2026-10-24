"""Native-only invalid/budget/service cases, MOV flags, savedBP alias and IN bound."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_gameport_bus import Registers,StateRegisters,Request,Service,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_gameport_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x5432,0,0),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,entry,zero,state in [(None,len(bus),0,0,C.byref(s)),(bus,len(bus)-1,0,0,C.byref(s)),(bus,len(bus),0,0,None),(bus,len(bus),3,0,C.byref(s)),(bus,len(bus),0,2,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,0xe000,entry,zero,state,5000,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),5000,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),5000,null,None,None);require(not any(bus),'Nulloutput');vectors+=1
 def put(sg,o,v):
  at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222);s.registers.interrupts_enabled=s.registers.direction=1;fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),5000,null,None,C.byref(r));require((r.status,r.reads,r.transfers,r.bus_writes,r.returned.registers.ax,r.returned.registers.interrupts_enabled,r.returned.registers.direction,r.returned.carry,r.flags_valid,r.zero_flag)==(0,0,0,0,0,1,1,0,1,1),'Disablednoadapter/definedflags/IFDFretained');vectors+=1
 bus[0x56cfc]=bus[0x56cfe]=1;bus[0x56281]=0xa5;fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),0,null,None,C.byref(r));require((r.status,r.next_segment,r.next_ip,r.reads,r.transfers,r.bus_writes,r.current_sp)==(3,0x16c9,0x669f,0,0,1,0xe000),'BudgetbeforefirstIN');require(bus[0x56281]==0 and bytes(bus[0x9e000:0x9e004])==bytes.fromhex('11112222'),'Budgetpartialstore/actualframe');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),5000,null,None,C.byref(r));require((r.status,r.next_ip,r.reads,r.transfers,r.bus_writes)==(4,0x669f,0,0,1),'Missingadapter distinctfrombudget');vectors+=1
 def fail_out(ctx,q,value):
  if q.contents.operation:return 0
  value.contents.value=0x33;return 1
 callback=Service(fail_out);fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),5000,callback,None,C.byref(r));require((r.status,r.next_ip,r.reads,r.transfers,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.interrupts_enabled)==(4,0x66b5,1,1,4,0xa533,0xb103,0,0),'OUTfailureafterCLI/initialstate');vectors+=1
 s.carry=1
 for zero in [0,1]:
  put(0x5000,0x6282,0x1111);put(0x5000,0x6284,0x2222);fn(bus,len(bus),0x1000,0x5000,0x6282,1,zero,C.byref(s),0,null,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.returned.carry,r.flags_valid,r.zero_flag)==(0,0x6286,0,0x50,5,1,1,zero),'InitializerMOVflags/DSoverwritesactualfarreturn');require((r.returned.registers.ax,r.returned.registers.bx,r.returned.bp,r.returned.registers.direction)==(0xa55a,0xb123,0x5678,1),'InitializerGPRDF');vectors+=1
 bus[0x5629e]=0x11;put(0x5000,0x62a0,0x1111);put(0x5000,0x62a2,0x2222);put(0x5000,0x62a4,0);fn(bus,len(bus),0x1000,0x5000,0x62a0,2,0,C.byref(s),0,null,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.bp,r.returned.carry,r.flags_valid,r.zero_flag)==(0,0x62a4,0x2222,0x1111,1,0x78,0,0x5678,0,1,1),'PUSHsavedBP beforeliveDSlookup');vectors+=1
 bus[0x56cfc]=bus[0x56cfe]=1;put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222)
 for budget in [4003,4002]:
  phase={'initial':True,'polls':0,'reads':0,'writes':0}
  def bounded(ctx,q,value):
   request=q.contents
   if request.operation:phase['writes']+=1;return 1
   phase['reads']+=1
   if phase['initial']:phase['initial']=False;value.contents.value=0xff
   elif request.state.registers.interrupts_enabled==0:phase['polls']+=1;value.contents.value=2
   else:value.contents.value=0xff
   return 1
  callback=Service(bounded);fn(bus,len(bus),0x1000,0x9000,0xe000,0,0,C.byref(s),budget,callback,None,C.byref(r));require(phase['polls']==4001 and phase['writes']==1 and r.reads==budget and r.transfers==budget+1,'Sharpserialized4003INbound')
  if budget==4003:require((r.status,r.next_segment,r.next_ip,r.current_sp,r.flags_valid,r.zero_flag)==(0,0x2222,0x1111,0xe004,1,1),'4003INcompletesroot')
  else:require((r.status,r.next_segment,r.next_ip,r.current_sp,r.returned.registers.interrupts_enabled)==(3,0x16c9,0x67f0,0xe000,1),'4002budgetstopsbeforefinalINafterSTI')
  vectors+=1
 deps=['tools/validate_gameport_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Native-only invalidbeforeeffects/nulloutput/disabled-noadapter/beforefirstINbudget/missingadapter/OUTfailureafterCLI/MOV-onlyinitializerCFZFandchangedactualSSfarwords/PUSHsavedBP-beforeDSlookup/sharp4003INbound-and4002prefix. Separatefromoriginalcomparison/realdevice-timebase-IRQ/whole420A-403B-core/game-fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
