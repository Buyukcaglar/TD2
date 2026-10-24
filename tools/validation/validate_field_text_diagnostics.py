"""Native0432:0006 interface/budgets/actualfarframes/trim andspace behavior."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_field_text import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');fn=C.CDLL(str(lib)).td2ega_field_text;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0x3456,0,0x4000,0x5000,0,0),0x5678,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,30,C.byref(s)),(bus,len(bus),29,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),30,C.byref(s)),(bus,len(bus),30,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,1,128,128,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;previous=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),1,128,128,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,previous);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),1,128,128,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(payload=b'ABC',dest=0x4000,ss=0x9000):
  C.memset(bus,0,len(bus))
  for i,b in enumerate(payload):bus[0x45000+i]=b
  for i,v in enumerate([0x1111,0x2222,dest,0x5000]):put(ss,30+2*i,v)
 def run(call=1,child=128,it=128,ss=0x9000):fn(bus,len(bus),0x1000,ss,30,C.byref(s),call,child,it,C.byref(r))
 reset();run(call=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,20,0x13,0,4),'BeforefarCALLafterargumentpushes');vectors+=1
 reset();run(child=0);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.child_operations,r.bus_writes)==(3,14,0x23a8,0x296b,1,0,7),'Childscanprefix/actualfarframe/savedBP');vectors+=1
 reset();run(it=0);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.iterations)==(3,24,0x1432,0x2e,0),'Parenttrimprefixafteractualchildreturn');vectors+=1
 reset(b' '*18);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.si,r.returned.carry)==(0,34,0x2222,0x1111,0x3456,0) and bytes(bus[0x44000:0x44013])==b'_'+b'\0'*18,'Trim17..1preservesfirstspaceforunderscore');vectors+=1
 reset(b' A B  ');run();require(bytes(bus[0x44000:0x44007])==b'_A_B__\0','Scalarspaces/trimonfixedoffset17');vectors+=1
 reset(b'ABC',dest=30,ss=0x4000);run(ss=0x4000);require((r.status,r.current_sp,r.next_segment,r.next_ip)==(0,34,0x0043,0x4241),'Copychangesactualfarrootwords');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_field_text.py','sha256':hashlib.sha256((ROOT/'tools/validate_field_text.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/threebudgetclasses/actualfarframe/minSP30/trim17..1/spaceconversion/actualSSrawrootreturn diagnostics only; originalfullbuscomparison separate. No capacity/NUL/DFvalidity/caller/writers/core/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
