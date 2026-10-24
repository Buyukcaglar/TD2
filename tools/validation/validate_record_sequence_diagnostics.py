"""Native-only5ADA interface, root budget and actual child-prefix checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_sequence import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_record_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,state in [(bus,len(bus)-1,24,C.byref(s)),(bus,len(bus),23,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),24,C.byref(s)),(bus,len(bus),24,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,6,128,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),6,128,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),6,128,None);require(not any(bus),'Null result no effects')
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),0,128,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,18,0x5ae8,0,3),'Before parentCALL preserves three saves')
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),6,0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,16,0x5b87,1,4),'Actual child-loop prefix/nearframe')
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=v>>8
 for o,v in [(0x5354,8),(0x5356,8),(0x3815,0x8000),(0x39a5,0x8000)]:put(o,v)
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),6,128,C.byref(r));require((r.status,r.current_sp,r.calls,r.iterations,r.returned.carry)==(0,28,4,2,0),'MinimumSP24 actual fourchild returns')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_sequence.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_sequence.py').read_bytes()).hexdigest()}],'limits':'Eight invalid profiles/noeffects, nullresultnoeffects, parentbeforeCALL, actualchildloop/nearframe prefix and minimumSP24 fourchild normalreturn. Native only, not actual1B2Cstate/writer/capacity/lifetime/core/runtime/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
