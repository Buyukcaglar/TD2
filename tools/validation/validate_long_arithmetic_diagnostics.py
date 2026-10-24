"""Native-only long arithmetic interfaces, RETF8 and sign/path CF distinctions."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_long_arithmetic import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_long_arithmetic;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,entry,state in [(bus,len(bus)-1,32,0,C.byref(s)),(bus,len(bus),31,0,C.byref(s)),(bus,len(bus),0xffff,0,C.byref(s)),(None,len(bus),32,0,C.byref(s)),(bus,len(bus),32,0,None),(bus,len(bus),32,2,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,32,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),32,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 def args(num,den):
  for k,v in enumerate([0x1111,0x2222,num&65535,num>>16,den&65535,den>>16]):bus[0x90000+32+2*k]=v&255;bus[0x90000+33+2*k]=v>>8
 args(0x80000000,0xffffffff);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.returned.registers.dx,r.returned.registers.ax,r.returned.carry)==(0,44,0x8000,0,0),'INT_MIN/-1 rawwrap/rootRETF8')
 args(0xffffffff,0);fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.returned.registers.ax,r.returned.registers.dx)==(5,26,0x2f5f,0,0),'ZeroDIVprefix after magnitude stores')
 args(0x7fffffff,0x10003);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.steps,r.calls,r.bus_writes)==(3,16,0x2ebb,1,0,8),'BeforeCALL retainsfourargwords')
 args(0x7fffffff,0x10003);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),32,C.byref(r));require((r.status,r.current_sp,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.bus_writes)==(0,44,1,0x7ffe,0,11),'Correctedestimate andactualchild/rootRETF8')
 args(0xffffffff,2);fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(s),32,C.byref(r));require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,0xffff,0xffff,1),'NegativefastremainderCF1')
 args(0xffffffff,0x10000);fn(bus,len(bus),0x1000,0x9000,32,1,C.byref(s),32,C.byref(r));require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,0xffff,0xffff,0),'Samenegativeremainderbits slowCF0')
 record={'schema':1,'result':'pass','vectors':15,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_long_arithmetic.py','sha256':hashlib.sha256((ROOT/'tools/validate_long_arithmetic.py').read_bytes()).hexdigest()}],'limits':'Nineinvalid/noeffects, INT_MIN/-1 rawwrap/rootRETF8, zeroDIVprefix, beforeCALL fourargpool, actualchild/rootRETF8estimatecorrection andnegativefast/slow remainderCF distinction. Nativeonly; no actualexceptiondelivery/caller/lifetime/core/runtime/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':15}))
if __name__=='__main__':main()
