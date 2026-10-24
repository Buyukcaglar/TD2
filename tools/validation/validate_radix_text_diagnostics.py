"""Native-only radix interface, zero-DIV and nonprogress profiles."""
import argparse,ctypes as C,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_radix_text import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_radix_text;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,entry,state in [(bus,len(bus)-1,32,0,C.byref(s)),(bus,len(bus),31,0,C.byref(s)),(bus,len(bus),0xffff,0,C.byref(s)),(None,len(bus),32,0,C.byref(s)),(bus,len(bus),32,0,None),(bus,len(bus),32,2,C.byref(s))]:
  fn(memory,count,0x1000,0x9000,sp,entry,state,4,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),4,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 def args(value,radix):
  for index,v in enumerate([0x1111,0x2222,value,0x1200,radix]):bus[0x90000+32+2*index]=v&255;bus[0x90000+33+2*index]=v>>8
 args(0,0);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),4,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes)==(5,24,0x2be4,1,5),'Zero DIV prefix before exception')
 args(1,1);fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),3,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes)==(3,24,0x2bda,3,8),'Radix1 nonprogress prefix')
 args(0xffff,10);s.registers.direction=1;fn(bus,len(bus),0x1000,0x9000,32,0,C.byref(s),80,C.byref(r));require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.direction)==(0,36,0x1200,0) and bytes(bus[0x41200:0x41203])==b'-1\0','MinimumSP32 decimal signed word/CLD')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_radix_text.py','sha256':hashlib.sha256((ROOT/'tools/validate_radix_text.py').read_bytes()).hexdigest()}],'limits':'Nine invalid profiles before bus effects, zeroDIV prefix, radix1 nonprogress prefix and minimumSP32 signed-decimal/CLD. Native only; no actual exception delivery/buffercapacity/caller/core/runtime/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
