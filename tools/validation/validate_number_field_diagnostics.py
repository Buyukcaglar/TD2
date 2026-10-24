"""Native20F0 invalid interfaces, raw number and mutable SS result conventions."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_number_field import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');fn=C.CDLL(str(lib)).td2ega_number_field;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,1),0,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,16,C.byref(s)),(bus,len(bus),15,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),16,C.byref(s)),(bus,len(bus),16,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,32,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;previous=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),32,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,previous);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),32,None);require(not any(bus),'Null result');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(payload,output=0x5000,sp=16,ss=0x9000):
  C.memset(bus,0,len(bus))
  for i,b in enumerate(payload):bus[0x44000+i]=b
  for i,v in enumerate([0x1111,0x2222,output,0x4000]):put(ss,sp+2*i,v)
 def run(limit=32,sp=16,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),limit,C.byref(r))
 reset(b'12');run(0);require((r.status,r.current_sp,r.next_ip,r.digits,r.bus_writes)==(3,6,0x213c,0,4),'Before firstdigit after literal saves');vectors+=1
 for payload,ax,dx,cf in [(b'32768',0x8000,0xffff,0),(b'-32768',0x8000,0,1),(b'65536',0,0,0),(b'-65535',1,0,0)]:
  reset(payload);run();require((bus[0x45000]|bus[0x45001]<<8,r.returned.registers.dx,r.returned.carry,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.direction)==(ax,dx,cf,20,0x2222,0x1111,1),'RawwordIMUL '+str(payload));vectors+=1
 reset(b'*');put(0x4000,0x8404,0x5000);put(0x4000,0x5000,0x8000);run();require((bus[0x48404]|bus[0x48405]<<8,bus[0x45000]|bus[0x45001]<<8,r.returned.registers.ax)==(0x5002,0x8000,0x4001),'Star rawword/currentcursor');vectors+=1
 reset(b'0');run();require((bus[0x48402]|bus[0x48403]<<8)==48,'Leading zero conditionalword');vectors+=1
 reset(b'\x80');run();require((r.digits,r.returned.registers.ax,bus[0x45000],bus[0x45001])==(0,0x4000,0,0),'Signedbyte highbit stops beforedigit');vectors+=1
 reset(b'123',output=16,sp=16,ss=0x4000);run(ss=0x4000);require((r.status,r.current_sp,r.next_ip,r.next_segment)==(0,20,123,0x2222),'Outputwrite changesactualfarreturn');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_number_field.py','sha256':hashlib.sha256((ROOT/'tools/validate_number_field.py').read_bytes()).hexdigest()}],'limits':'Native interfaces/budget/signedbyte/wordwrap/IMULCF/starcursor/leadingzero/actualSSfarreturn diagnostics only; originalinstructioncomparison separate, noformatter/format/caller/bounds/core/session/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
