"""Native-only C838 actual minimum stack, zero scratch offset and DEC guard."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_member_reorder import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_member_reorder;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0,0,0),0,0);r=Result()
 for memory,count,sp,state in [(bus,len(bus)-1,54,C.byref(s)),(bus,len(bus),53,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),54,C.byref(s)),(bus,len(bus),54,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,80,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,54,C.byref(s),80,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,54,C.byref(s),80,None);require(not any(bus),'Null result no effects')
 def put(at,v):bus[at]=v&255;bus[at+1]=v>>8
 def setup(count,mask):
  for k,v in enumerate([0x1111,0x2222,0,0x3000,0,0x6000]):put(0x90000+54+2*k,v)
  put(0x30004,count);table=(4*count+6)&65535;delta=0x50000-(0x30000+((8*count+6)&65535));put(0x30000+table,delta&65535);put(0x30000+((table+2)&65535),(delta>>16)&65535);put(0x50000,1);put(0x50002,1);bus[0x5000e]=mask<<4;bus[0x5000f]=0;bus[0x50010]=0x6d
 setup(1,1);fn(bus,len(bus),0x1000,0x9000,54,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.steps,r.bus_writes)==(3,26,0xc856,0,6),'Before memberprefix/real locals and saves')
 setup(1,1);s.registers.direction=1;fn(bus,len(bus),0x1000,0x9000,54,C.byref(s),80,C.byref(r));require((r.status,r.current_sp,r.calls,r.steps,r.byte_transfers,r.returned.registers.direction)==(0,58,1,7,2,1) and bus[0x60000]==0x6d,'MinimumSP54/actualzerooffsetscratch/DFpreserved')
 setup(0x8000,0);fn(bus,len(bus),0x1000,0x9000,54,C.byref(s),80,C.byref(r));require(r.status==0 and r.calls==1 and bus[0x90032]==0xff and bus[0x90033]==0x7f,'DEC8000new7FFF but signedOF guard exits')
 record={'schema':1,'result':'pass','vectors':12,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_member_reorder.py','sha256':hashlib.sha256((ROOT/'tools/validate_member_reorder.py').read_bytes()).hexdigest()}],'limits':'Eight invalid profiles/noeffects, nullresult, actual memberprefix, minSP54zerooffsetscratch/incomingDF1 and DEC8000signedOFguard. Native only; no actualallocator/packedproducer/fileformat/capacity/lifetime/core/device/session/gameplay/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':12}))
if __name__=='__main__':main()
