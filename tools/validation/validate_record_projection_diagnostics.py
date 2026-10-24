"""Native0201 invalid interfaces, do-once loops, partial stores and raw frames."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_projection import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');fn=C.CDLL(str(lib)).td2ega_record_projection;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x4000,0x5000,0,1),0,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,0,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),0,C.byref(s)),(bus,len(bus),0,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,32,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;previous=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0,C.byref(s),32,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,previous);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0,C.byref(s),32,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v):bus[0x40000+o]=v&255;bus[0x40000+o+1]=(v>>8)&255
 def reset(sp=0,ss=0x9000):
  C.memset(bus,0,len(bus));bus[(ss<<4)+sp]=0x11;bus[(ss<<4)+sp+1]=0x11;bus[(ss<<4)+sp+2]=0x22;bus[(ss<<4)+sp+3]=0x22
 def run(limit=32,sp=0,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),limit,C.byref(r))
 reset();run(0);require((r.status,r.current_sp,r.next_ip,r.records,r.bus_writes,r.returned.registers.es,r.returned.registers.direction)==(3,0,0x279,0,35,0x4000,0),'InitialREPstores/ESDS/CLD before firstrecord');vectors+=1
 reset();run(1);require((r.status,r.next_ip,r.records,r.returned.registers.si)==(3,0x2b4,1,0),'Zero firstcount do-once then secondprefix');vectors+=1
 reset();run(2);require((r.status,r.current_sp,r.records,r.next_segment,r.next_ip,r.returned.registers.dx,r.returned.carry)==(0,4,2,0x2222,0x1111,0xfffe,1),'Bothzerocountsdo-once/realRET4/finalSHLCF');vectors+=1
 reset();put(0x3813,0x1111);put(0x3815,1);put(0x3819,0xa55a);put(0x39a3,0x2222);put(0x39a5,1);put(0x39a9,0x5aa5);put(0x742,0xa55a);put(0x74a,0x5aa5);run(2);require((r.status,r.records,r.bus_writes,r.returned.registers.di,r.returned.bp)==(0,2,48,16,0x2222),'Twoacceptedrecords/sharedDI/BPclobber');require((bus[0x40742]|bus[0x40743]<<8,bus[0x4074a]|bus[0x4074b]<<8)==(0xa55a,0x5aa5),'Sixbytewrites preservefourthword');vectors+=1
 reset(0x1308,0x4000);run(2,0x1308,0x4000);require((r.status,r.current_sp,r.next_segment,r.next_ip)==(0,0x130c,0,0),'REPzeroesactualSSfarframe');vectors+=1
 reset();put(0x5354,0xffff);run(32);require((r.status,r.next_ip,r.records,r.returned.registers.si)==(3,0x279,32,256),'Unalignedhighbound/budget notcapacity');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_projection.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_projection.py').read_bytes()).hexdigest()}],'limits':'Nativeinterface/initialREP/ESDS-CLD/digit-independentrecordbudget/do-oncezerocounts/sharedDI/partialstores/BPclobber/rawfarframe/unalignedbound diagnostics only; originalinstructioncomparison separate. No capacity/caller/writers/core/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
