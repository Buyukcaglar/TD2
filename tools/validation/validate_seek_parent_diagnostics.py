"""Native-only2AD8 interface/root-childbudgets/minimumSP48/ignoredthirdresult."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_seek_parent import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/freshpaths');fn=C.CDLL(str(lib)).td2ega_seek_parent;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null=Service();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,48,C.byref(s)),(bus,len(bus),47,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),48,C.byref(s)),(bus,len(bus),48,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,3,3,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),null,None,3,3,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),null,None,3,3,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),null,None,0,3,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,28,0x2aeb,0,6),'BeforefarCALL poolretained');vectors+=1
 bus[0x36da2]=1;fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),null,None,3,0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.calls,r.services,r.bus_writes)==(3,18,0x22cc,1,0,9),'ActualchildbeforeINT');vectors+=1
 bus[0x36da2]=0;fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),null,None,3,3,C.byref(r));require((r.status,r.current_sp,r.calls,r.services,r.error_calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx)==(0,52,1,0,1,14,65535,65535),'MinimumSP48 earlysentinel/actualmapper16');vectors+=1
 counter=[0]
 @Service
 def success(context,memory,q,out):counter[0]+=1;out[0]=q.contents.incoming;out.contents.registers.ax=counter[0]*0x1111;out.contents.registers.dx=0;out.contents.carry=0;return 1
 bus[0x36da2]=1;fn(bus,len(bus),0x1000,0x9000,48,C.byref(s),success,None,3,3,C.byref(r));require((r.status,r.current_sp,r.calls,r.services,r.error_calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,52,3,3,0,0x2222,0,0),'Thirdresultignored/secondSSresultreturned');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_seek_parent.py','sha256':hashlib.sha256((ROOT/'tools/validate_seek_parent.py').read_bytes()).hexdigest()}],'limits':'Eightinvalid/noeffects/nullresult/rootbeforeCALLpool/actualchildbeforeINT/minimumSP48mapper/thirdresultignored checks. Nativeonly, notallcaller/writer/lifetime/IRQ/core/actualDOS/resource/device/session/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
