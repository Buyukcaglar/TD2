"""Native-only225E interface, adapter/budget and minimumSP24 diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_seek_handle import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/freshpaths');fn=C.CDLL(str(lib)).td2ega_seek_handle;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,0,0,0,0,0x3000,0,0,0),0,0);r=Result();null=Service();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,24,C.byref(s)),(bus,len(bus),0,C.byref(s)),(bus,len(bus),20,C.byref(s)),(bus,len(bus),23,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),24,C.byref(s)),(bus,len(bus),24,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,3,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalid beforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),null,None,3,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),null,None,3,None);require(not any(bus),'Nullresult beforeeffects');vectors+=1
 bus[0x36da2]=1;fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),null,None,3,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.services,r.bus_writes)==(4,18,0x22cc,0,1),'Missingadapter boundary');vectors+=1
 @Service
 def bad(context,memory,q,out):out[0]=q.contents.incoming;out.contents.carry=2;return 1
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),bad,None,3,C.byref(r));require(r.status==4 and r.bus_writes==1 and r.services==0,'Invalidreturnedflag');vectors+=1
 @Service
 def error(context,memory,q,out):out[0]=q.contents.incoming;out.contents.registers.ax=1;out.contents.carry=1;return 1
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),error,None,3,C.byref(r));require((r.status,r.current_sp,r.services,r.error_calls,r.bus_writes)==(0,28,1,1,4) and r.returned.registers.ax==65535 and r.returned.registers.dx==65535,'MinimumSP24 mapper16');vectors+=1
 fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),null,None,0,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.services,r.bus_writes)==(3,18,0x22cc,0,1),'BeforeINT prefix');vectors+=1
 bus[0x36da2]=0;fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),null,None,0,C.byref(r));require((r.status,r.services,r.error_calls,r.returned.registers.ax)==(0,0,1,65535),'Invalidhandle bypasses servicebudget/adapter');vectors+=1
 @Service
 def success(context,memory,q,out):out[0]=q.contents.incoming;out.contents.registers.ax=0x1234;out.contents.registers.dx=0x5678;out.contents.carry=0;return 1
 bus[0x36da2]=1;bus[0x36da4]=255;fn(bus,len(bus),0x1000,0x9000,24,C.byref(s),success,None,3,C.byref(r));require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,bus[0x36da4])==(0,28,0x1234,0x5678,0,0xfd),'SuccesspreservesAXDX/clearsbit2');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_seek_handle.py','sha256':hashlib.sha256((ROOT/'tools/validate_seek_handle.py').read_bytes()).hexdigest()}],'limits':'Teninvalid/noeffects/nullresult/missing-badadapter/minimumSP24mapper/beforeINT/invalidindexbypass/successAXDX preservation checks. Nativeonly, noactualDOS/file/IRQ/caller/lifetime/core/resource/device/session/gameplay/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
