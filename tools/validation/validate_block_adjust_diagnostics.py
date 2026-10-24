"""Native28C0 invalid/service/scan/rounding/metadata/nearframe diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_block_adjust import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_block_adjust;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0,0,1,0,0x6d2a,0x4000,0x5000,0,0),0xd000,0);r=Result();vectors=0;null=Service()
 for memory,count,sp,state in [(bus,len(bus)-1,0,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),0,C.byref(s)),(bus,len(bus),0,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;previous=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0,C.byref(s),null,None,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,previous);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0,C.byref(s),null,None,32,1,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(sp=0,ss=0x9000):
  C.memset(bus,0,len(bus));put(0x4000,0x6d2a,16);put(0x4000,0x6d2c,0x2000);put(0x4000,0x6d24,0xffff);put(0x4000,0x6d9b,0x2000);put(ss,0xd00e,0x2000);put(ss,sp,0x1111)
 def run(records=32,services=1,cb=null,sp=0,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,records,services,C.byref(r))
 reset();run(records=0);require((r.status,r.next_ip,r.records,r.bus_writes,r.returned.registers.cx,r.returned.registers.si)==(3,0x28c5,0,0,0x2000,0x6d2a),'InheritedBP/readargbeforescanprefix');vectors+=1
 reset();run();require((r.status,r.current_sp,r.records,r.services,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,2,1,0,1,16,0x2000,0),'Capacityshortcut/metadataexchangewithoutservice');vectors+=1
 reset();put(0x4000,0x6d2c,0);run();require((r.status,r.records,r.services,r.returned.carry,r.returned.registers.si)==(0,20,0,1,0x6d7a),'Twentyrecordscan/failedmatchboundary');vectors+=1
 reset();put(0x4000,0x6d2a,0xffff);run();require((r.status,r.returned.registers.bx,r.returned.registers.dx,r.returned.carry,r.bus_writes)==(0,0,1,1,0),'SizeadditioncarrybeforeDXcommit');vectors+=1
 reset();put(0x4000,0x6d24,0);run(services=0);require((r.status,r.next_ip,r.services,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.es)==(3,0x2904,0,0x4a00,2,0x2000),'PreparedDOS4AbeforeINT');vectors+=1
 reset();put(0x4000,0x6d24,0);run();require((r.status,r.services,r.bus_writes)==(4,0,0),'Missingadapter');vectors+=1
 @Service
 def fail(context,memory,request,result):return 0
 reset();put(0x4000,0x6d24,0);run(cb=fail);require(r.status==4 and r.services==0,'Adapterfailure');vectors+=1
 @Service
 def invalid(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=2;return 1
 reset();put(0x4000,0x6d24,0);run(cb=invalid);require(r.status==4 and r.services==0,'Invalidreturnedflags');vectors+=1
 requests=[]
 @Service
 def success(context,memory,request,result):
  q=request.contents;requests.append((q.vector,q.site,q.incoming.registers.ax,q.incoming.registers.bx,q.incoming.registers.es));result[0]=q.incoming;result.contents.carry=0;return 1
 reset();put(0x4000,0x6d24,0);put(0x4000,0x6d2a,0xfffe);run(cb=success);require(requests==[(0x21,0x2904,0x4a00,4096,0x2000)] and (r.status,r.services,r.bus_writes,r.returned.registers.ax)==(0,1,2,0xfffe),'CarryawareceilFFFF/actualmetadata');vectors+=1
 @Service
 def moved(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.si=0x6d20;result.contents.registers.dx=0xcafe;result.contents.carry=0;return 1
 reset();put(0x4000,0x6d24,0);put(0x4000,0x6d20,0x1234);run(cb=moved);require((r.status,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,1,0x1234,0x2000,1),'SuccessfulDOSCFoverwrittenbyactualreturnedSI-DICMP');vectors+=1
 reset(0x6d2a,0x4000);run(sp=0x6d2a,ss=0x4000);require((r.status,r.current_sp,r.next_ip)==(0,0x6d2c,0x1112),'Metadataexchangechangesactualnearreturn');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_block_adjust.py','sha256':hashlib.sha256((ROOT/'tools/validate_block_adjust.py').read_bytes()).hexdigest()}],'limits':'NativeinheritedBP/invalid/budgets/adapterfailure/twentyrows/sizecarry/17bitrounding/returnedSICF/metadata-nearframe diagnostics only. SyntheticDOSrequest notactualDOS, originalcomparison separate; allwriters/domain/caller/core/session/gameplay/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
