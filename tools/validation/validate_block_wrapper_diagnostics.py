"""Native2830 actualDSswitch/SSargs/restores andrequiredZF discriminator checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_block_wrapper import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_block_wrapper;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(5,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,0),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,sp,state in [(bus,len(bus)-1,30,C.byref(s)),(bus,len(bus),29,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),30,C.byref(s)),(bus,len(bus),30,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,1,1,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),null,None,1,1,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,30,C.byref(s),null,None,1,1,32,1,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(size=5,sp=30,ss=0x9000):
  C.memset(bus,0,len(bus));s.registers.ax=size;put(ss,sp,0x1111);put(0x4000,0x6d2a,16);put(0x4000,0x6d2c,0x2000);put(0x4000,0x6d24,0xffff);put(0x4000,0x6d9b,0x2000)
 def run(outer=1,inner=1,records=32,services=1,cb=null,sp=30,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,outer,inner,records,services,C.byref(r))
 reset();run(outer=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes,r.returned.registers.ds,r.returned.registers.ax,r.returned.registers.dx,r.flags_valid)==(3,16,0x283e,0,8,0x4000,1,0,0),'DSswitch/fiveargs/beforefarCALL');vectors+=1
 reset();run(inner=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.child_calls,r.flags_valid)==(3,4,0x286a,1,0,0),'Actualouterfarframe/parentprologue');vectors+=1
 reset();run(records=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.child_calls,r.flags_valid)==(3,2,0x28c5,1,1,0),'Actualnestednearframe/prefixZFnotvalid');vectors+=1
 reset();run();require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.ds,r.returned.registers.bx,r.returned.carry,r.zero_flag,r.flags_valid)==(0,32,16,5,0x2000,0xb123,0,0,1),'SavedAXtoDX/DS-BXrestores/requiredZF0');vectors+=1
 reset(0);run();require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.zero_flag,r.flags_valid)==(0,16,0,1,1),'SuccessfulchildbutrestoredDX0givesZF1');vectors+=1
 reset();put(0x4000,0x6d2a,0xffff);run();require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.zero_flag)==(0,0xffff,5,0,1),'ChildfailureZF1survivesPOPDXnonzero/ORskipped');vectors+=1
 reset();put(0x4000,0x6d24,0);run(services=0);require((r.status,r.next_ip,r.services,r.flags_valid)==(3,0x2904,0,0),'BeforeDOS4Aprefix/ZFunadmitted');vectors+=1
 reset();put(0x4000,0x6d24,0);run();require((r.status,r.services,r.flags_valid)==(4,0,0),'Missingadapter/ZFunadmitted');vectors+=1
 @Service
 def changed_save(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=0;memory[0x9001a]=0;memory[0x9001b]=0;return 1
 reset();put(0x4000,0x6d24,0);run(cb=changed_save);require((r.status,r.returned.registers.dx,r.zero_flag,r.flags_valid)==(0,0,1,1),'ServicechangesactualsavedAXbeforePOPDX/ZF');vectors+=1
 @Service
 def raw_child(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=0;at=(q.stack_segment<<4)+q.stack_sp;memory[at]=0xfe;memory[at+1]=0xff;return 1
 reset();put(0x4000,0x6d24,0);run(cb=raw_child);require((r.status,r.next_ip,r.flags_valid)==(1,0xfffe,0),'RawchildnearRET/ZFunadmitted');vectors+=1
 reset(sp=0x6d46,ss=0x4000);run(sp=0x6d46,ss=0x4000);require((r.status,r.current_sp,r.next_ip,r.flags_valid)==(4,0x6d2a,0x2904,0),'ActualSSframesoverwritefirstrowkey/selectlaterrow/DOSadapterboundary');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_block_wrapper.py','sha256':hashlib.sha256((ROOT/'tools/validate_block_wrapper.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/realSSframes-DSswitch/fiveargs/restores/requirednormalZF/discriminator/actualsavedAXalias/diagnosticZFnotvalid only. Fulloriginalcomparison separate; syntheticDOSnoINTframes, wholecaller/writers/capacity/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
