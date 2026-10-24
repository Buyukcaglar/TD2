"""Native2852 fullSS/inheritedchild/sharedservicebudget andrawreturn diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_block_request import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_block_request;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x4000,0x5000,0,0),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,sp,state in [(bus,len(bus)-1,12,C.byref(s)),(bus,len(bus),11,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),12,C.byref(s)),(bus,len(bus),12,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,1,32,2,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,12,C.byref(s),null,None,1,32,2,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,12,C.byref(s),null,None,1,32,2,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(mode=1,high=0,cursor=0x6d2a):
  C.memset(bus,0,len(bus))
  for i,v in enumerate([0x1111,0x2222,mode,17,high,0xa55a,0x2000]):put(0x9000,12+2*i,v)
  for k in range(20):put(0x4000,0x6d2a+4*k,16);put(0x4000,0x6d2c+4*k,0x2000+k)
  put(0x4000,0x6d24,0xffff);put(0x4000,0x6d7a,cursor);put(0x4000,0x6d9b,0x2000)
 def run(calls=1,records=32,services=2,cb=null):fn(bus,len(bus),0x1000,0x9000,12,C.byref(s),cb,None,calls,records,services,C.byref(r))
 reset();run(calls=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes)==(3,4,0x286a,0,4),'FirstCALLbudgetafter4saves');vectors+=1
 reset(3,cursor=0x6d2e);run(calls=0);require((r.status,r.current_sp,r.next_ip,r.bus_writes)==(3,2,0x2883,6),'SecondCALLbudgetafterargwrite/PUSHSI');vectors+=1
 reset();run(records=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.records)==(3,2,0x28c5,1,0),'Actualnearframe/inheritedchildprefix');vectors+=1
 reset();run();require((r.status,r.current_sp,r.calls,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.es)==(0,16,1,0,16,0x2000,0x5000),'Capacityshortcut/actualSSrestore/rootRET4');vectors+=1
 reset(high=1);run();require((r.status,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,0,0xffff,0xffff,0),'HighguardfailurepreservesCMPcarry0');vectors+=1
 reset(2);run(services=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx)==(3,4,0x28a9,0,0x4800,2,0xc403),'PreparedALLOC/rawCL/17bitrounding');vectors+=1
 reset(2);run();require(r.status==4 and r.services==0,'MissingALLOCadapter');vectors+=1
 @Service
 def success(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.ax=0x7000;result.contents.carry=0;return 1
 reset(2);run(cb=success);require((r.status,r.services,r.returned.registers.ax,r.returned.carry,bus[0x46d2e]|bus[0x46d2f]<<8,bus[0x46d30]|bus[0x46d31]<<8,bus[0x46d7a]|bus[0x46d7b]<<8)==(0,1,0,0,17,0x7000,0x6d2e),'ActualreturnedALLOCrow/cursorwrites');vectors+=1
 @Service
 def error(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.ax=8;result.contents.carry=1;return 1
 reset(2);run(cb=error);require((r.status,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,1,0xffff,0xffff,1),'ALLOCerror/wordCWD/CF1');vectors+=1
 reset(3,cursor=0x6d2e);run(services=1,cb=error);require((r.status,r.current_sp,r.next_ip,r.services)==(3,4,0x28a9,1),'SharedbudgetafterfailedchildSETBLOCK');vectors+=1
 @Service
 def saved_si(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=1;at=(q.stack_segment<<4)+q.stack_sp+2;memory[at]=0x76;memory[at+1]=0x6d;return 1
 reset(3,cursor=0x6d2e);run(cb=saved_si);require((r.status,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(0,1,0xffff,0xffff,0),'ActualPOPSIchanged/boundaryfailureCF0');vectors+=1
 @Service
 def raw_child(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=0;at=(q.stack_segment<<4)+q.stack_sp;memory[at]=0xfe;memory[at+1]=0xff;return 1
 reset(3,cursor=0x6d2e);run(cb=raw_child);require((r.status,r.current_sp,r.next_ip,r.services)==(1,2,0xfffe,1),'ActualchildnearRETtargetexposedneverfollowed');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_block_request.py','sha256':hashlib.sha256((ROOT/'tools/validate_block_request.py').read_bytes()).hexdigest()}],'limits':'Nativeinterface/root-childbudgets/realSSnearfarframes/CFguard/failure/returnedDOS48metadata/sharedservicebudget/actualPOPSI/rawnearreturn diagnostics only. Syntheticservice omitsrealDOS-INTframes, originalcomparison separate; caller/writers/capacity/core/session/gameplay/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
