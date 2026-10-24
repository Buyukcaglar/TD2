"""Native280E SSframes/actualwrapperZF/metadata/DECZF/POPs diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_block_tail import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_block_tail;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(5,0xb123,0xc456,0xd789,20,0x4567,0x2000,0x4000,0,0),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,sp,state in [(bus,len(bus)-1,36,C.byref(s)),(bus,len(bus),35,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),36,C.byref(s)),(bus,len(bus),36,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,1,1,1,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,36,C.byref(s),null,None,1,1,1,32,1,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,36,C.byref(s),null,None,1,1,1,32,1,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):bus[(sg<<4)+o]=v&255;bus[(sg<<4)+o+1]=(v>>8)&255
 def reset(size=5,si=20):
  C.memset(bus,0,len(bus));s.registers.ax=size;s.registers.si=si;put(0x9000,36,0x1111);put(0x4000,0x6d2a,16);put(0x4000,0x6d2c,0x2000);put(0x4000,0x6d24,0xffff);put(0x4000,0x6d9b,0x2000)
 def run(root=1,far=1,near=1,records=32,services=1,cb=null):fn(bus,len(bus),0x1000,0x9000,36,C.byref(s),cb,None,root,far,near,records,services,C.byref(r))
 reset();run(root=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.bus_writes,r.flags_valid)==(3,32,0x2810,0,2,0),'RootnearCALLbudgetafterDX-CXsaves');vectors+=1
 reset();run(far=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.child_far_calls,r.flags_valid)==(3,16,0x283e,1,0,0),'Actualnearframe/wrapperprefix');vectors+=1
 reset();run(near=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.child_far_calls,r.child_near_calls,r.flags_valid)==(3,4,0x286a,1,1,0,0),'Actualfarframe/parentprefix');vectors+=1
 reset();run(records=0);require((r.status,r.current_sp,r.next_ip,r.child_near_calls,r.flags_valid)==(3,2,0x28c5,1,0),'Actualnestednearframe/leafprefix');vectors+=1
 reset();run();require((r.status,r.current_sp,r.returned.registers.ax,r.returned.registers.si,r.returned.registers.di,r.returned.registers.cx,r.returned.registers.dx,r.returned.carry,r.zero_flag,r.flags_valid)==(0,38,0x4567,21,20,0xc456,0xd789,0,1,1),'DECDXzero/POPAXactualsavedDI/CX-DXrestores');vectors+=1
 reset(si=22);run();require((r.status,r.returned.carry,r.zero_flag,bus[0x20014]|bus[0x20015]<<8)==(0,1,0,0xfffe),'SUBborrowpreservedDEC/wordstore');vectors+=1
 reset(0);run();require((r.status,r.returned.registers.ax,r.returned.registers.si,r.returned.registers.di,r.zero_flag,r.flags_valid)==(0,16,20,0x4567,1,1),'WrapperZF1skipsmetadata/DIpush');vectors+=1
 reset();put(0x4000,0x6d2a,0xffff);run();require((r.status,r.returned.registers.ax,r.zero_flag,r.flags_valid)==(0,0xffff,1,1),'ChildfailureZFpropagated');vectors+=1
 reset();put(0x4000,0x6d24,0);run(services=0);require((r.status,r.next_ip,r.flags_valid)==(3,0x2904,0),'BeforeDOS4A/noadmittedZF');vectors+=1
 @Service
 def raw(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=0;at=(q.stack_segment<<4)+q.stack_sp;memory[at]=0xfe;memory[at+1]=0xff;return 1
 reset();put(0x4000,0x6d24,0);run(cb=raw);require((r.status,r.next_ip,r.flags_valid)==(1,0xfffe,0),'RawchildnearRET/noadmittedrootZF');vectors+=1
 @Service
 def returned_key(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.cx=0x2000;result.contents.carry=0;return 1
 reset(1,20);s.registers.ds=0xffff;put(0x4000,0x6d2c,0xffff);put(0x4000,0x6d24,0);run(cb=returned_key);require((r.status,r.returned.registers.ds,r.returned.carry,r.zero_flag,r.flags_valid,bus[0xfffff],bus[0],bus[2],bus[3])==(0,0xffff,1,0,1,0xfe,0xff,0xfc,0xff),'NativeDSFFFFwordstorecrosses20bitboundary/actualreturnedsegmentkey');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_block_tail.py','sha256':hashlib.sha256((ROOT/'tools/validate_block_tail.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/fourCALL-recordbudgetlevels/realSSframes/requiredwrapperZF/DECDXZF/SUBCF/orderedmetadata/actualPOPAX-CX-DX/rawchild diagnostics only. Originalcomparison separate; syntheticDOSnoINTframes, wholecaller/writers/capacity/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
