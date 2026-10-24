"""Native27D4 ESthreshold/rawheader/mask-overflow/actualretryDX/requiredZF."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_block_align import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh privatepaths');fn=C.CDLL(str(lib)).td2ega_block_align;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,5,0xd789,20,0x4567,0x2000,0x4000,0,0),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,sp,state in [(bus,len(bus)-1,40,C.byref(s)),(bus,len(bus),39,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),40,C.byref(s)),(bus,len(bus),40,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,null,None,8,1,1,1,32,2,128,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,40,C.byref(s),null,None,8,1,1,1,32,2,128,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,40,C.byref(s),null,None,8,1,1,1,32,2,128,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def reset(cx=5,si=20,di=0x4567,key=0x2000,header=0,threshold=0,sp=40,ss=0x9000):
  C.memset(bus,0,len(bus));s.registers.cx=cx;s.registers.si=si;s.registers.di=di;s.registers.ds=key;put(ss,sp,0x1111);put(key,di-2,header);put(0x4000,0x6f36,threshold);put(0x4000,0x6d2a,16);put(0x4000,0x6d2c,key);put(0x4000,0x6d24,0xffff);put(0x4000,0x6d9b,key)
 def run(calls=8,tail=1,far=1,near=1,records=32,services=2,it=128,cb=null,sp=40,ss=0x9000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,calls,tail,far,near,records,services,it,C.byref(r))
 reset();run(it=0);require((r.status,r.current_sp,r.next_ip,r.iterations,r.calls,r.bus_writes,r.returned.registers.cx,r.returned.registers.dx,r.flags_valid)==(3,38,0x27e4,0,0,1,7,0x7fff,0),'BeforeESthreshold/actualsavedCX/header');vectors+=1
 reset(header=3);run(it=0);require(r.returned.registers.cx==3,'OddheaderfullwordSUB-DEC-INCs');vectors+=1
 reset(header=0xffff);run(it=0);require((r.returned.registers.cx,r.returned.carry)==(7,1),'RawoddFFFFheader/wordwrap/preservedborrow');vectors+=1
 reset(threshold=0xffff);run(it=1);require((r.status,r.next_ip,r.iterations,r.returned.registers.dx,r.returned.carry)==(3,0x27ef,1,0x7fff,1),'UnsignedESthreshold/noSHR/beforeattempt');vectors+=1
 reset(sp=0x6f38,ss=0x4000,threshold=0xffff);run(it=1,sp=0x6f38,ss=0x4000);require((r.status,r.next_ip,r.returned.registers.dx,bus[0x46f36]|bus[0x46f37]<<8)==(3,0x27e4,0x3fff,5),'ActualPUSHCXaliasesESthresholdbeforefirstread');vectors+=1
 reset();run(calls=0);require((r.status,r.current_sp,r.next_ip,r.iterations,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.flags_valid)==(3,38,0x27ff,16,0,7,0xffff,0),'Threshold0/actualmaskcomplement/beforeCALL');vectors+=1
 reset();run();require((r.status,r.current_sp,r.calls,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.dx,r.returned.carry,r.zero_flag,r.flags_valid)==(0,42,1,0x4567,5,0xffff,0,0,1),'ChildJNEsuccess/returnscomplementDX/actualCXrestore');vectors+=1
 reset(di=0);run();require((r.status,r.returned.registers.ax,r.zero_flag,r.flags_valid)==(0,0,0,1),'SuccessAX0withZF0/callermustuseZF');vectors+=1
 reset(cx=0xfffd,si=1,threshold=0xffff);run();require((r.status,r.calls,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.dx,r.returned.carry,r.zero_flag)==(0,0,0,0xfffd,0x7fff,0,1),'FirstADDoverflowfailswithoutCALL');vectors+=1
 reset(cx=0,si=0xfff0,threshold=0xffff);run();require((r.status,r.calls,r.returned.registers.dx,r.returned.carry,r.zero_flag)==(0,1,0xfff8,1,0),'SecondADDoverflowshrinksuncomplementedDX');vectors+=1
 reset(key=0xffff);run();require((r.status,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.zero_flag)==(0,1,0,0,1),'ChildZF1/NOTactualreturnedDX/SHRzeroexhaustion');vectors+=1
 @Service
 def changed_mask(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=1;memory[0x90022]=0xff;memory[0x90023]=0xff;return 1
 reset(threshold=0xffff);put(0x4000,0x6d24,0);run(cb=changed_mask);require((r.status,r.calls,r.services,r.returned.registers.ax,r.returned.registers.dx,r.zero_flag)==(0,1,1,0,0,1),'ChildSSsavedDXmutationaffectsactualretry/notcachedmask');vectors+=1
 @Service
 def error(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=1;return 1
 reset(threshold=3);put(0x4000,0x6d24,0);run(services=1,cb=error);require((r.status,r.next_ip,r.calls,r.services,r.flags_valid)==(3,0x2904,2,1,0),'Sharedservicebudgetacrosstwoactualattempts');vectors+=1
 reset(threshold=3);put(0x4000,0x6d24,0);run(calls=1,cb=error);require((r.status,r.next_ip,r.calls,r.services,r.flags_valid)==(3,0x27ff,1,1,0),'RootCALLbudgetafterfailedchild/retrypreparation');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_block_align.py','sha256':hashlib.sha256((ROOT/'tools/validate_block_align.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/ESoverride-SSalias/rawoddheader/overflowbranches/actualreturnedDXretry/sharedbudgets/requiredZF-vsAX/realSSCXrestore diagnostics only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, wholecaller/writers/capacity/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
