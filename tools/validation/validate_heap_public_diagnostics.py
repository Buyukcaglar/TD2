"""Native26A8 caller-ownedcount/currentBP-DS/ZF-init/SS-farreturn diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_heap_public import Registers,StateRegisters,Request,Limits,WalkLimits,Result,Service,require

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_heap_public;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,0);r=Result();vectors=0;null=Service();limits=Limits(2,WalkLimits(8,128,8,64,1,1,1,32,8))
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,50,C.byref(s),C.byref(limits)),(bus,len(bus),49,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),50,C.byref(s),C.byref(limits)),(bus,len(bus),50,None,C.byref(limits)),(bus,len(bus),50,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,50,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,50,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(count=4,initialize=False,ss=0x9000,sp=50):
  C.memset(bus,0,len(bus));s.registers.ds=0x2000;s.registers.direction=1;s.bp=0x5678
  for o,v in [(0x6f26,0 if initialize else 0x3000),(0x6f28,0x3000),(0x6f2c,16),(0x6f2e,0),(0x6f30,0x2000),(0x6f34,0xa55a),(0x6f36,0),(0x3000,9),(0x6d2a,0x3001 if initialize else 16),(0x6d2c,0x2000),(0x6d24,0xffff),(0x6d9b,0x2000)]:put(0x2000,o,v)
  for i,v in enumerate([0x1111,0x2222,count]):put(ss,sp+2*i,v)
 def run(calls=2,iterations=128,services=8,cb=null,ss=0x9000,sp=50):
  limits.calls=calls;limits.walk.iterations=iterations;limits.walk.services=services;fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 reset();run(calls=0);require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.returned.bp,r.returned.registers.bx,r.returned.registers.es,r.returned.registers.cx,r.flags_valid)==(3,0x26e5,44,3,48,0x6f26,0x2000,4,0),'Actualprologue/argument/ESDS/beforeheapCALL');vectors+=1
 reset(initialize=True);run(calls=0);require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.returned.registers.ax,r.returned.registers.es)==(3,0x26ba,44,4,5,0x2000),'InitPUSHDS-POPESwritesactualSS/fixedAX5');vectors+=1
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ax,r.returned.registers.dx,r.zero_flag,r.flags_valid,word(0x9000,54))==(0,54,0x2222,0x1111,0x5678,0x3456,0x4567,0x3002,0x2000,0,1,4),'PlainfarRETfourframebytes/countremainscallerowned/SI-DI-BPrestored');vectors+=1
 reset(ss=0x2000);run(ss=0x2000);require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.zero_flag)==(0,0x3002,0x2000,0,1),'HeapZF1successnotbranchedonbypublicwrapper');vectors+=1
 reset(count=0xffff);run();require((r.status,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.direction,r.returned.carry,r.zero_flag)==(0,0,0,1,0,1),'HeapguardbeforeCLD/zero-pairfailure');vectors+=1
 reset(initialize=True);put(0x2000,0x6d2a,0xffff);run();require((r.status,r.calls,r.heap_calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.direction,r.zero_flag,word(0x2000,0x6f26))==(0,1,0,0,0,1,1,0),'InitrequiredZFfailure/noheapCALL/noinitializerstores');vectors+=1
 reset(initialize=True);run(calls=1);require((r.status,r.next_ip,r.calls,word(0x2000,0x6f26),word(0x2000,0x6f28),word(0x2000,0x3002),word(0x2000,0x3004),word(0x2000,0x6f2c),r.returned.registers.cx)==(3,0x26e5,1,0x3002,0x3002,1,0xfffe,0x3006,4),'Initround-even/header1/sentinel/currentDSstores/actualargument');vectors+=1
 reset(initialize=True);put(0x2000,0x6d24,0);run(services=0);require((r.status,r.next_ip,r.services,r.flags_valid)==(3,0x2904,0,0),'SharedservicebudgetbeforeinitDOS');vectors+=1
 reset(initialize=True);put(0x2000,0x6d24,0);run();require((r.status,r.next_ip,r.services,r.flags_valid)==(4,0x2904,0,0),'Missingadapterprefixnotallocationfailure');vectors+=1
 @Service
 def raw_child(context,memory,request,result):
  q=request.contents;result[0]=q.incoming;result.contents.carry=0;at=((q.stack_segment<<4)+q.stack_sp)&0xfffff;memory[at]=0xfe;memory[(at+1)&0xfffff]=0xff;return 1
 reset(initialize=True);put(0x2000,0x6d24,0);run(cb=raw_child);require((r.status,r.next_ip,r.flags_valid)==(1,0xfffe,0),'RawnestedRETafterinstruction/neverfollowed');vectors+=1
 @Service
 def saved_bp(context,memory,request,result):
  result[0]=request.contents.incoming;result.contents.carry=0;put(0x9000,48,0x1357);return 1
 reset(initialize=True);put(0x2000,0x6d24,0);run(calls=1,cb=saved_bp);require((r.status,r.next_ip,r.returned.bp,word(0x9000,48))==(3,0x26e5,48,0x1357),'RootsavedBPbusmutationretainedbeforeepilogue');vectors+=1
 reset(ss=0x2000,sp=0x6f2a);run(calls=0,ss=0x2000,sp=0x6f2a);require((r.status,r.next_ip,word(0x2000,0x6f26),word(0x2000,0x6f28),r.returned.registers.cx)==(3,0x26e5,0x3456,0x5678,4),'ActualSSsavesaliasmetadata beforeCMP');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_heap_public.py','sha256':hashlib.sha256((ROOT/'tools/validate_heap_public.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/actualprologue-initSSwrites/currentDS-ES/requiredinitZF/heapZFnotallocationflag/onecallerownedcount/plainfarRET/actualsavedBP-metadataaliases/budget-adapter-rawRET diagnostics only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, wholecallers/writers/capacity/ownership/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
