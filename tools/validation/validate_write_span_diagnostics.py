"""Native2600 partialwrite/stackcarry/nonlocalfarreturn/mapperalias/adapter gates."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_write_span import Registers,StateRegisters,Request,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_write_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0x3000,0x3456,0x3004,0x2000,0x4000,0,1),0x8000,0);r=Result();vectors=0;null=Service()
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,0x9000,0xe000,state,1,1,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.return_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,1,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,1,null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(span=4,ctrlz=False,ss=0x9000,sp=0xe000,saved=0x9000):
  C.memset(bus,0,len(bus));s.registers.di=(s.registers.dx+span)&65535;s.bp=0x8000
  for o,v in [(0x7ff8,saved),(0x7ffe,0x1234),(0x8000,0x5678),(0x8002,0x1111),(0x8004,0x2222),(0x8006,4),(0x8008,0x6d00),(saved,0x3456),(saved+2,0x4567)]:put(ss,o,v)
  bus[0x26da8]=0x40 if ctrlz else 0;bus[0x26d00]=0x1a if ctrlz else 0;put(ss,sp,0x3333)
 def run(cb=null,calls=1,services=1,ss=0x9000,sp=0xe000):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),calls,services,cb,None,C.byref(r))
 @Service
 def short(context,memory,request,result):
  q=request.contents;require((q.vector,q.site,q.segment,q.stack_sp,q.incoming.registers.ax,q.incoming.registers.bx,q.incoming.registers.cx,q.incoming.registers.dx)==(0x21,0x260e,0x23a8,0xdffa,0x405a,4,4,0x3000),'ExactDOS40request');result[0]=q.incoming;result.contents.registers.ax=1;result.contents.carry=0;return 1
 @Service
 def zero(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.ax=0;result.contents.carry=0;return 1
 @Service
 def error(context,memory,request,result):result[0]=request.contents.incoming;result.contents.registers.ax=5;result.contents.carry=1;return 1
 reset(span=0);run();require((r.status,r.return_kind,r.return_valid,r.services,r.current_sp,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.di,r.returned.carry)==(0,0,1,0,0xe002,0xa55a,0xb123,0xc456,0x3000,0),'ZeroSPANskipDOS/actualPOPs/nearRET');vectors+=1
 reset();run(short);require((r.status,r.return_kind,r.services,word(0x9000,0x7ffe),r.returned.registers.ax,r.returned.registers.di,r.returned.registers.direction)==(0,0,1,0x1235,0xa55a,0x3000,1),'Shortnonzerowriteaccepted/noretry/AXrestored');vectors+=1
 reset();run(zero);require((r.status,r.return_kind,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,r.calls,word(0x2000,0x6d95))==(0,1,0x8006,0x2222,0x1111,0x5678,0x3456,0x4567,0xffff,0xffff,0,1,0x1c),'ZeroWRITE/nonlocalfarparentexit/mapperORAHclearsCF');vectors+=1
 reset(ctrlz=True);run(zero);require((r.status,r.return_kind,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,word(0x2000,0x6d95))==(0,1,0,0,0x3000,0,0),'CtrlZsharedCLC/bypassmapper');vectors+=1
 reset(ctrlz=True);run(error);require((r.status,r.return_kind,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,word(0x9000,0x7ffe))==(0,1,0,5,0x3000,0,0x1234),'DOSerrorCFoverwrittenbyADDSP8/ctrlZCLC/rawAX5');vectors+=1
 for sp in [0,1,2,3,4,5,0xfffe,0xffff]:
  reset(ctrlz=True,sp=sp);run(error,sp=sp);require((r.status,r.return_kind,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,bus[0x26da0],word(0x2000,0x6d95))==(0,1,1,0xffff,0xffff,0,5,9),'ADDSP8carryAH9 '+str(sp));vectors+=1
 reset();run(services=0);require((r.status,r.current_sp,r.next_ip,r.services,r.bus_writes,r.return_valid)==(3,0xdffa,0x260e,0,3,0),'Servicebudgetafteractualsaves/request');vectors+=1
 reset();run();require((r.status,r.next_ip,r.services,r.return_valid)==(4,0x260e,0,0),'MissingadapternotDOSerror');vectors+=1
 @Service
 def invalid(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=2;return 1
 reset();run(invalid);require((r.status,r.next_ip,r.services,r.return_valid)==(4,0x260e,0,0),'Invalidserviceflagsbeforeadoption');vectors+=1
 reset();run(error,calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.services,r.returned.registers.ax,r.returned.carry,r.return_valid)==(3,0x939,0x9004,0,1,0x1c00,1,0),'Mapperbudgetafteractualsharedpops/nonlocalprefix');vectors+=1
 reset(ss=0x2000,saved=0x6d93);run(error,ss=0x2000);require((r.status,r.next_ip,r.current_sp,r.calls,r.returned.registers.ax,r.returned.carry,r.return_valid)==(1,0x1c,0x6d97,1,0x1c,0,0),'Mappererrorwordaliasesactualnearreturn/afterRETneverfollowed');vectors+=1
 @Service
 def saved_and_return(context,memory,request,result):result[0]=request.contents.incoming;result.contents.carry=0;result.contents.registers.ax=2;put(0x9000,0xdffe,0x2468);put(0x9000,0xe000,0x1357);return 1
 reset();run(saved_and_return);require((r.status,r.return_kind,r.next_ip,r.returned.registers.ax,r.return_valid)==(0,0,0x1357,0x2468,1),'ActualsavedAX/rootnearreturnrereadafterservice');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_write_span.py','sha256':hashlib.sha256((ROOT/'tools/validate_write_span.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/exactDOS40request/shortnonzerowrite/zeroSPAN/zeroWRITE/nonlocalparentfarRET/ADDSP8carryall8entryvalues/DOSCFoverwrite/ctrlZCLC/mapperORAH-CF/errorword-nearreturnalias/actualsavedAX-rootreturn/adapter-budgetgates only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, whole2558/callers/writers/capacity/ownership/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
