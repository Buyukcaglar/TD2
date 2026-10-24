"""Native5FBC branch/order/actual642E-840A/global budgets/DI and far-frame aliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_exit_video import Registers,StateRegisters,Service,BIOSService,Result,require,bios_event,device_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_exit_video;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BIOSService,C.c_void_p,Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null_bios=BIOSService();null_device=Service();trace=[];mode=0;devmode=0;ss=0x9000;sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null_bios,None,null_device,None,2,16412,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null_bios,None,null_device,None,2,16412,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null_bios,None,null_device,None,2,16412,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(flag=1,stack=0x9000,pointer=0xe000,df=0):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.direction=df;trace.clear();bus[0x25e6e]=flag
  for i in range(12):bus[0x25e7c+i]=0x80+i
  put(0x10,0xffff,0x40);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 @BIOSService
 def bios(context,memory,request,result):
  q=request.contents;rr=q.incoming.registers;trace.append(['bios',bios_event(q)]);require(q.vector==0x10 and q.site in [0x6450,0x6457,0x6018],'BIOSidentity');require(rr.ax==(3 if q.site==0x6450 else 7) if q.site!=0x6457 else rr.ax>>8==0xb and rr.bx==0,'LiteralBIOSAX');result[0]=q.incoming
  if mode==1:
   result.contents.registers.ax=0xbeef;result.contents.registers.bx=0x7654;result.contents.registers.cx=0x4567;result.contents.registers.dx=0xabcd;result.contents.registers.si=0x7777;result.contents.registers.di=0x9999;result.contents.registers.ds=0x2200;result.contents.registers.es=0x8888;result.contents.registers.interrupts_enabled=0;result.contents.registers.direction=1;result.contents.carry=1;result.contents.bp=0xc000
  if mode==2:put(sp,0x1357,ss);put(sp+2,0x369c,ss)
  if mode==3 and q.site==0x6457:put(sp-6,0x2468,ss);put(sp-4,0x369c,ss)
  if mode==4:result.contents.carry=2
  return 1
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(['device',device_event(q)]);result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
  if devmode==1 and q.site==0x5ff4:memory[((q.incoming.registers.ds<<4)+0x5e7c+q.incoming.registers.bx)&0xfffff]=0xf0+q.incoming.registers.bx
  if devmode==2 and q.site==0x6013:put(sp-2,0xabcd,ss)
  if devmode==3 and q.site==0x843a:put(sp-12,0x2468,ss);put(sp-10,0x369c,ss)
  if devmode==4 and q.kind==4:return 0
  if q.kind in [3,4]:memory[q.address]=q.value&255
  if q.kind==4:memory[(q.address+1)&0xfffff]=(q.value>>8)&255
  return 1
 def run(calls=2,events=16412,b=bios,d=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),b,None,d,None,calls,events,C.byref(r))
 reset();bus[0xb8000]=bus[0xbffff]=255;run();ports=[e[1] for e in trace if e[0]=='device' and e[1][0]==1];require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.services,r.ports,r.bytes,r.words,r.bus_writes,r.returned.bp,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.es,r.returned.registers.di,r.returned.carry,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,0,16412,1,27,0,16384,16386,0x5678,7,12,0,0x3b8,0xb800,0x4567,0,0) and bus[0xb8000]==bus[0xbffff]==0 and word(0x10,0x40)==0xffff,'Nonzeroflagfullwordpath/actualsavedDI');require([(e[6],e[7]) for e in ports]==[(0x3bf,3),(0x3b8,0x20)]+[(port,value) for i in range(12) for port,value in [(0x3b4,i),(0x3b5,0x80+i)]]+[(0x3b8,0x28)] and trace[-1][0]=='bios' and trace[-1][1][1]==0x6018,'Literal27OUTs/table-values/BIOSlast');vectors+=1
 reset(flag=0);run();require((r.status,r.current_sp,r.calls,r.events,r.services,r.ports,r.bytes,r.words,r.bus_writes,r.returned.registers.ax,r.returned.registers.di,r.returned.registers.es,word(0x10,0x40))==(0,0xe004,2,8008,2,6,8000,0,8009,0xb03,0x4567,0x40,0xffdf),'Zeroactual642E-840Afullframes/POProotDIafterBIOS');vectors+=1
 for flag,site,writes,calls in [(1,0x5fe3,2,0),(0,0x8418,8,2)]:
  reset(flag=flag);run(events=0);require((r.status,r.next_ip,r.bus_writes,r.calls,r.events)==(3,site,writes,calls,0),'Globalfirsteventprefix');vectors+=1
 reset(flag=0);run(calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes)==(3,0x5fc4,0xdffe,0,1),'CALLbudgetafterrootDIpush');vectors+=1
 reset(flag=0);run(calls=1);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes)==(3,0x6431,0xdff8,1,4),'NestedCALLbudgetafter642EzeroargPUSH');vectors+=1
 reset();run(events=26);require((r.status,r.next_ip,r.events,r.words,r.bus_writes,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.direction)==(3,0x600c,26,0,2,0x4000,0,0),'WordREPprefixafterCLD');vectors+=1
 reset();run(events=27);require((r.status,r.next_ip,r.events,r.words,r.bus_writes,r.returned.registers.cx,r.returned.registers.di)==(3,0x600c,27,1,3,0x3fff,2),'Onewordprefix');vectors+=1
 reset();run(events=16410);require((r.status,r.next_ip,r.events,r.words,r.ports,r.bus_writes,r.services)==(3,0x6013,16410,16384,26,16386,0),'WordfillcompletebeforelastOUT');vectors+=1
 reset();run(events=16411);require((r.status,r.next_ip,r.events,r.services,r.returned.registers.ax,r.current_sp)==(3,0x6018,16411,0,7,0xdffe),'LastOUT-beforeBIOS-prefix/noPOPs');vectors+=1
 reset(df=1);run();require((r.status,r.returned.registers.direction)==(0,0),'WordpathCLD');vectors+=1
 reset(flag=0,df=1);run();require((r.status,r.returned.registers.direction)==(0,1),'ZerochildpathnoCLD');vectors+=1
 for flag in [0,1]:
  mode=1;reset(flag=flag);run();require((r.status,r.returned.bp,r.returned.registers.ax,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.es,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xc000,0xbeef,0x7777,0x4567,0x2200,0x8888,1,0,1),'FullBIOSstateexceptactualsavedDI');vectors+=1
 mode=0;devmode=1;reset();run();ports=[e[1] for e in trace if e[0]=='device' and e[1][0]==1 and e[1][6]==0x3b5];require([e[7] for e in ports]==list(range(0xf0,0xfc)),'IndexOUTbeforetablebyte-read');vectors+=1;devmode=0
 devmode=2;reset();run();require((r.status,r.returned.registers.di)==(0,0xabcd),'LateOUTmutatessavedDI-beforeBIOSthenPOP');vectors+=1;devmode=0
 mode=2;reset();run();require((r.status,r.next_segment,r.next_ip)==(0,0x369c,0x1357),'BIOSmutatesrootfarframe');vectors+=1;mode=0
 mode=3;reset(flag=0);run();require((r.status,r.next_segment,r.next_ip,r.current_sp,r.calls,r.services)==(1,0x369c,0x2468,0xdffe,2,2),'Changed642EfarRET/noPOProotDI');vectors+=1;mode=0
 devmode=3;reset(flag=0);run();require((r.status,r.next_segment,r.next_ip,r.calls,r.services)==(1,0x369c,0x2468,2,0),'Changed840AfarRET/noBIOSfollow');vectors+=1;devmode=0
 reset(flag=0,stack=0x2000,pointer=0x5e70);run();require((r.status,r.calls,r.words,r.bytes,bus[0x25e6e])==(0,0,16384,0,0x67),'EntryPUSHDIaliasesbranchbyte-beforeCMP');vectors+=1
 reset(flag=0,stack=0x40,pointer=0x12);run();require((r.status,r.returned.registers.di)==(0,0x4557),'ChildBDAaliasesrootsavedDI');vectors+=1
 reset(stack=0xb800,pointer=0x8000);run();require((r.status,r.returned.registers.di,r.next_segment,r.next_ip)==(0,0,0x2222,0x1111),'LastwordaliasesrootsavedDI');vectors+=1
 reset(stack=0xb800,pointer=0);run();require((r.status,r.next_segment,r.next_ip)==(0,0,0),'Wordfillaliasesrootfarframe');vectors+=1
 for pointer,site in [(3,0x6459),(4,0x6459),(5,0x6459),(9,0x843d),(10,0x843d),(11,0x843d)]:
  reset(flag=0,pointer=pointer);run();require((r.status,r.next_ip)==(5,site),'Zerochildqualificationlevel');vectors+=1
 for flag,site in [(0,0x5fca),(1,0x601b)]:
  reset(flag=flag,pointer=0xffff);run();require((r.status,r.next_ip,r.current_sp)==(5,site,0xffff),'RootpreRETqualificationafterPOPDI');vectors+=1
 reset();run(d=null_device);require((r.status,r.next_ip,r.events,r.bus_writes)==(4,0x5fe3,0,2),'Missingdevice');vectors+=1
 reset();run(b=null_bios);require((r.status,r.next_ip,r.events,r.services,r.bus_writes)==(4,0x6018,16411,0,16386),'MissingBIOSafterfullwordwork');vectors+=1
 mode=4;reset();run();require((r.status,r.next_ip,r.events,r.returned.registers.ax,r.current_sp)==(4,0x6018,16411,7,0xdffe),'InvalidBIOSreturnnotadopted');vectors+=1;mode=0
 devmode=4;reset();run();require((r.status,r.next_ip,r.events,r.words,r.returned.registers.cx,r.returned.registers.di)==(4,0x600c,26,0,0x4000,0),'Rejectedwordbeforeadvance');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_exit_video.py','sha256':hashlib.sha256((ROOT/'tools/validate_exit_video.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/twoalternativepaths/actual642E-840A/fullSS/globalCALL-device-BIOSeventbudgets/27literalOUTs/read-after-indexOUT/CLD-wordfill/BIOSfullstate/livePOPDI/branchbyte-BDA-word-returnframealiases/rawchildRET/child-rootqualification/adapterfailures only. Originalcomparison/staticproofsseparate; no actualROM-controller-hardware/renderer/CPU-A20/caller-storage-writers-lifetime-exclusion/core/CGA/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
