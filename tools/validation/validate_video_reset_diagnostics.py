"""Native642E ABI/effect ordering, returned AL, actual frames and diagnostic prefixes."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_video_reset import Registers,StateRegisters,Request,Response,Service,BIOSRequest,BIOSService,Result,require,bios_event,device_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_video_reset;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BIOSService,C.c_void_p,Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null_bios=BIOSService();null_device=Service();trace=[];mode=0;device_mode=0;ss=0x9000;sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null_bios,None,null_device,None,1,8008,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null_bios,None,null_device,None,1,8008,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null_bios,None,null_device,None,1,8008,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(stack=0x9000,pointer=0xe000,df=0):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.direction=df;trace.clear();put(0x10,0xffff,0x40);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 @BIOSService
 def bios(context,memory,request,result):
  q=request.contents;rr=q.incoming.registers;phase=q.site==0x6457;require((q.vector,q.segment,q.stack_segment,q.stack_sp)==(0x10,0x16c9,ss,sp),'BIOScontext');require((rr.ax>>8)==0xb and rr.bx==0 if phase else rr.ax==3,'BIOSidentity');trace.append(['bios',bios_event(q)]);result[0]=q.incoming
  if mode==1 and not phase:
   result.contents.registers.ax=0xf1a7;result.contents.registers.bx=0x8765;result.contents.registers.cx=0xcafe;result.contents.registers.dx=0xbada;result.contents.registers.si=0x1357;result.contents.registers.di=0x2468;result.contents.registers.ds=0x2100;result.contents.registers.es=0x9876;result.contents.registers.interrupts_enabled=0;result.contents.registers.direction=1;result.contents.carry=1;result.contents.bp=0xd000
  if mode==1 and phase:
   result.contents.registers.ax=0xbeef;result.contents.registers.bx=0x7654;result.contents.registers.cx=0x4567;result.contents.registers.dx=0xabcd;result.contents.registers.si=0x7777;result.contents.registers.di=0x9999;result.contents.registers.ds=0x2200;result.contents.registers.es=0x8888;result.contents.registers.interrupts_enabled=1;result.contents.registers.direction=0;result.contents.carry=1;result.contents.bp=0xc000
  if mode==2 and phase:put(sp,0x1357,ss);put(sp+2,0x369c,ss)
  if mode==3 and not phase:result.contents.carry=2
  if mode==4 and phase:result.contents.carry=2
  return 1
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(['device',device_event(q)]);result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
  if device_mode==1 and q.site==0x843a:put(sp-6,0x2468,ss);put(sp-4,0x369c,ss)
  if device_mode==2 and q.site==0x8426:put(sp-2,0x80ff,ss)
  if device_mode==3 and q.kind==3:return 0
  if q.kind==3:memory[q.address]=q.value
  return 1
 def run(calls=1,events=8008,b=bios,d=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),b,None,d,None,calls,events,C.byref(r))
 reset();run(calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.events,r.bus_writes,word(0xdffe,ss),r.returned.carry)==(3,0x6431,0xdffe,0,0,1,0,0),'InitialXOR/PUSH0/preCALL');vectors+=1
 reset();run(events=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.events,r.bus_writes,word(0xdffa,ss),word(0xdffc,ss),r.returned.bp)==(3,0x8418,0xdff6,1,0,5,0x6436,0x16c9,0xdff8),'Actualchildframe/twoSSFNs');vectors+=1
 reset();run(events=4);require((r.status,r.next_ip,r.events,r.ports,r.bytes,r.bus_writes,r.returned.registers.cx,r.returned.registers.di)==(3,0x842f,4,4,0,5,8000,0),'REPprefix');vectors+=1
 reset();run(events=5);require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes,r.returned.registers.cx,r.returned.registers.di)==(3,0x842f,5,1,6,7999,1),'Onebyteprefix');vectors+=1
 reset();run(events=8006);require((r.status,r.next_ip,r.current_sp,r.services,r.ports,r.bytes,r.bus_writes,word(0x10,0x40),r.returned.registers.ax)==(3,0x6450,sp,0,6,8000,8006,0xffdf,3),'BDAstore-beforeBIOS');vectors+=1
 reset();run(events=8007);require((r.status,r.next_ip,r.events,r.services,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.es)==(3,0x6457,8007,1,0xb03,0,0x40),'RetainedAL/BX0/noESreset');vectors+=1
 reset();run();ports=[e[1] for e in trace if e[0]=='device' and e[1][0]==1];require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.services,r.ports,r.bytes,r.bus_writes,r.returned.bp,r.returned.registers.ax,r.returned.carry)==(0,0xe004,0x2222,0x1111,1,8008,2,6,8000,8006,0x5678,0xb03,0) and [(e[6],e[7]) for e in ports]==[(0x3ce,5),(0x3cf,2),(0x3c4,2),(0x3c5,15),(0x3ce,5),(0x3cf,0)],'Literalcompletecomposition');vectors+=1
 reset(df=1);bus[0xa0001]=0xff;run();effects=[e[1] for e in trace if e[0]=='device' and e[1][0]==3];require((r.status,r.returned.registers.direction,effects[0][9],effects[1][9],bus[0xa0001])==(0,1,0xa0000,0xaffff,0xff),'NoCLD/currentDF');vectors+=1
 mode=1;reset();run();second=next(e[1] for e in trace if e[0]=='bios' and e[1][1]==0x6457);require(second[5]==[0xba7,0,0xcafe,0xbada,0x1357,0x2468,0x2100,0x9876,0,1] and second[6:]==[0xd000,1],'AHonly/retainedAL-fullstate-firstBIOS');require((r.returned.bp,r.returned.registers.ax,r.returned.registers.ds,r.returned.registers.es,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0xc000,0xbeef,0x2200,0x8888,1,1,0),'FullsecondBIOSstate');vectors+=1;mode=0
 mode=2;reset();run();require((r.status,r.next_segment,r.next_ip)==(0,0x369c,0x1357),'FinalBIOSfarwordmutations-beforeRET');vectors+=1;mode=0
 device_mode=1;reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.services,r.bus_writes)==(1,0xdffe,0x369c,0x2468,8006,0,8005),'RawchildRETafterinstruction/noBDA-BIOSfollow');vectors+=1;device_mode=0
 device_mode=2;reset();run();require((r.status,bus[0xa0000],bus[0xa1f3f])==(0,255,255),'ChildargumentrereadafterOUTmutation');vectors+=1;device_mode=0
 reset(stack=0xa000,pointer=0);run();require((r.status,r.next_segment,r.next_ip)==(0,0,0),'Forwardfillrootframealias');vectors+=1
 reset(stack=0xa000,pointer=0,df=1);run();require((r.status,r.next_segment,r.next_ip,r.services)==(1,0,0,0),'Reversefillchildframealias');vectors+=1
 reset(stack=0x40,pointer=0x10);put(sp,0xffff,ss);run();require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0xffdf),'BDArootIPalias');vectors+=1
 for pointer in [3,4,5]:
  reset(pointer=pointer);run();require((r.status,r.current_sp,r.next_ip,r.events,r.services,r.bus_writes)==(5,(pointer-6)&65535,0x843d,8006,0,8005),'ChildpreRETqualification');vectors+=1
 for pointer in [0xfffd,0xfffe,0xffff]:
  reset(pointer=pointer);run();require((r.status,r.current_sp,r.next_ip,r.events,r.services,r.bus_writes)==(5,pointer,0x6459,8008,2,8006),'RootpreRETqualification');vectors+=1
 reset();run(d=null_device);require((r.status,r.next_ip,r.calls,r.events,r.bus_writes)==(4,0x8418,1,0,5),'Missingdevice');vectors+=1
 reset();run(b=null_bios);require((r.status,r.next_ip,r.events,r.services,r.bus_writes)==(4,0x6450,8006,0,8006),'MissingBIOS');vectors+=1
 for m,site,events,services in [(3,0x6450,8006,0),(4,0x6457,8007,1)]:
  mode=m;reset();run();require((r.status,r.next_ip,r.events,r.services)==(4,site,events,services),'InvalidBIOSstate');vectors+=1
 mode=0;device_mode=3;reset();run();require((r.status,r.next_ip,r.events,r.bytes,r.returned.registers.cx)==(4,0x842f,4,0,8000),'Rejectedbyte-beforeadvance');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_video_reset.py','sha256':hashlib.sha256((ROOT/'tools/validate_video_reset.py').read_bytes()).hexdigest()}],'limits':'NativeABI/literal6OUTs/actual840Aframe/fullSS-currentDF/sharedbudget/BDA0410/modeBIOSfullstate-AH0BreturnedAL-BX0/lastBIOSfullstate/aliasfarframes/rawchildRET/child-rootqualification/adapterdiagnostics. Originalcomparison separate; no actualROM-devicehardware/renderer/historicalCPU/caller-domain/writers/storage/lifetime/exclusion/core/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
