"""Native90E8 actual840A/sharedbudget/BIO Sfarpalettecontext/fullSS/rawreturns."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_video_init import Registers,StateRegisters,Request,Response,Service,BIOSRequest,BIOSService,Result,require,device_event,bios_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_video_init;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BIOSService,C.c_void_p,Service,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null_bios=BIOSService();null_device=Service();trace=[];bios_mode=0;device_mode=0;active_ss=0x9000;active_sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,0x9000,0xe000,state,null_bios,None,null_device,None,1,8016,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null_bios,None,null_device,None,1,8016,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null_bios,None,null_device,None,1,8016,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(ss=0x9000,sp=0xe000,df=0):
  nonlocal active_ss,active_sp
  C.memset(bus,0,len(bus));s.registers.direction=df;trace.clear();active_ss=ss;active_sp=sp
  for sg,start in [(0x2000,0),(0x2100,0xa0)]:
   for i in range(17):bus[(sg<<4)+0x6848+i]=start+i
  put(0x10,0xffff,0x40);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 @BIOSService
 def bios(context,memory,request,result):
  q=request.contents;rr=q.incoming.registers;phase=int(q.site==0x9140);require((q.vector,q.segment,q.stack_segment,q.stack_sp,rr.ax)==(0x10,0x16c9,active_ss,active_sp,0x1002 if phase else 0xd),'ExactBIOSidentities/rootSP');payload=bytes(memory[(((rr.es<<4)+rr.dx+i)&0xfffff)] for i in range(17)).hex() if phase else None;trace.append(['bios',bios_event(q),payload]);result[0]=q.incoming
  if bios_mode==1 and not phase:
   result.contents.registers.ax=0xf123;result.contents.registers.si=0x1357;result.contents.registers.di=0x2468;result.contents.registers.ds=0x2100;result.contents.registers.es=0x9876;result.contents.registers.interrupts_enabled=0;result.contents.registers.direction=1;result.contents.carry=1;result.contents.bp=0xd000
  if bios_mode==1 and phase:
   result.contents.registers.ax=0xbeef;result.contents.registers.bx=0x7654;result.contents.registers.cx=0x4567;result.contents.registers.dx=0xabcd;result.contents.registers.si=0x7777;result.contents.registers.di=0x9999;result.contents.registers.ds=0x2200;result.contents.registers.es=0x8888;result.contents.registers.interrupts_enabled=1;result.contents.registers.direction=0;result.contents.carry=1;result.contents.bp=0xc000
  if bios_mode==2 and not phase:
   for i in range(17):memory[0x26848+i]=0xe0+i
  if bios_mode==3 and phase:put(active_sp,0x1357,active_ss);put(active_sp+2,0x369c,active_ss)
  if bios_mode==4 and not phase:result.contents.carry=2
  if bios_mode==5 and phase:result.contents.carry=2
  return 1
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(['device',device_event(q)]);result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=0xffff
  if device_mode==1 and q.site==0x843a:put(active_sp-6,0x2468,active_ss);put(active_sp-4,0x369c,active_ss)
  if device_mode==2 and q.site==0x8426:put(active_sp-2,0x80ff,active_ss)
  if device_mode==3 and q.site==0x8418:return 0
  if device_mode==4 and q.kind==3:return 0
  if q.kind==3:memory[q.address]=q.value
  return 1
 def run(calls=1,events=8016,b=bios,d=device):fn(bus,len(bus),0x1000,active_ss,active_sp,C.byref(s),b,None,d,None,calls,events,C.byref(r))
 reset();run(events=0);require((r.status,r.next_ip,r.events,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry)==(3,0x90ed,0,0,0,0xa505,0x3ce,1),'FirstOUTprefix/noownSSFNs/CFpreserved');vectors+=1
 reset();run(calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.events,r.ports,r.bus_writes,word(0xdffe,0x9000),r.returned.carry)==(3,0x9114,0xdffe,0,8,8,1,0,1),'FixedzeroargPUSH/beforeactualfarCALL');vectors+=1
 reset();run(events=8);require((r.status,r.next_ip,r.current_sp,r.calls,r.events,r.bus_writes,word(0xdffa,0x9000),word(0xdffc,0x9000),r.returned.bp)==(3,0x8418,0xdff6,1,8,5,0x9119,0x16c9,0xdff8),'Actualchildfarframe-and-twoSSFNs/sharedremainingbudget0');vectors+=1
 reset();run(events=12);require((r.status,r.next_ip,r.events,r.ports,r.bytes,r.bus_writes,r.returned.registers.cx,r.returned.registers.di,r.returned.carry)==(3,0x842f,12,12,0,5,8000,0,0),'Sharedbudget-beforechildREP');vectors+=1
 reset();run(events=13);require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes,r.returned.registers.cx,r.returned.registers.di)==(3,0x842f,13,1,6,7999,1),'Sharedbudget-onebyteprefix');vectors+=1
 reset();run(events=8014);require((r.status,r.next_ip,r.current_sp,r.services,r.ports,r.bytes,r.bus_writes,word(0x10,0x40),r.returned.registers.ax,r.returned.registers.es)==(3,0x9133,0xe000,0,14,8000,8006,0xffdf,0xd,0x40),'Childnormalreturn/ADDSP2/BDAstore-beforemodeINT');vectors+=1
 reset();run(events=8015);require((r.status,r.next_ip,r.events,r.services,r.returned.registers.ax,r.returned.registers.ds,r.returned.registers.es,r.returned.registers.dx)==(3,0x9140,8015,1,0x1002,0x2000,0x2000,0x6848),'ESactualmodeDS/palettefarrequest-prefix');vectors+=1
 reset();bus[0xa0000]=0xff;bus[0xa1f3f]=0xff;run();ports=[e[1] for e in trace if e[0]=='device' and e[1][0]==1];requests=[e for e in trace if e[0]=='bios'];require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.services,r.ports,r.bytes,r.bus_writes,r.returned.bp,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.ds,r.returned.registers.es,r.returned.carry,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,1,8016,2,14,8000,8006,0x5678,0x1002,0x6848,0x2000,0x2000,0,0),'Fullactual840A-2BIOS composition/realfarframes');require([(p[6],p[7]) for p in ports]==[(0x3ce,5),(0x3cf,0),(0x3ce,1),(0x3cf,0),(0x3ce,8),(0x3cf,255),(0x3ce,3),(0x3cf,0),(0x3ce,5),(0x3cf,2),(0x3c4,2),(0x3c5,15),(0x3ce,5),(0x3cf,0)] and [e[1][1] for e in requests]==[0x9133,0x9140] and requests[1][2]==bytes(range(17)).hex() and bus[0xa0000]==0 and bus[0xa1f3f]==0,'Literal14OUTs/orderedBIOS-palette17/rawRAM');vectors+=1
 reset(df=1);bus[0xa0001]=0xff;run();device_events=[e[1] for e in trace if e[0]=='device' and e[1][0]==3];requests=[e for e in trace if e[0]=='bios'];require((r.status,r.returned.registers.direction,device_events[0][9],device_events[1][9],bus[0xa0001])==(0,1,0xa0000,0xaffff,0xff) and all(e[1][5][9]==1 for e in requests),'NoCLD/root-child-echoBIOSDFretained');vectors+=1
 bios_mode=1;reset();run();palette=next(e for e in trace if e[0]=='bios' and e[1][1]==0x9140);require((r.status,r.returned.bp,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.es,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xc000,0xbeef,0x7654,0x4567,0xabcd,0x7777,0x9999,0x2200,0x8888,1,1,0) and palette[1][5][6:8]==[0x2100,0x2100] and palette[2]==bytes(range(0xa0,0xb1)).hex(),'ModeDSfarbuffer-context/lastBIOSfullstateadoption');vectors+=1;bios_mode=0
 bios_mode=2;reset();run();palette=next(e for e in trace if e[0]=='bios' and e[1][1]==0x9140);require((r.status,palette[2])==(0,bytes(range(0xe0,0xf1)).hex()),'Modebusmutation-beforepalette17snapshot');vectors+=1
 reset(ss=0x2000,sp=0x6848);run();require((r.status,r.next_segment,r.next_ip)==(0,0xe3e2,0xe1e0),'Palettebuffer17alsoactualrootfarframe');vectors+=1;bios_mode=0
 bios_mode=3;reset();run();require((r.status,r.next_segment,r.next_ip)==(0,0x369c,0x1357),'Palettecallbackmutatesfarwords-beforeRET');vectors+=1;bios_mode=0
 device_mode=1;reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.services,r.bus_writes)==(1,0xdffe,0x369c,0x2468,1,8014,0,8005),'RawchildfarRET-afterinstruction/noADDSP2-noBDA-BIOS');vectors+=1;device_mode=0
 device_mode=2;reset();run();require((r.status,bus[0xa0000],bus[0xa1f3f],r.returned.registers.ax)==(0,0xff,0xff,0x1002),'ChildargumentrereadaftersetupOUTbusmutation');vectors+=1;device_mode=0
 reset(ss=0xa000,sp=0);run();require((r.status,r.next_segment,r.next_ip)==(0,0,0),'Forwardfillaliasesrootfarframe/childframefits');vectors+=1
 reset(ss=0xa000,sp=0,df=1);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.services)==(1,0xfffe,0,0,0),'Reversefillaliaseschildfarframe/noBIOSfollow');vectors+=1
 reset(ss=0xa000,sp=0x1f48);run();require((r.status,r.returned.registers.di,r.returned.bp,r.next_segment,r.next_ip)==(0,0,0x5678,0x2222,0x1111),'LastfillbytesaliaschildsavedDIthenBIOSecho');vectors+=1
 for sp in [3,4,5]:
  reset(sp=sp);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.services,r.bus_writes)==(5,(sp-6)&65535,0x16c9,0x843d,1,8014,0,8005),'ChildpreRETqualificationpropagated '+str(sp));vectors+=1
 for sp in [0xfffd,0xfffe,0xffff]:
  reset(sp=sp);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.services,r.bus_writes)==(5,sp,0x16c9,0x9142,8016,2,8006),'RootpreRETqualificationafterbothBIOS '+str(sp));vectors+=1
 reset();run(d=null_device);require((r.status,r.next_ip,r.calls,r.events,r.bus_writes)==(4,0x90ed,0,0,0),'MissingdevicefirstOUT');vectors+=1
 reset();run(b=null_bios);require((r.status,r.next_ip,r.services,r.events,r.bus_writes)==(4,0x9133,0,8014,8006),'MissingBIOSafterchild-BDA');vectors+=1
 for mode,site,events,services in [(4,0x9133,8014,0),(5,0x9140,8015,1)]:
  bios_mode=mode;reset();run();require((r.status,r.next_ip,r.events,r.services)==(4,site,events,services),'InvalidBIOSstate-notadopted '+str(mode));vectors+=1
 bios_mode=0;device_mode=3;reset();run();require((r.status,r.next_ip,r.calls,r.events,r.bus_writes)==(4,0x8418,1,8,5),'RejectedchildOUTprefix');vectors+=1
 device_mode=4;reset();run();require((r.status,r.next_ip,r.events,r.bytes,r.returned.registers.cx)==(4,0x842f,12,0,8000),'Rejectedchildbyte-beforeadvance');vectors+=1;device_mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_video_init.py','sha256':hashlib.sha256((ROOT/'tools/validate_video_init.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/literal8setup-6childOUTs/actual840Afarframe-zeroarg-ADDSP2/sharedglobalbudget/BDA0410mask/modeBIOSfullstate-ESactualreturnedDS/palette17snapshot-lastBIOSfullstate/BIOS-device-memorychanges/child-rootSSFNs-aliases/rawchildRET-beforefollow/child-rootpreRETqualification/adapterfailures only. Originalcomparison separate; no actualROM-EGApalette-register-latchhardware/renderer/historicalCPU/caller-domain/writers/storage/lifetime/exclusion/core/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
