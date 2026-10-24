"""NativeEGA5F64 BIOSstate/tableordering/CLDwordfill/BDA-and-SSaliases/prefixes."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_fallback_mode import Registers,StateRegisters,Request,Response,Service,BIOSRequest,BIOSService,Result,require,device_event,bios_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_fallback_mode;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),BIOSService,C.c_void_p,Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null_bios=BIOSService();null_device=Service();trace=[];bios_mode=0;device_mode=0;active_ss=0x9000;active_sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,0x9000,0xe000,state,null_bios,None,null_device,None,16412,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null_bios,None,null_device,None,16412,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null_bios,None,null_device,None,16412,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(ss=0x9000,sp=0xe000):
  nonlocal active_ss,active_sp
  C.memset(bus,0,len(bus));s.registers.direction=1;trace.clear();active_ss=ss;active_sp=sp
  for sg,start in [(0x2000,0x10),(0x2100,0xa0)]:
   for i in range(12):bus[(sg<<4)+0x5e70+i]=start+i
  put(0x10,0xffff,0x40);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 @BIOSService
 def bios(context,memory,request,result):
  q=request.contents;trace.append(['bios',bios_event(q)]);require((q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,q.incoming.registers.ax,q.incoming.registers.es,q.incoming.carry)==(0x10,0x5f81,0x16c9,active_ss,(active_sp-2)&65535,4,0x40,0),'ExactBIOSmode0004request');result[0]=q.incoming
  if bios_mode==1:
   result.contents.registers.ax=0xf123;result.contents.registers.si=0x1357;result.contents.registers.di=0x2468;result.contents.registers.ds=0x2100;result.contents.registers.es=0x9876;result.contents.registers.interrupts_enabled=0;result.contents.registers.direction=1;result.contents.carry=1;result.contents.bp=0xd000
  if bios_mode==2:put(active_sp-2,0x1357,active_ss)
  if bios_mode==3:result.contents.carry=2
  return int(bios_mode!=4)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(['device',device_event(q)]);result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=0xffff
  if device_mode==3 and q.site==0x5f88:return 0
  if device_mode==4 and q.kind==4:return 0
  if device_mode==1 and q.site==0x5f99:memory[(((q.incoming.registers.ds<<4)+q.incoming.registers.bx+0x5e70)&0xfffff)]=0xee
  if device_mode==2 and q.site==0x5fb8:
   for o,v in [(active_sp-2,0xabcd),(active_sp,0x1357),(active_sp+2,0x369c)]:put(o,v,active_ss)
  if q.kind==4:memory[q.address]=q.value&255;memory[(q.address+1)&0xfffff]=(q.value>>8)&255
  return 1
 def run(limit=16412,b=bios,d=device):fn(bus,len(bus),0x1000,active_ss,active_sp,C.byref(s),b,None,d,None,limit,C.byref(r))
 reset();run(limit=0);require((r.status,r.current_sp,r.next_ip,r.events,r.services,r.bus_writes,word(0x10,0x40),bus[0x25e6e],r.returned.registers.ax,r.returned.registers.es,r.returned.carry)==(3,0xdffe,0x5f81,0,0,3,0xffef,1,4,0x40,0),'Initialflag-BDAstore/BIOSprefix/exactAX4');vectors+=1
 for limit,ip in [(1,0x5f88),(2,0x5f8e),(3,0x5f99),(4,0x5f9f),(26,0x5f9f)]:
  reset();run(limit);require((r.status,r.next_ip,r.events,r.services,r.ports,r.words)==(3,ip,limit,1,limit-1,0),'BIOS-OUT-tableprefix '+str(limit));vectors+=1
 reset();run(limit=27);require((r.status,r.next_ip,r.events,r.ports,r.words,r.returned.registers.direction,r.returned.registers.es,r.returned.registers.di,r.returned.registers.cx,r.returned.registers.ax)==(3,0x5fb1,27,26,0,0,0xb800,0,0x4000,0),'CLDafterBIOS/tableloop-beforefirstword');vectors+=1
 reset();bus[0xb8000]=0xff;bus[0xb8001]=0xff;run(limit=28);require((r.status,r.words,r.bus_writes,r.returned.registers.di,r.returned.registers.cx,bus[0xb8000],bus[0xb8001])==(3,1,4,2,0x3fff,0,0),'Onewordeffect/littleendian-twoCPUbytes');vectors+=1
 reset();run(limit=16411);require((r.status,r.next_ip,r.events,r.services,r.ports,r.words,r.bus_writes,r.returned.registers.di,r.returned.registers.cx,r.returned.registers.ax,r.returned.registers.dx)==(3,0x5fb8,16411,1,26,16384,16387,0x8000,0,0x8a,0x3b8),'Completeclear-beforefinalOUT/noinventedcleanup');vectors+=1
 reset();bus[0xbffff]=0xff;bus[0xc0000]=0xa5;run();ports=[e[1] for e in trace if e[0]=='device' and e[1][0]==1];require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.services,r.ports,r.words,r.bus_writes,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.es,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,16412,1,27,16384,16387,0x5678,0x3456,0x4567,0x2000,0xb800,0x8a,12,0,0x3b8,0,1,0),'FullBIOS-ports-wordfill-SSFNs/CLD/sourceoutputs');require([(p[6],p[7]) for p in ports[:2]]==[(0x3bf,3),(0x3b8,2)] and [(p[6],p[7]) for p in ports[2:26]]==[v for i in range(12) for v in [(0x3b4,i),(0x3b5,0x10+i)]] and (ports[-1][6],ports[-1][7])==(0x3b8,0x8a) and bus[0xbffff]==0 and bus[0xc0000]==0xa5,'Literal27ports/12indices/32KiBendpoint');vectors+=1
 bios_mode=1;reset();run();ports=[e[1] for e in trace if e[0]=='device' and e[1][4]==active_ss and e[1][1]==0x5f9f];require((r.status,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xd000,0x1357,0x4567,0x2100,0,0) and [p[7] for p in ports]==list(range(0xa0,0xac)),'FullBIOSreturnedBP-DS-SI-IFDF/entryDIsave');vectors+=1;bios_mode=0
 device_mode=1;reset();run();ports=[e[1] for e in trace if e[0]=='device' and e[1][1]==0x5f9f];require((r.status,[p[7] for p in ports])==(0,[0xee]*12),'Tablebyte-rereadafterindexOUT/nomergedcachedtable');vectors+=1;device_mode=0
 bios_mode=2;reset();run();require((r.status,r.returned.registers.di)==(0,0x1357),'BIOSmutatesactualsavedDI');vectors+=1;bios_mode=0
 reset(ss=0xb800,sp=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.di)==(0,4,0,0,0x4567),'Wordclearaliasesfarframe');vectors+=1
 reset(ss=0xb800,sp=0x8000);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.di)==(0,0x8004,0x2222,0x1111,0),'LastwordclearaliasesactualsavedDI7FFE');vectors+=1
 for sp,di in [(0x5e6f,0x0167),(0x5e70,0x4501)]:
  reset(ss=0x2000,sp=sp);run();require((r.status,r.returned.registers.di,r.next_segment,r.next_ip)==(0,di,0x2222,0x1111),'InitialDSflagaliasesPUSHDI '+str(sp));vectors+=1
 reset(ss=0x40,sp=0x10);run();require((r.status,r.next_segment,r.next_ip,word(0x10,0x40))==(0,0x2222,0x1121,0x1121),'BDAwordstorealiasesactualfarIP');vectors+=1
 device_mode=2;reset();run();require((r.status,r.returned.registers.di,r.next_segment,r.next_ip)==(0,0xabcd,0x369c,0x1357),'LateOUTbusmutation-beforePOP-RET');vectors+=1;device_mode=0
 reset(sp=0xffff);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.words,r.ports)==(5,0xffff,0x16c9,0x5fba,16412,16384,27),'Fullworkthenunqualifiedfarframeprefix');vectors+=1
 reset();run(b=null_bios);require((r.status,r.next_ip,r.events,r.services,r.bus_writes)==(4,0x5f81,0,0,3),'MissingBIOSadapterprefix');vectors+=1
 reset();run(d=null_device);require((r.status,r.next_ip,r.events,r.services,r.ports)==(4,0x5f88,1,1,0),'MissingdeviceadapterafterBIOS');vectors+=1
 for mode in [3,4]:
  bios_mode=mode;reset();run();require((r.status,r.next_ip,r.events,r.services,r.ports)==(4,0x5f81,0,0,0),'Invalid-rejectedBIOSnotadopted '+str(mode));vectors+=1
 bios_mode=0;device_mode=3;reset();run();require((r.status,r.next_ip,r.events,r.services,r.ports)==(4,0x5f88,1,1,0),'RejectedOUTprefix/noeventconsumed');vectors+=1
 device_mode=4;reset();run();require((r.status,r.next_ip,r.events,r.ports,r.words,r.returned.registers.di,r.returned.registers.cx)==(4,0x5fb1,27,26,0,0,0x4000),'Rejectedword-beforeREPstep');vectors+=1;device_mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_fallback_mode.py','sha256':hashlib.sha256((ROOT/'tools/validate_fallback_mode.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/exactBIOSAX4/BDAphysical0410mask-beforeINT/BIOSfullstate/tablebyteread-after-indexOUT/CLDafterBIOS/27byteports/16384rawRAMwords/SSFNs-BDA-flag-wordclear-lateOUTaliases/preRETqualification/adapter-budgetgates only. Originalcomparison separate; withinEGAexe/notCGAedition, no actualBIOS-devicehardware/renderer/historicalCPU/callerDF-IF-storage/writers/schema/lifetime/exclusion/core/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
