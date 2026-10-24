"""Native247C/fullSS/nearDS-vs-SSlocal/AH-DF-CXreturns/mapper and control prefixes."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_read_span import Registers,StateRegisters,Request,Service,Result,require,event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_read_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();trace=[];mode=0;ss=0x9000;sp=0xe000;payload=b'A\r\nB';peek=0;primary_error=-1;ioctl=0;ioctl_error=0;seek_error=0;altbp=0x8000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,1,8,16,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),1,8,16,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),1,8,16,null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(data=b'A\r\nB',flag=0x80,requested=None,stack=0x9000,pointer=0xe000,handle=0,buffer=0x6000):
  nonlocal ss,sp,payload
  ss,sp,payload=stack,pointer,data;C.memset(bus,0,len(bus));trace.clear()
  for sg in [0x2000,0x2100]:
   put(0x6da2,1,sg);bus[(sg<<4)+0x6d9d]=3
   for h in [0,2]:bus[(sg<<4)+0x6da4+h]=flag
   for i in range(20):bus[(sg<<4)+0x6dda+i]=(0x80+13*i)&255
   for i,v in enumerate(data+b'\rZ'):bus[(sg<<4)+0x6000+i]=v
  put(sp,0x1111,ss);put(sp+2,0x2222,ss)
  for i,v in enumerate([handle,buffer,max(1,len(data)) if requested is None else requested]):put(sp+4+2*i,v,ss)
  if mode in [3,6]:
   put(altbp,0x1357,ss);put(altbp+2,0x2468,ss);put(altbp+4,0x369c,ss)
 @Service
 def dos(context,memory,request,result):
  q=request.contents;rr=q.incoming.registers;trace.append(event(q));require(q.vector==0x21,'DOSvector');result[0]=q.incoming;result.contents.carry=0
  if q.site==0x24a5:
   require(rr.ax>>8==0x3f,'Primary3F');result.contents.registers.ax=len(payload)
   if primary_error>=0:result.contents.carry=1;result.contents.registers.ax=primary_error
   else:
    for i,v in enumerate(payload):memory[(((rr.ds<<4)+((rr.dx+i)&65535))&0xfffff)]=v
   if mode==3:
    result.contents.registers.bx=2;result.contents.registers.cx=0x4433;result.contents.registers.dx=0x7000;result.contents.registers.si=0x1111;result.contents.registers.di=0x2222;result.contents.registers.ds=0x2100;result.contents.registers.es=0x3333;result.contents.registers.interrupts_enabled=0;result.contents.registers.direction=0;result.contents.bp=altbp
   if mode==6:result.contents.bp=altbp
  elif q.site==0x2504:require(rr.ax==0x4400,'IOCTLAX');result.contents.registers.ax=0x5507;result.contents.registers.dx=ioctl;result.contents.carry=ioctl_error
  elif q.site in [0x2511,0x2522]:
   require(rr.ax>>8==0x3f,'Lookahead3F');result.contents.registers.ax=0 if peek==2 else 1
   if peek==3:result.contents.carry=1;result.contents.registers.ax=5
   elif peek!=2:memory[(((rr.ds<<4)+rr.dx)&0xfffff)]=0xa if peek==0 else 0x41
   if mode==4:result.contents.registers.cx=2;result.contents.registers.si=0x6001;result.contents.registers.di=0x6000;result.contents.registers.direction=1
  elif q.site==0x2538:require((rr.ax,rr.cx,rr.dx)==(0x4201,0xffff,0xffff),'Seekbackliteral');result.contents.registers.ax=0x1234;result.contents.carry=seek_error
  else:raise RuntimeError('UnexpectedDOSsite '+hex(q.site))
  if mode==5:result.contents.carry=2
  if mode==7:return 0
  return 1
 def run(calls=1,services=8,steps=16,d=dos):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),calls,services,steps,d,None,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.services,r.steps,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.si,r.returned.registers.di,r.returned.bp,r.returned.carry,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,0,1,4,7,3,0x6000,0x3456,0x4567,0x5678,0,0) and bytes(bus[0x26000:0x26004])==b'A\nBB','TextCRLFcompaction-noNUL/actualSSsaves');vectors+=1
 reset(data=b'A\r\n\x1a',flag=0);run();require((r.status,r.services,r.steps,r.bus_writes,r.returned.registers.ax,r.returned.registers.direction)==(0,1,0,1,4,1) and bytes(bus[0x26000:0x26004])==b'A\r\n\x1a','Binarypath-noCLD/noformatrewrite');vectors+=1
 reset(data=b'\n');run();require(bus[0x26da4]==0x84,'FirstbyteLFsetsflag4');vectors+=1
 reset(data=b'A\n');run();require(bus[0x26da4]==0x80,'LaterLFdoesnotsetfirstbyteflag');vectors+=1
 reset(data=b'\x1aX');run();require((r.status,r.returned.registers.ax,r.steps,bus[0x26da4])==(0,0,1,0x82),'CtrlZlatch-stops-beforestore');run();require((r.status,r.services,r.steps,r.returned.registers.ax,r.returned.registers.dx,r.returned.registers.direction)==(0,0,0,0,0xd789,1),'Latchedbit2earlyreturn-beforeDXload-CLD');vectors+=1
 reset(handle=1);run();require((r.status,r.calls,r.services,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,word(0x6d95,0x2000))==(0,1,0,0xffff,0xffff,0,9),'Invalidhandle-originalmappererror-native0');vectors+=1
 reset(handle=1);run(calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.carry)==(3,0x939,0xdffc,0,1,0x900,1),'Mapperbudgetbeforeactualnearframe');vectors+=1
 reset();run(services=0);require((r.status,r.next_ip,r.current_sp,r.services,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx)==(3,0x24a5,0xdffc,0,1,0x3f5a,0x6000),'Primaryserviceprefix/retainsincomingAL');vectors+=1
 reset(data=b'\x00');run(steps=0);require((r.status,r.next_ip,r.current_sp,r.services,r.steps,r.bus_writes,r.returned.registers.ax,r.returned.carry,r.returned.registers.direction)==(3,0x24d0,0xdff8,1,0,4,0xd01,1,0),'LODSbudgetafterfirstbytepeekCF-beforeLODS');vectors+=1
 primary_error=5;reset();run();require((r.status,r.calls,r.services,r.returned.registers.ax,r.returned.carry,bus[0x26da0],word(0x6d95,0x2000))==(0,1,1,0xffff,0,5,9),'PrimaryCF1forcesAH9/bypassesDOSerrorXLAT');vectors+=1;primary_error=-1
 peek=3;reset(data=b'\r');run();require((r.status,r.calls,r.services,r.steps,r.returned.registers.ax,r.returned.registers.bx,r.returned.carry,word(0x6d95,0x2000))==(0,1,2,1,0xffff,0x6dda,1,0xffc1),'SecondaryCF1retainsAH0/actualsignedXLATmapper');vectors+=1;peek=0
 reset(data=b'\r',requested=1,stack=0x2000);run();require((r.status,r.services,r.returned.registers.ax,bus[0x26000],bus[0x2dffd])==(0,2,1,0xa,0xa),'DSsameSSlookaheadLF/localmatches');vectors+=1
 reset(data=b'\r',requested=1);run();require((r.status,r.services,r.returned.registers.ax,bus[0x26000],bus[0x2dffd],bus[0x9dffd])==(0,3,1,0xd,0xa,0),'DSdiffSSlookaheadwritesdifferentbyte/seekback');vectors+=1
 reset(data=b'\r',requested=2,stack=0x2000);run();require((r.status,r.services,r.returned.registers.ax,bus[0x26000])==(0,3,0,0xd),'Requestedcount2-LFpeek-seekback-CRskip');vectors+=1
 peek=1;seek_error=1;reset(data=b'\r',requested=1,stack=0x2000);run();require((r.status,r.services,r.calls,r.returned.registers.ax,r.returned.carry)==(0,3,0,1,0),'SeekCF1ignored/normalCRcount');vectors+=1;peek=0;seek_error=0
 ioctl=0x20;ioctl_error=1;reset(data=b'\r',flag=0xc0);run();require((r.status,r.services,r.calls,r.returned.registers.ax,bus[0x26000])==(0,2,0,1,0xa),'IOCTL_CF1ignored_TESTDX20-nopeek');vectors+=1;ioctl=0;ioctl_error=0
 peek=2;reset(data=b'\r',flag=0xc0);run();require((r.status,r.services,r.returned.registers.ax,bus[0x26000])==(0,3,1,0xa) and trace[-1][5][0]==0x3f07,'DevicepeekEOFstillLF/retainedIOCTLAL07');vectors+=1;peek=0
 mode=4;reset(data=b'\r',flag=0xc0);run();require((r.status,r.services,r.steps,r.returned.registers.ax,r.returned.registers.direction,bytes(bus[0x26000:0x26002]))==(0,3,2,2,1,b'\n\r'),'ReturnedAH0marker-DF1-CX2retainliteralcontinuation');vectors+=1;mode=0
 mode=3;altbp=0x8000;reset(data=b'A',flag=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.ds,r.returned.registers.es,r.returned.registers.dx,r.returned.registers.si,r.returned.registers.di,r.returned.registers.interrupts_enabled)==(0,0x8006,0x369c,0x2468,0x1357,0x2100,0x3333,0x7000,0x1111,0x2222,0),'PrimaryfullreturnedBP-DS-ES-state/actualalternatefarframe');vectors+=1;mode=0
 primary_error=1;reset(stack=0x2000,pointer=0x6d9b);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.registers.ax)==(1,0x6d97,0x23a8,9,9),'Mapperwordaliasesactualnearreturn/rawafterRET');vectors+=1
 reset(stack=0x2000,pointer=0x6d95);run();require((r.status,r.next_segment,r.next_ip,r.returned.registers.ax)==(0,0x2222,9,0xffff),'MapperwordaliasesrootfarIP');vectors+=1;primary_error=-1
 reset(data=b'AB',requested=2,buffer=0xffff);run();require((r.status,r.calls,r.returned.registers.ax,r.returned.registers.dx,r.returned.carry,word(0x6d95,0x2000))==(0,1,0xffff,0xffff,1,0xff9a),'CompactedDIwrapSUBborrow-entersmapper-despiteDOSsuccess');vectors+=1
 reset(data=b'\x34\x12',flag=0,stack=0x2000,pointer=0x6002);run();require((r.status,r.returned.bp)==(0,0x1234),'PrimarypayloadaliasesactualsavedBP');vectors+=1
 for site,flag,services in [(0x2522,0x80,1),(0x2504,0xc0,1),(0x2511,0xc0,2)]:
  reset(data=b'\r',flag=flag);run(services=services);require((r.status,r.next_ip,r.services)==(3,site,services),'Globalserviceprefix '+hex(site));vectors+=1
 mode=6
 for bp in [0xfffb,0xfffc,0xfffd]:
  altbp=bp;reset(data=b'A',flag=0);run();require((r.status,r.current_sp,r.next_ip,r.returned.bp)==(5,(bp+2)&65535,0x943,0x1357),'PreRETqualificationafteractualreturnedBP-pop');vectors+=1
 mode=0;reset();run(d=null);require((r.status,r.next_ip,r.services,r.bus_writes)==(4,0x24a5,0,1),'MissingDOSservice');vectors+=1
 mode=5;reset();run();require((r.status,r.next_ip,r.services,r.returned.registers.ax)==(4,0x24a5,0,0x3f5a),'Invalidreturnedstate-notadopted');vectors+=1;mode=0
 mode=7;reset();run();require((r.status,r.next_ip,r.services)==(4,0x24a5,0),'RejectedDOSadapter');vectors+=1;mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_read_span.py','sha256':hashlib.sha256((ROOT/'tools/validate_read_span.py').read_bytes()).hexdigest()}],'limits':'Native247C/fullSS/syntheticDOSfullreturns/firstLFflag-CTRLZ-binary-text/primaryAH9-vs-secondaryAH0mapper/DSnearbuffer-vs-SSlookaheadlocal/retainedAH-DF-CX/fullBP-DSframeeffects/ignoredIOCTL-seekCF/countborrow/mapper-near-rootaliases/CALL-service-LODSbudgets/preRETqualification/adapterdiagnostics only. Originalcomparison/staticproofs separate; no realDOS-INTframes/fileIO/fullresourcecodec/allwriters-bufferbounds-storage-lifetime-exclusion/historicalCPU-A20/core/CGA/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
