"""NativeBA3C actualwordOUT/byteprofiles/rawplanes/fullSS/cachedbranch qualification."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_pixel_point import Registers,StateRegisters,Result,Service,require,device_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_pixel_point;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null=Service();trace=[];mode=0;ss=0x9000;sp=0xe000;pixel=0x1234
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null,None,8,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,8,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,8,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(hw=1,color=0x12,x=3,y=1,row=0x1234,stack=0x9000,pointer=0xe000,planes=None,df=0):
  nonlocal ss,sp,pixel
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.direction=df;trace.clear();pixel=(row+(x>>3))&65535;planes=planes if planes is not None else [0xa000]*4 if hw else [0x3000,0x4000,0x5000,0x6000]
  put(0xaf44,0x4000,0x16c9);put((0x4000+2*y)&65535,row,0x16c9)
  for i,segment in enumerate(planes):put(0xaf3c+2*i,segment,0x16c9)
  for i,v in enumerate([0x80,0x40,0x20,0x10,8,4,2,1]):bus[0x268ce+i]=v
  for segment in set(planes):
   if segment:bus[((segment<<4)+pixel)&0xfffff]=0x55
  put(sp,0x1111,ss);put(sp+2,0x2222,ss);put(sp+4,x,ss);put(sp+6,y,ss);put(sp+8,0xab00|color,ss)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(device_event(q));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=(memory[q.address]|0xff00) if q.kind==2 else 0xffff
  if mode==1 and q.site==0xba70:put(0xaf3c,0,0x16c9)
  if mode==2 and q.site in [0xbab0,0xbab6] and q.incoming.registers.bx==0:put(0xaf3e,0,0x16c9)
  if mode==3 and q.site in [0xbab0,0xbab6]:memory[0x268ce]=0
  if mode==4:return 0
  if q.kind==3:memory[q.address]=q.value&255
  if q.kind==6:memory[q.address]|=q.value&255
  return 1
 def run(limit=8,d=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),d,None,limit,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.reads,r.writes,r.ports,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.es,r.returned.registers.si,r.returned.registers.di,r.returned.bp,r.returned.carry)==(0,0xe004,0x2222,0x1111,7,1,1,5,4,5,3,0x5512,0x3ce,0xa000,0x3456,0x4567,0x5678,0) and bus[0xa0000+pixel]==0x12,'HardwareliteralGPR/CHread-fullCLwrite');require([(e[6],e[7]) for e in trace if e[0]==5]==[(0x3c4,0xff02),(0x3ce,0x1008),(0x3ce,0x205),(0x3ce,0xff08),(0x3ce,5)],'FiveWORDOUTs/exactAX');vectors+=1
 reset(hw=0,color=0xa);run();require((r.status,r.events,r.reads,r.writes,r.ports,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.es,r.returned.carry)==(0,6,2,4,0,7,0x6000,8,0xc400,0xef10,0x6000,0) and [bus[(sg<<4)+pixel] for sg in [0x3000,0x4000,0x5000,0x6000]]==[0x45,0x55,0x45,0x55],'Softwarefourplanes/readANDwrite-OR/CHpreserved');vectors+=1
 reset(hw=0,color=0xff);run();require((r.status,r.events,r.reads,r.writes,r.returned.registers.cx)==(0,4,0,4,0xc40f),'SoftwareCLuppernibbleremains/noearlycolor-mask');vectors+=1
 reset(hw=0,color=0xff,planes=[0,0,0,0]);run(limit=0,d=null);require((r.status,r.events,r.bus_writes,r.returned.registers.cx,r.returned.registers.es)==(0,0,3,0xc40f,0x4000),'AllzeroplanesconsumeCLbits/noadapterneeded');vectors+=1
 for limit,site,events,reads,writes,ports,ax in [(0,0xba70,0,0,0,0,0xff02),(1,0xba7a,1,0,0,1,0x1008),(3,0xba7f,3,0,0,3,0x205),(4,0xba82,4,1,0,3,0x205),(5,0xba88,5,1,1,3,0xff08),(6,0xba8c,6,1,1,4,5)]:
  reset();run(limit=limit);require((r.status,r.next_ip,r.current_sp,r.events,r.reads,r.writes,r.ports,r.returned.registers.ax)==(3,site,0xdffa,events,reads,writes,ports,ax),'Hardwareeffectprefix '+str(limit));vectors+=1
 reset(hw=0,color=1,x=0);run(limit=0);require((r.status,r.next_ip,r.events,r.bus_writes)==(3,0xbab6,0,3),'ORtransactionbudgetbeforeatomicwrite');vectors+=1
 reset(hw=0,color=1,x=0);run(limit=1);require((r.status,r.next_ip,r.events,r.reads,r.writes,bus[0x30000+pixel])==(3,0xbaab,1,0,1,0xd5),'OneORthennextplane-readprefix');vectors+=1
 for hw in [0,1]:
  reset(hw=hw,df=1);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1,1),'IFDFunchanged');vectors+=1
 mode=1;reset(pointer=0xffff);run();require((r.status,r.next_ip,r.ports,word(0xaf3c,0x16c9))==(5,0xba90,5,0),'PreRETsiteusesoriginalbranch/AF3Cmutated');vectors+=1;mode=0
 mode=2;reset(hw=0,color=0xf);run();require((r.status,r.writes,r.events,word(0xaf3e,0x16c9))==(0,3,3,0),'Rereadplaneafterpriorpixeladaptermutation');vectors+=1;mode=0
 mode=3;reset(hw=0,color=0xf,x=0);run();require((r.status,r.returned.registers.dx,bus[0x268ce],[bus[(sg<<4)+pixel] for sg in [0x3000,0x4000,0x5000,0x6000]])==(0,0x7f80,0,[0xd5]*4),'Maskreadoncebeforefourplanes');vectors+=1;mode=0
 reset(hw=0,color=1,x=0,row=0xe000,planes=[0x9000,0,0,0]);run();require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0x1191),'PixelORaliasesrootfarIP');vectors+=1
 reset(hw=0,color=1,x=0,row=0xdffe,planes=[0x9000,0,0,0]);run();require((r.status,r.returned.bp)==(0,0x56f8),'PixelORaliasesactualsavedBP');vectors+=1
 reset(hw=0,color=1,x=0,row=0xdffa,planes=[0x9000,0,0,0]);run();require((r.status,r.returned.registers.di)==(0,0x45e7),'PixelORaliasesactualsavedDI');vectors+=1
 reset(stack=0x2000,pointer=0x68d0,x=0);run();require(next(e[7] for e in trace if e[1]==0xba7a)==0x7808,'EntryPUSHBPaliasesmask-beforemaskread');vectors+=1
 reset(x=0xffff,y=0xffff,row=0xfff8);run();require(trace[3][9]==0xa0000+0x1ff7,'UnsignedX/wrappedY-rowaddition');vectors+=1
 for hw in [0,1]:
  for pointer in [0xfffd,0xfffe,0xffff]:
   reset(hw=hw,pointer=pointer);run();require((r.status,r.current_sp,r.next_ip)==(5,pointer,0xba90 if hw else 0xbac6),'RootpreRETqualification');vectors+=1
 reset();run(d=null);require((r.status,r.next_ip,r.events,r.bus_writes)==(4,0xba70,0,3),'MissingadapterafterthreeSSFNs');vectors+=1
 mode=4;reset();run();require((r.status,r.next_ip,r.events,r.bus_writes)==(4,0xba70,0,3),'RejectfirstwordOUT');vectors+=1;mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_pixel_point.py','sha256':hashlib.sha256((ROOT/'tools/validate_pixel_point.py').read_bytes()).hexdigest()}],'limits':'NativeBA3CfullSS/literal5wordOUTs/byteReadlow8-fullCLwrite/softwarefourplanes-zero-skip-liveplane-reread/readANDwrite-atomicOR/maskread-once/CH-CLregistereffects/IFDF/budgets/stack-mask-controlaliases/cachedbranchpreRETqualifications only. Originalcomparison/staticproofs separate; no clippingbounds/allwriters/realdevice-latch-hardware/renderer/CPU-A20/storage-lifetime-exclusion/core/resource/CGA/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
