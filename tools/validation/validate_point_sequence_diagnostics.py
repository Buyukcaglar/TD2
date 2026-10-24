"""Native3A91 actualthreeupdates/liveinputs/globalbudgets/lastchildflags/fullSS."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_point_sequence import Registers,StateRegisters,Limits,PointLimits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_point_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();bounds=Limits(3,PointLimits(6,48));ss=0x9000;sp=0xe000;trace=[];mode=0
 for memory,count,state,limits in [(bus,len(bus)-1,C.byref(s),C.byref(bounds)),(None,len(bus),C.byref(s),C.byref(bounds)),(bus,len(bus),None,C.byref(bounds)),(bus,len(bus),C.byref(s),None)]:
  fn(memory,count,0x1000,ss,sp,state,limits,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(value=0x3b71,old=0,planes=None,pointer=0xe000):
  nonlocal sp
  sp=pointer;C.memset(bus,0,len(bus));bounds.calls=3;bounds.update.calls=6;bounds.update.events=48;trace.clear()
  for o in [0x52ca,0x52d2,0x52da]:put(0x2000,o,value)
  for o in [0x2f50,0x2f52,0x2f54]:put(0x2000,o,old)
  put(0x16c9,0xaf44,0x4000);put(0x16c9,0x4000,0)
  for i,plane in enumerate(planes if planes is not None else [0,0,0,0]):put(0x16c9,0xaf3c+2*i,plane)
  for i,v in enumerate([0x80,0x40,0x20,0x10,8,4,2,1]):bus[0x268ce+i]=v
  bus[0x30000]=0x55;put(ss,sp,0x1111)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append((q.site,q.kind,q.value,q.address));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.bp=0xffff;result.contents.value=(memory[q.address]|0xff00) if q.kind==2 else 0xffff
  if q.kind in [3,6]:
   if mode==1:put(0x2000,0x52d2,0x8000);put(0x2000,0x52da,0xffff)
   if mode==2:put(0x2000,0x52da,0x8000);put(0x2000,0x2f54,0xffff)
   if mode==3:put(ss,sp-2,0x1357)
   if mode==4:put(ss,sp,0x1357)
  if mode==5:return 0
  if q.kind==3:memory[q.address]=q.value&255
  if q.kind==6:memory[q.address]|=q.value&255
  return 1
 def run(cb=null):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),cb,None,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.point_calls,r.events,r.bus_writes,r.returned.registers.si,r.returned.bp,r.returned.carry,r.zero_flag)==(0,0xe002,0x16c9,0x1111,3,6,0,54,1,0x5678,0,0) and [word(0x2000,o) for o in [0x2f50,0x2f52,0x2f54]]==[1]*3,'Threeactualnearupdate-farpixelcompositions');vectors+=1
 reset(value=0,old=0xffff);run();require((r.status,r.calls,r.point_calls,r.bus_writes,r.zero_flag,r.returned.carry)==(0,3,0,3,1,0),'Threeequalitychildren/lastactualZF1');vectors+=1
 for cap,site,si,bx,dx in [(0,0x3a9a,0x3b71,0,0xc),(1,0x3aa7,0x3b71,2,9),(2,0x3ab4,0x3b71,4,0xe)]:
  reset();bounds.calls=cap;run();require((r.status,r.next_ip,r.calls,r.point_calls,r.returned.registers.si,r.returned.registers.bx,r.returned.registers.dx,r.flags_valid)==(3,site,cap,cap*2,si,bx,dx,0),'SetupbeforeouterCALLbudget '+str(cap));vectors+=1
 for cap,outer,site in [(0,1,0x3ae4),(1,1,0x3af0),(2,2,0x3ae4),(5,3,0x3af0)]:
  reset();bounds.update.calls=cap;run();require((r.status,r.next_ip,r.calls,r.point_calls,r.flags_valid)==(3,site,outer,cap,0),'GlobalpixelCALLbudget '+str(cap));vectors+=1
 reset(planes=[0xa000]*4);bounds.update.events=14;run(device);require((r.status,r.next_ip,r.calls,r.point_calls,r.events,r.ports)==(3,0xba70,2,3,14,10),'Globaldevicebudgetacrossthreeupdates');vectors+=1
 reset(planes=[0xa000]*4);run(device);require((r.status,r.calls,r.point_calls,r.events,r.ports,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,3,6,42,30,1,1),'Fullthreehardwareprofiles/ignoreddeviceCPUresponse');vectors+=1
 for pointer in range(2,8):
  reset(value=0,old=0xfffe,pointer=pointer);run();require((r.status,r.calls,r.point_calls,r.returned.carry,r.zero_flag)==(0,3,0,1,int(pointer==2)),'LastactualchildADDflags '+str(pointer));vectors+=1
 mode=1;reset(planes=[0x3000,0,0,0]);run(device);require((r.status,r.calls,r.point_calls,r.returned.registers.si,r.zero_flag)==(0,3,4,0xffff,0) and [word(0x2000,o) for o in [0x2f50,0x2f52,0x2f54]]==[1,0xffff,0xffff],'Rereadsourcewordsafterpriorchildbusmutation');vectors+=1
 mode=2;reset(planes=[0x3000,0,0,0]);run(device);require((r.status,r.calls,r.point_calls,r.returned.registers.si,r.zero_flag)==(0,3,4,0xffff,1),'ThirdactualequalityZFafterchangedfirsttwo');vectors+=1
 mode=3;reset(planes=[0x3000,0,0,0]);run(device);require((r.status,r.calls,r.point_calls,r.next_ip,r.flags_valid)==(1,1,2,0x1357,0),'ActualchildnearRETrawneverfollowed');vectors+=1
 mode=4;reset(planes=[0x3000,0,0,0]);run(device);require((r.status,r.calls,r.next_ip,r.flags_valid)==(0,3,0x1357,1),'ActualrootnearRETafterbusmutation');vectors+=1;mode=0
 for pointer in [15,16,17,9,10,11]:
  reset(pointer=pointer);run();require(r.status==5 and r.flags_valid==0,'NestedfarpreRETqualification '+str(pointer));vectors+=1
 reset(planes=[0xa000]*4);run();require(r.status==4 and r.events==0 and r.flags_valid==0,'Missingdeviceadapter');vectors+=1
 mode=5;reset(planes=[0xa000]*4);run(device);require(r.status==4 and r.events==0,'Declineddeviceeffect');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_point_sequence.py','sha256':hashlib.sha256((ROOT/'tools/validate_point_sequence.py').read_bytes()).hexdigest()}],'limits':'Native3A91 actualthree3AB8near-BA3Cfarcompositions/liveinputrereads/sharedouterCALL-pixelCALL-devicebudgets/lastactualchildCF-ZF/rawchildnearRET-rootnearRET/nestedqualification only. Originalcomparison/staticproofseparate. RawRAMdeviceprofile/nohardwarelatches-renderer/allwriters-coordinatebounds-storage-capacity-lifetime-exclusion/CPU-A20/core/resource/CGA/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
