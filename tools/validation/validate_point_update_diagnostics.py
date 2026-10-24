"""Native3AB8 signednormalization/cache-before-device/actualSSold-newframes/nearCF."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_point_update import Registers,StateRegisters,Limits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_point_update;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0,0xc456,0xf,0x3b71,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();bounds=Limits(2,16);ss=0x9000;sp=0xe000;trace=[];mode=0
 for memory,count,state,limits in [(bus,len(bus)-1,C.byref(s),C.byref(bounds)),(None,len(bus),C.byref(s),C.byref(bounds)),(bus,len(bus),None,C.byref(bounds)),(bus,len(bus),C.byref(s),None)]:
  fn(memory,count,0x1000,ss,sp,state,limits,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(value=0x3b71,old=0,planes=None,stack=0x9000,pointer=0xe000,bx=0):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));bounds.calls=2;bounds.events=16;trace.clear();s.registers.si=value;s.registers.bx=bx;s.registers.cx=0xc456;s.registers.dx=0xf
  put(0x2000,0x2f50+bx,old);put(0x16c9,0xaf44,0x4000);put(0x16c9,0x4000,0)
  for i,plane in enumerate(planes if planes is not None else [0,0,0,0]):put(0x16c9,0xaf3c+2*i,plane)
  for i,v in enumerate([0x80,0x40,0x20,0x10,8,4,2,1]):bus[0x268ce+i]=v
  bus[0x30000]=0x55;put(ss,sp,0x1111)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append((q.site,q.kind,q.value,q.address));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.bp=0xffff;result.contents.value=(memory[q.address]|0xff00) if q.kind==2 else 0xffff
  if q.kind in [3,6]:
   if mode==1:put(ss,q.stack_sp+2,0xffff)
   if mode==2:put(ss,q.stack_sp+6,0x1357)
   if mode==3:put(ss,sp,0x1357)
  if mode==4:return 0
  if q.kind==3:memory[q.address]=q.value&255
  if q.kind==6:memory[q.address]|=q.value&255
  return 1
 def run(cb=null):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(bounds),cb,None,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.events,r.bus_writes,r.returned.registers.si,r.returned.bp,r.returned.carry,r.zero_flag,word(0x2000,0x2f50))==(0,0xe002,0x16c9,0x1111,2,0,17,1,0x5678,0,0,1),'Twoactualfarframes/nearRET2/noadapterzeroplanes');vectors+=1
 reset(old=1,bx=2);run();require((r.status,r.calls,r.bus_writes,r.returned.registers.bx,r.zero_flag,r.returned.carry,word(0x2000,0x2f52))==(0,0,0,2,1,0,1),'Equalitybeforecachewrite-orframes');vectors+=1
 for value,normalized in [(0,0xffff),(0x3b50,0xffff),(0x3b51,0),(0x3b70,0),(0x3b71,1),(0x7fff,549),(0x8000,0xffff),(0xffff,0xffff)]:
  reset(value=value,old=normalized);run();require((r.status,r.calls,r.returned.registers.si,r.zero_flag)==(0,0,normalized,1),'SignedSUB-JGE-SAR5 '+hex(value));vectors+=1
 reset(value=0,old=0xfffe);run();require((r.status,r.calls,r.bus_writes,r.returned.registers.si,word(0x2000,0x2f50))==(0,0,4,0xffff,0xffff),'Bothnegativechanged/nochildren/cachestore-and-threePUSHes');vectors+=1
 reset(value=0,old=0);run();require((r.status,r.calls,word(0x2000,0x2f50))==(0,1,0xffff),'Oldpositive-erased/newnegative-skipped');vectors+=1
 reset(old=0xffff);run();require((r.status,r.calls,r.returned.registers.si)==(0,1,1),'Oldnegative-skipped/newpositive-drawn');vectors+=1
 for pointer in range(6):
  reset(value=0,old=0xfffe,pointer=pointer);run();require((r.status,r.current_sp,r.returned.carry,r.zero_flag)==(0,pointer+2,1,int(pointer==0)),'LiteralfinalADDcarry '+str(pointer));vectors+=1
 reset();bounds.calls=0;run();require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes,r.flags_valid,word(0x2000,0x2f50))==(3,0x3ae4,0xdff4,0,7,0,1),'Cachecommit-and-args-beforeCALLbudget');vectors+=1
 reset();bounds.calls=1;run();require((r.status,r.next_ip,r.current_sp,r.calls,r.flags_valid)==(3,0x3af0,0xdffa,1,0),'Firstcompletechild-before-secondCALLbudget');vectors+=1
 reset(planes=[0xa000]*4);bounds.events=7;run(device);require((r.status,r.next_ip,r.calls,r.events,r.ports,r.flags_valid)==(3,0xba70,2,7,5,0),'Globaldevicebudgetspansbothchildren');vectors+=1
 reset(planes=[0xa000]*4);run(device);require((r.status,r.calls,r.events,r.reads,r.writes,r.ports,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,2,14,2,2,10,1,1),'Twohardwareprofiles/ignoreddeviceCPUresponse/IFDF');vectors+=1
 reset(stack=0x2000,pointer=0x2f50);run();require((r.status,r.next_ip,word(0x2000,0x2f50))==(0,1,1),'Cachewritealiasesrootnearreturn');vectors+=1
 for testmode,calls,status,ip,returnedsi in [(1,1,0,0x1111,0xffff),(2,1,1,0x1357,1),(3,2,0,0x1357,1)]:
  mode=testmode;reset(planes=[0x3000,0,0,0]);run(device);require((r.status,r.calls,r.next_ip,r.returned.registers.si)==(status,calls,ip,returnedsi),'Devicebus-alias '+str(testmode));vectors+=1
 mode=0
 for pointer,site in [(13,0xbac6),(14,0xbac6),(15,0xbac6),(7,0xbac6),(8,0xbac6),(9,0xbac6)]:
  reset(pointer=pointer);run();require((r.status,r.next_ip,r.flags_valid)==(5,site,0),'ActualchildpreRETqualification '+str(pointer));vectors+=1
 reset(planes=[0xa000]*4);run();require(r.status==4 and r.events==0 and r.flags_valid==0,'Missingdeviceadapter');vectors+=1
 mode=4;reset(planes=[0xa000]*4);run(device);require(r.status==4 and r.events==0,'Declineddeviceeffect');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_point_update.py','sha256':hashlib.sha256((ROOT/'tools/validate_point_update.py').read_bytes()).hexdigest()}],'limits':'Native3AB8/fullSS/signedSUB-JGE-SAR5/equality-cachewrite-before-frames/cursorstate-savedSI-controlaliases/actualBA3C-old-newframes/globalCALL-eventlimits/nearRET-CF-ZF/childqualification only. Originalcomparison/staticproofs separate. RawRAMdeviceprofile/no hardwarelatches-renderer/allwriters-coordinatebounds-storage-lifetime-exclusion/CPU-A20/core/resource/CGA/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
