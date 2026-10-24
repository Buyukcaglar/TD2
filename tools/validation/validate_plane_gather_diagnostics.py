"""NativeAC40 fullSS/headerwrites/plane-row-counterwidth/globalwork/returninterfaces."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_plane_gather import Registers,StateRegisters,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_plane_gather;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();ss=0x9000;sp=0xe000;trace=[];mode=0
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null,None,128,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,128,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,128,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(config=None,width=2,height=3,pointer=0xe000):
  nonlocal sp
  sp=pointer;C.memset(bus,0,len(bus));trace.clear()
  for o,v in [(0x1200,width),(0x1202,height),(0x1208,0xaaaa),(0x120a,0xbbbb)]:put(0x2000,o,v)
  for i,v in enumerate(config if config is not None else [1,2,4,0x48]):bus[0x2120c+i]=v
  put(0x16c9,0xaf44,0x4000);put(0x16c9,0xaf4e,0x50);put(0x16c9,0x4000,0x200)
  for n in range(16):bus[0x16c90+0xac0c+n]=0 if n==0 else (n&-n).bit_length()-1
  for i in range(65536):bus[0xa0000+i]=i&255
  for i,v in enumerate([0x1111,0x2222,0x1200,0x2000,8,0]):put(ss,sp+2*i,v)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append((q.site,q.kind,q.value,q.port,q.address));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
  if mode==1 and q.site==0xacf5:memory[0x2120d]=0
  if q.kind==7:
   if mode==2:put(ss,q.incoming.bp-0xc,0)
   if mode in [3,4]:memory[((ss<<4)+((q.incoming.bp-0x14)&65535))&0xfffff]=0x80 if mode==3 else 2
   if mode==5:put(ss,q.incoming.bp-2,1)
   if mode==6:put(ss,sp,0x1357)
  if mode==7:return 0
  if q.kind==7:memory[q.address]=q.value
  return 1
 def run(limit=128,cb=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,limit,C.byref(r))
 reset(config=[0]*4);run(cb=null);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.work,r.planes,r.ports,r.copies,r.rows,r.bus_writes,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.es,r.returned.registers.ds,r.returned.registers.si,r.returned.registers.di,r.returned.bp,r.returned.registers.direction,r.returned.carry)==(0,0xe004,0x2222,0x1111,4,4,0,0,0,24,0xa000,0xc456,0x2000,0x2000,0x3456,0x4567,0x5678,0,0),'Zeronibbles/SSlocals/rawheaderwrites/noadapter/actualsaves');require((word(0x2000,0x1208),word(0x2000,0x120a))==(8,0),'Rawheaderx-ybeforeSARlocal');vectors+=1
 reset();run();require((r.status,r.work,r.planes,r.ports,r.copies,r.rows,r.bus_writes,r.returned.registers.ax,r.returned.registers.dx)==(0,48,4,8,24,12,48,0xa003,0),'Fourplanes/packedcopies-gaps/literalGPR');require(bytes(bus[0x21210:0x21216])==bytes([1,2,0x51,0x52,0xa1,0xa2]) and [(e[3],e[2]) for e in trace if e[1]==1]==[(0x3ce,4),(0x3cf,0),(0x3ce,4),(0x3cf,1),(0x3ce,4),(0x3cf,2),(0x3ce,4),(0x3cf,3)],'Rawread-before-writeCOPY/twoportbytesperplane');vectors+=1
 for nibble in range(1,16):
  reset(config=[nibble,0,0,0],width=1,height=1);run();require((r.status,r.planes,r.ports,r.copies,r.rows)==(0,4,2,1,1) and trace[1][2]==(nibble&-nibble).bit_length()-1,'Allnonzeronibbles '+str(nibble));vectors+=1
 for height,rows,dx in [(0,1,0xffff),(1,1,0),(2,2,0),(0x8000,1,0x7fff),(0xffff,1,0xfffe)]:
  reset(config=[1,0,0,0],width=0,height=height);run();require((r.status,r.rows,r.copies,r.returned.registers.dx)==(0,rows,0,dx),'Do-oncewideDECJG '+hex(height));vectors+=1
 reset(config=[1,0,0,0],width=0,height=0x7fff);run(limit=16);require((r.status,r.work,r.next_ip,r.rows)==(3,16,0xacfc,13),'Zerowidthlargeheightworkbound');vectors+=1
 for limit,site,planes,ports,rows,copies in [(0,0xacdc,0,0,0,0),(1,0xacf1,1,0,0,0),(2,0xacf5,1,1,0,0),(3,0xacfc,1,2,0,0),(4,0xacff,1,2,1,0),(5,0xacff,1,2,1,1)]:
  reset();run(limit=limit);require((r.status,r.next_ip,r.work,r.planes,r.ports,r.rows,r.copies)==(3,site,limit,planes,ports,rows,copies),'Plane-row-byteworkprefix '+str(limit));vectors+=1
 mode=1;reset();run();require((r.status,r.planes,r.ports,r.copies)==(0,4,6,18),'Liveheadernibblesrereadafterport');vectors+=1
 mode=2;reset();run();require((r.status,r.rows,r.copies,r.ports)==(0,12,2,8),'SSwidthrereadnextrow/currentREPcountretained');vectors+=1
 mode=3;reset();run();require((r.status,r.planes,r.rows,r.copies)==(0,1,3,6),'Bytecounter80->7FwithOF1/JGfalse');vectors+=1
 mode=4;reset();run(limit=64);require(r.status==3 and r.work==64 and r.planes>4,'Mutableplanecounterglobalworkbound');vectors+=1
 mode=5;reset();run();require((r.status,r.returned.registers.ds)==(0,1),'ActualsavedDSrereadafterCOPYalias');vectors+=1
 mode=6;reset();run();require((r.status,r.next_ip,r.next_segment)==(0,0x1357,0x2222),'ActualfarreturnwordrereadafterCOPYalias');vectors+=1;mode=0
 for pointer in range(8,26):
  reset(config=[0]*4,pointer=pointer);run(cb=null);require((r.status,r.returned.carry,r.current_sp)==(0,1,pointer+4),'FinalADDSP18carry '+str(pointer));vectors+=1
 for pointer in [0xfffd,0xfffe,0xffff]:
  reset(config=[0]*4,pointer=pointer);run(cb=null);require((r.status,r.current_sp,r.next_ip,r.work)==(5,pointer,0xad19,4),'PreRETqualificationafterbody');vectors+=1
 reset();run(cb=null);require((r.status,r.next_ip,r.work)==(4,0xacf1,1),'Missingdeviceadapter');vectors+=1
 mode=7;reset();run();require((r.status,r.next_ip,r.work)==(4,0xacf1,1),'Declineddeviceeffect');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_plane_gather.py','sha256':hashlib.sha256((ROOT/'tools/validate_plane_gather.py').read_bytes()).hexdigest()}],'limits':'NativeAC40/fullSS/rawheaderwrites/localSAR/liveheadernibbles/packedCOPY-gap/15nonzeroselectors/rowandbyte-counterDECJGwide/liveSSwidth/savedDS-farframealiases/globalplane-row-port-copybudget/ADDSPcarry/preRETqualification only. Originalcomparison/staticproofseparate; no alternateAC64entry/allwriters-format-capacities-lifetime-exclusion/realreadmap-latches-renderer/CPU-A20/core/resourcecodec/CGA/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
