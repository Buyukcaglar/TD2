"""NativeAE62 byteMULs/firstREP-vs-secondLOOP/fullSS/budgets/zero-width-wrap."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_plane_shift_strip import Registers,StateRegisters,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_plane_shift_strip;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();ss=0x9000;sp=0xe000;trace=[];mode=0
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(optional=1,width=2,height=2,index=0x101,config=None,pointer=0xe000):
  nonlocal sp
  sp=pointer;C.memset(bus,0,len(bus));trace.clear();put(0x16c9,0xaf44,0x4000);put(0x16c9,0x4000,0x200);put(0x2000,0x1200,0x0102);put(0x2000,0x1202,0x0203)
  for i,v in enumerate(config if config is not None else [1,2,4,0x48]):bus[0x2120c+i]=v
  for i in range(128):bus[0x21210+i]=i
  for i in range(65536):bus[0xa0000+i]=i&255
  for i,v in enumerate([0x1111,0x2222,0,0,width,height,0x50,0x1200,0x2000 if optional else 0,index]):put(ss,sp+2*i,v)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append((q.site,q.kind,q.value,q.address,q.incoming.registers.si,q.incoming.registers.ax));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=memory[q.address]|0xff00 if q.kind==2 else 0xffff
  if mode==1 and q.site==0xae78:put(ss,q.incoming.bp+6,0xffff)
  if mode==2 and q.kind==7:put(ss,q.incoming.bp+0xa,0)
  if q.kind==3:
   if mode==3:memory[0x2120d]=0
   if mode==4:memory[((ss<<4)+((q.incoming.bp-8)&65535))&0xfffff]=0x80
   if mode==5:put(ss,q.incoming.bp-14,1)
   if mode==6:put(ss,sp,0x1357)
   if mode==7:put(ss,q.incoming.bp-6,0xffff)
  if mode==8:return 0
  if q.kind in [3,7]:memory[q.address]=q.value
  return 1
 def run(limit=256,cb=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,limit,C.byref(r))
 reset(optional=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.work,r.ports,r.copies,r.rows,r.planes,r.loads,r.bus_writes,r.returned.registers.ax,r.returned.carry,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,12,6,4,2,0,0,9,0,0,0),'FirstREPshift-only/sixliteralports/actualsaves');vectors+=1
 reset();run();require((r.status,r.work,r.ports,r.copies,r.rows,r.planes,r.loads,r.reads,r.writes,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.ds,r.returned.registers.es,r.returned.registers.si,r.returned.registers.di,r.returned.bp)==(0,48,14,4,2,4,8,8,8,24,0x1721,0x1210,0,0x3c5,0x2000,0xa000,0x3456,0x4567,0x5678),'CompleteREP-plus-byteReadAH-WriteALstrip/GPR');require(word(ss,0xdffa)==8 and bytes(bus[0xa02a0:0xa02a2])==bytes([32,33]),'HeaderAL3*BL2+gap4-width2/lowindex01*width02');vectors+=1
 for height,rows in [(0,1),(1,1),(2,2),(0x8000,1),(0xffff,1)]:
  reset(optional=0,width=0,height=height);run();require((r.status,r.rows,r.copies,r.ports)==(0,rows,0,6),'FirstREPwidth0/do-oncewideDECJG '+hex(height));vectors+=1
 reset(config=[0,2,4,0x48]);run();require((r.status,r.planes,r.loads,r.ports)==(0,1,0,6),'FirstzeronibbleWHOLEexit');vectors+=1
 reset(config=[1,0,4,0x48]);run();require((r.status,r.planes,r.loads,r.ports)==(0,2,2,8),'SecondzeronibbleWHOLEexitafterfirststrip');vectors+=1
 for mw,mh,width,expected in [(0xabcd,0xef12,2,3692),(0xabcd,0xef12,0x102,3436)]:
  reset(width=width);put(0x2000,0x1200,mw);put(0x2000,0x1202,mh);run(limit=4096);require(r.status==0 and word(ss,0xdffa)==expected and next(e[4] for e in trace if e[1]==2)==0x1213,'TwoBYTE-MULs/highbytesignored '+hex(width));vectors+=1
 reset(width=0,height=0,index=0,config=[1,0,4,0x48]);run(limit=200000);require((r.status,r.copies,r.loads,r.reads,r.writes,r.planes,r.work,r.returned.registers.ax)==(0,0,65536,65536,65536,2,196619,0x4f48),'Complete65536secondLOOPwrap/firstREPzero/no countnormalization');vectors+=1
 for limit,site in [(0,0xae78),(4,0xaeb2),(5,0xaeb5),(6,0xaeb5),(7,0xaeb2),(10,0xaec3),(12,0xaf09),(13,0xaf15),(14,0xaf19),(15,0xaf20),(16,0xaf21),(17,0xaf24),(18,0xaf20)]:
  reset();run(limit=limit);require((r.status,r.work,r.next_ip)==(3,limit,site),'Sharedworkprefix '+str(limit));vectors+=1
 mode=1;reset();run();require(word(ss,0xdffc)==0x1fff and next(e[3] for e in trace if e[1]==7)==0xa21ff,'SSxreadAFTERsetupports/unsignedSHR3');vectors+=1
 mode=2;reset();run();require(r.status==3 and r.copies==2 and r.loads>0,'CurrentREPcountretained/nextSSwidth0stripbounded');vectors+=1
 mode=3;reset();run();require((r.status,r.planes,r.loads,r.ports)==(0,2,2,8),'Futureheadernibbleliveafterstripwrite');vectors+=1
 mode=4;reset();run();require((r.status,r.planes,r.loads)==(0,1,2),'Bytecounter80->7FwithOF1/JGfalse');vectors+=1
 mode=5;reset();run();require((r.status,r.returned.registers.ds)==(0,1),'ActualsavedDSrereadafterstripwrite');vectors+=1
 mode=6;reset();run();require((r.status,r.next_ip,r.next_segment)==(0,0x1357,0x2222),'Actualfarframeafterstripwrite');vectors+=1
 mode=7;reset();run();require(r.status==0 and any(e[1]==3 and e[3]==0xaffff for e in trace),'LiveSSstripdestnextplane/DIwrap');vectors+=1;mode=0
 for pointer,carry in [(0,0),(1,0),(2,1),(9,1)]:
  reset(pointer=pointer);run(limit=0);require((r.status,r.next_ip,r.returned.carry,r.current_sp)==(3,0xae78,carry,(pointer-16)&65535),'ActualSUBSPcarrybeforefirstport '+str(pointer));vectors+=1
 for pointer in [0xfffd,0xfffe,0xffff]:
  reset(optional=0,width=0,height=0,pointer=pointer);run();require((r.status,r.current_sp,r.next_ip)==(5,pointer,0xaf39),'RootpreRETqualificationafterbody');vectors+=1
 reset();run(cb=null);require((r.status,r.next_ip,r.work,r.bus_writes)==(4,0xae78,0,4),'MissingdeviceadapterafterrealSSsaves');vectors+=1
 mode=8;reset();run();require((r.status,r.next_ip,r.work)==(4,0xae78,0),'Declineddeviceeffect');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_plane_shift_strip.py','sha256':hashlib.sha256((ROOT/'tools/validate_plane_shift_strip.py').read_bytes()).hexdigest()}],'limits':'NativeAE62/fullSS/firstREPshift-vs-secondunconditionalLOOP65536/twobyteMULs-fullrequestedCX/zero-nibblewholeexit/liveSSwidth-dest-counter-saves-farframe/sourceorderedbyteReadAH-WriteAL/globalwork/prefixCF/preRETqualification only. Originalcomparison/staticproofseparate; rawRAMprofile/noEGAwrite-mode-latches-renderer/allwriters-format-capacities-storage-lifetime-exclusion/CPU-A20/core/resource/CGA/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
