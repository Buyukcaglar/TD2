"""NativeC784 fullSS/liveargs-locals/rowwork/DECJGoverflow/rawCOPY profiles."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_plane_byte_copy import Registers,StateRegisters,Result,Service,require,device_event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_plane_byte_copy;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,1),0x5678,1);r=Result();vectors=0;null=Service();trace=[];mode=0;ss=0x9000;sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(width=8,height=2,srcx=0,dstx=0,stack=0x9000,pointer=0xe000,planes=None,destrow=0x300):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));trace.clear()
  for i in range(65536):bus[0xa0000+i]=i&255
  put(0xaf5e,0x4000,0x16c9);put(0xaf44,0x6000,0x16c9);put(0xaf4e,0x50,0x16c9);put(0x4000,0x200,0x16c9);put(0x6000,destrow,0x16c9)
  for i,segment in enumerate(planes if planes is not None else [0x3000,0x4000,0x5000,0x6000]):put(0xaf3c+2*i,segment,0x16c9)
  put(sp,0x1111,ss);put(sp+2,0x2222,ss)
  for i,value in enumerate([srcx,0,dstx,0,width,height]):put(sp+4+2*i,value,ss)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append(device_event(q));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
  if mode==1 and q.site==0xc804 and q.incoming.registers.bx==0:put(0xaf3c,0,0x16c9)
  if mode==2 and q.kind==7:put(q.incoming.bp-0x10,0,q.stack_segment)
  if mode==3 and q.kind==7:put(q.incoming.bp-2,1,q.stack_segment)
  if mode==4 and q.kind==7:put(q.incoming.bp+0x10,0,q.stack_segment)
  if mode==5:return 0
  if q.kind==7:memory[q.address]=q.value
  return 1
 def run(limit=256,d=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),d,None,limit,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.work,r.ports,r.copies,r.rows,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.es,r.returned.bp,r.returned.carry,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,24,8,8,8,19,0x6000,8,0,0,0x3456,0x4567,0x2000,0x6000,0x5678,0,0),'FullfourplaneCLD-frame-body');require([(e[6],e[7]) for e in trace if e[0]==1]==[(port,value) for i in range(4) for port,value in [(0x3ce,4),(0x3cf,i)]] and all(bus[(sg<<4)+0x300]==0 and bus[(sg<<4)+0x350]==0x28 for sg in [0x3000,0x4000,0x5000,0x6000]),'EightliteralbyteOUTs/source40-dest80strides');vectors+=1
 reset(srcx=7,dstx=9);run();require((r.status,word(sp+4,ss),word(sp+8,ss),word(sp+12,ss))==(0,0,1,8),'In-placeSAR3callerXargs/widthargunchanged');vectors+=1
 for height,finalDX in [(0,0xffff),(0x8000,0x7fff),(0xffff,0xfffe)]:
  reset(width=0,height=height);run();require((r.status,r.work,r.rows,r.copies,r.returned.registers.dx)==(0,12,4,0,finalDX),'Do-oncerows/DECJGwide '+hex(height));vectors+=1
 reset(width=0,height=0x7fff);run(limit=32);require((r.status,r.next_ip,r.work,r.rows,r.copies,r.returned.registers.dx)==(3,0xc819,32,30,0,0x7fe1),'Zero-widthrowheadsconsumehostbudget');vectors+=1
 reset(width=0xffff);run(limit=64);require((r.status,r.next_ip,r.work,r.copies,r.rows,r.bus_writes,r.returned.registers.cx)==(3,0xc81c,64,61,1,72,0xffc2),'NegativeSARwidthretainsunsignedREPcount/prefix');vectors+=1
 reset(planes=[0,0,0,0]);run();require((r.status,r.work,r.ports,r.copies,r.rows,r.bus_writes,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.es)==(0,8,8,0,0,11,0,3,0x3cf,0),'Zero-plane-skipsstillissueallOUTs');vectors+=1
 for limit,site,ports,rows,copies,ax in [(0,0xc800,0,0,0,0xa004),(1,0xc804,1,0,0,0xa000),(2,0xc819,2,0,0,0x3000),(3,0xc81c,2,1,0,0x3000),(4,0xc819,2,1,1,0x3000),(5,0xc81c,2,2,1,0x3000)]:
  reset();run(limit=limit);require((r.status,r.next_ip,r.current_sp,r.work,r.ports,r.rows,r.copies,r.returned.registers.ax)==(3,site,0xdfee,limit,ports,rows,copies,ax),'Effect-row-prefix '+str(limit));vectors+=1
 reset(width=16,height=1,planes=[0xa000,0,0,0],destrow=0x201);run();require((r.status,r.copies,bytes(bus[0xa0200:0xa0203]))==(0,2,bytes([0,0,0])),'ForwardoverlapCOPYnotbuffered');vectors+=1
 mode=1;reset();run();require((r.status,r.rows,r.copies,r.work,word(0xaf3c,0x16c9))==(0,6,6,20,0),'Plane-wordreadoccursafterselectorOUT');vectors+=1;mode=0
 mode=2;reset();run();require((r.status,r.rows,r.copies,r.work,word(0xdfee,ss),word(0xdff2,ss),word(0xdff0,ss))==(0,8,1,17,0,39,79),'Widthlocalreread/stridesretaininitialderivedvalues');vectors+=1;mode=0
 mode=3;reset();run();require((r.status,r.returned.registers.ds)==(0,1) and all(e[8][0]==0xa000 for e in trace if e[0]==7),'ActualsavedDSrestored/currentcopyDSstaysA000');vectors+=1;mode=0
 mode=4;reset();run();require((r.status,r.rows,r.copies,r.work,word(sp+14,ss))==(0,5,5,18,0),'Heightargloadedonceperplane/rereadlaterplanes');vectors+=1;mode=0
 reset(width=8,height=1,planes=[ss,0,0,0],destrow=sp);run();require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0x1100),'COPYaliasesrootfarIP');vectors+=1
 reset(width=8,height=1,planes=[ss,0,0,0],destrow=sp-2);run();require((r.status,r.returned.bp)==(0,0x5600),'COPYaliasesactualsavedBP');vectors+=1
 reset(width=8,height=1,planes=[ss,0,0,0],destrow=sp-4);bus[0xa0200]=0x5a;run();require((r.status,r.returned.registers.ds)==(0,0x205a),'COPYaliasesactualsavedDS');vectors+=1
 for pointer in [8,17]:
  reset(width=0,height=1,pointer=pointer);run();require((r.status,r.returned.carry,r.current_sp)==(0,1,pointer+4),'FinalADDSP10carry');vectors+=1
 for pointer in [0xfffd,0xfffe,0xffff]:
  reset(width=0,height=1,pointer=pointer);run();require((r.status,r.next_ip,r.current_sp)==(5,0xc836,pointer),'RootpreRETqualification');vectors+=1
 reset(planes=[0,0,0,0]);run(d=null);require((r.status,r.next_ip,r.work,r.bus_writes)==(4,0xc800,0,11),'Missingadapterevenzero-planes');vectors+=1
 mode=5;reset();run();require((r.status,r.next_ip,r.work,r.bus_writes)==(4,0xc800,0,11),'RejectedfirstOUT');vectors+=1;mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_plane_byte_copy.py','sha256':hashlib.sha256((ROOT/'tools/validate_plane_byte_copy.py').read_bytes()).hexdigest()}],'limits':'NativeC784fullSS/in-placeSAR3args/livewidth-stride-heightlocals/CLD/fourplane-OUTs/atomicCOPY-forwardoverlap/DECJGoverflow-do-oncerows/workbudgetincludingzerowidth/SSsave-controlaliases/finalstackADDcarry/preRETqualification only. Originalcomparison/staticproofs separate; no actualEGAselector-latch-hardware/renderer/clippingbounds/allwriters-storage-lifetime-exclusion/CPU-A20/core/resource/CGA/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
