"""Native840A effectprefixes/rawRAMfill/DFwrap/lateSSargs-returns/portstatepreserve."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_plane_fill import Registers,StateRegisters,Request,Response,Service,Result,require,event
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_plane_fill;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null=Service();trace=[];mode=0;active_ss=0x9000;active_sp=0xe000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,0x9000,0xe000,state,null,None,8006,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null,None,8006,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),null,None,8006,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def reset(value=0x1234,df=0,ss=0x9000,sp=0xe000):
  nonlocal active_ss,active_sp
  C.memset(bus,0,len(bus));s.registers.direction=df;trace.clear();active_ss=ss;active_sp=sp
  for i,v in enumerate([0x1111,0x2222,value]):put(sp+2*i,v,ss)
 @Service
 def callback(context,memory,request,result):
  q=request.contents;trace.append(event(q));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.interrupts_enabled=2;result.contents.returned.registers.direction=2;result.contents.returned.bp=0xffff;result.contents.value=0xffff
  if mode==3 and q.site==0x8422:return 0
  if mode==4 and q.kind==3:return 0
  if mode==1 and q.site==0x8426:put(active_sp+4,0xabcd,active_ss)
  if mode==2 and q.site==0x843a:
   for o,v in [(active_sp-4,0xabcd),(active_sp-2,0x2468),(active_sp,0x1357),(active_sp+2,0x369c)]:put(o,v,active_ss)
  if q.kind==3:memory[q.address]=q.value
  return 1
 def run(limit=8006,cb=callback):fn(bus,len(bus),0x1000,active_ss,active_sp,C.byref(s),cb,None,limit,C.byref(r))
 reset();run(limit=0);require((r.status,r.next_ip,r.current_sp,r.events,r.bytes,r.bus_writes,r.returned.registers.ax,r.returned.registers.es,r.returned.registers.dx,r.returned.carry)==(3,0x8418,0xdffc,0,0,2,0xa005,0xa000,0x3ce,1),'FirstOUTprefix/realSSFNs/incomingCFretained');vectors+=1
 for limit,ip in [(1,0x841c),(2,0x8422),(3,0x8426)]:
  reset();run(limit);require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes)==(3,ip,limit,0,2),'SetupOUTprefix '+str(limit));vectors+=1
 reset();run(limit=4);require((r.status,r.next_ip,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.di,r.returned.carry,r.bytes)==(3,0x842f,0x1234,8000,0,0,0),'ArgumentrereadafterfourOUTs/XORDIbeforeREP');vectors+=1
 reset();run(limit=5);require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes,r.returned.registers.di,r.returned.registers.cx,bus[0xa0000])==(3,0x842f,5,1,3,1,7999,0x34),'Oneacceptedbyte/REPprefix');vectors+=1
 reset();run(limit=8004);require((r.status,r.next_ip,r.events,r.bytes,r.returned.registers.cx,r.returned.registers.di,r.returned.registers.ax)==(3,0x8436,8004,8000,0,8000,0x1205),'Completefill-beforefirstrestoreOUT/noinventedcleanup');vectors+=1
 reset();run(limit=8005);require((r.status,r.next_ip,r.events,r.returned.registers.dx,r.returned.registers.ax)==(3,0x843a,8005,0x3cf,0x1200),'BeforefinalOUT/AHretained');vectors+=1
 reset();run();ports=[(e[6],e[7]) for e in trace if e[0]==1];require((r.status,r.current_sp,r.next_segment,r.next_ip,r.events,r.bytes,r.bus_writes,r.returned.bp,r.returned.registers.di,r.returned.registers.ax,r.returned.registers.cx,r.returned.registers.dx,r.returned.registers.es,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,8006,8000,8002,0x5678,0x4567,0x1200,0,0x3cf,0xa000,0,1,0),'FullSSFNs/portresponseGPRignored');require(ports==[(0x3ce,5),(0x3cf,2),(0x3c4,2),(0x3c5,15),(0x3ce,5),(0x3cf,0)] and bytes(bus[0xa0000:0xa1f40])==b'\x34'*8000 and bus[0xa1f40]==0,'Literalports/rawRAM8000bytes');vectors+=1
 reset(df=1);run();device=[e for e in trace if e[0]==3];require((r.status,r.returned.registers.direction,device[0][9],device[1][9],device[-1][9],trace[-2][10][5],bus[0xa0000],bus[0xa0001],bus[0xae0c0],bus[0xae0c1])==(0,1,0xa0000,0xaffff,0xae0c1,0xe0c0,0x34,0,0,0x34),'DF1offsetwrap/notforwardmemset');vectors+=1
 reset(value=0x80ff);run();require((r.status,r.returned.registers.ax,bus[0xa0000])==(0,0x8000,0xff),'ALfillrawbyte/AHretainedthroughlastports');vectors+=1
 mode=1;reset();run();require((r.status,r.returned.registers.ax,bus[0xa0000])==(0,0xab00,0xcd),'Portadapterbusmutationbeforeargumentread');vectors+=1;mode=0
 reset(ss=0xa000,sp=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.di)==(0,4,0x3434,0x3434,0x5678,0x4567),'Forwardfillaliasesactualfarwords');vectors+=1
 reset(df=1,ss=0xa000,sp=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.di)==(0,4,0x2222,0x1134,0x3434,0x3434),'Reversefillaliasesactualsaves-and-onefarbyte');vectors+=1
 reset(df=1,ss=0xa000,sp=0xffff);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.di)==(5,0xffff,0x16c9,0x843d,0x3434,0x3434),'Unqualifiedfarframeprefixafterallfill-ports-savedPOPs');vectors+=1
 for sp in [0xfffd,0xfffe]:
  reset(sp=sp);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bytes,r.events)==(5,sp,0x16c9,0x843d,8000,8006),'Fullwork-beforeunqualifiedfarRET '+str(sp));vectors+=1
 mode=2;reset();run();require((r.status,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.di)==(0,0x369c,0x1357,0x2468,0xabcd),'Lateportbusmutation/actualsavedwords-reread');vectors+=1;mode=0
 reset();run(cb=null);require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes)==(4,0x8418,0,0,2),'Missingadapternotoriginalfailure');vectors+=1
 mode=3;reset();run();require((r.status,r.next_ip,r.events,r.bytes,r.bus_writes)==(4,0x8422,2,0,2),'RejectedOUTbeforeinstruction/nocleanup');vectors+=1;mode=0
 mode=4;reset();run();require((r.status,r.next_ip,r.events,r.bytes,r.returned.registers.di,r.returned.registers.cx)==(4,0x842f,4,0,0,8000),'RejecteddevicewritebeforeREPadvance');vectors+=1;mode=0
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_plane_fill.py','sha256':hashlib.sha256((ROOT/'tools/validate_plane_fill.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/exactsetup-fill-restoreeventprefixes/8000rawRAMbytes/literalOUTs/portresponseGPRignored/AL-AH/DF1offsetwrap/SSargumentafterports/forward-reverse-fillfarframe-savesaliases/lateportbusmutation/SPFFFD-FFFFunqualifiedfarRETprefixafterfullwork/adapterrejectprefixes only. Originalcomparison separate; no EGAplanar-register-latchhardwareeffects/renderer/actualcaller-DF-IF-storage/writers/capacity/CPU-A20/IRQ/core/resource/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
