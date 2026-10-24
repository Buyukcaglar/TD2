"""Native843E threepaths/DF/colorwordmutation/byteMUL/fullSS/work/qualification."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_view_fill import Registers,StateRegisters,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_view_fill;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;null=Service();ss=0x9000;sp=0xe000;trace=[];mode=0
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),null,None,256,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(kind=0,width=2,height=2,color=0xffff,planes=None,pointer=0xe000,df=0):
  nonlocal sp
  sp=pointer;C.memset(bus,0,len(bus));trace.clear();s.registers.direction=df
  for offset,v in [(0xaf44,0x4000),(0x4000,0x200),(0xaf46,0),(0xaf48,width),(0xaf4a,0),(0xaf4c,height),(0xaf4e,width if kind==1 else 0x50)]:put(0x16c9,offset,v)
  for i,plane in enumerate(planes if planes is not None else [0xa000]*4 if kind==2 else [0x3000,0x4000,0x5000,0x6000]):put(0x16c9,0xaf3c+2*i,plane)
  for segment in [0x3000,0x4000,0x5000,0x6000,0xa000]:
   for i in range(0x1f0,0x300):bus[(segment<<4)+i]=0x55
  for i,v in enumerate([0x1111,0x2222,color]):put(ss,sp+2*i,v)
 @Service
 def device(context,memory,request,result):
  q=request.contents;trace.append((q.site,q.kind,q.value,q.address,q.incoming.carry));result.contents.returned=q.incoming;result.contents.returned.carry=2;result.contents.returned.registers.direction=2;result.contents.value=0xffff
  if mode==1 and q.site==0x8525:put(0x16c9,0xaf3c,0)
  if q.kind in [3,4]:
   if mode==2:put(ss,q.incoming.bp-8,0)
   if mode==3:memory[((ss<<4)+((q.incoming.bp-0x12)&65535))&0xfffff]=0x80
   if mode==4:put(ss,q.incoming.bp+6,0xffff)
   if mode==5:put(ss,q.incoming.bp-2,1)
   if mode==6:put(ss,sp,0x1357)
  if mode==7:return 0
  if q.kind in [3,4]:
   memory[q.address]=q.value&255
   if q.kind==4:memory[(q.address+1)&0xfffff]=(q.value>>8)&255
  return 1
 def run(limit=256,cb=device):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),cb,None,limit,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.work,r.planes,r.rows,r.ports,r.byte_writes,r.word_writes,r.bus_writes,r.returned.registers.ax,r.returned.registers.es,r.returned.registers.ds,r.returned.registers.si,r.returned.registers.di,r.returned.bp,word(ss,sp+4))==(0,0xe004,0x2222,0x1111,28,4,8,0,16,0,38,0xffff,0x6000,0x2000,0x3456,0x4567,0x5678,0xfff),'Softwarerows/fullSS/wholeSScolorwordshift');vectors+=1
 reset(kind=1);run();require((r.status,r.work,r.planes,r.rows,r.byte_writes,r.word_writes,r.bus_writes,r.returned.registers.dx,word(ss,sp+4))==(0,12,4,0,0,8,17,0xff0f,0xffff),'PackedIMUL-lowword/wordSTOS/DL-onlyshift');vectors+=1
 reset(kind=1,width=3,height=1,color=0xabcd);run();require((r.status,r.byte_writes,r.word_writes,r.returned.registers.dx,word(ss,sp+4))==(0,4,4,0xab0c,0xabcd),'Oddpackedbyte/STOSWplusSTOSB/highDHpreserved');vectors+=1
 reset(kind=2,width=40,height=1,color=0xabcd);run();require((r.status,r.work,r.ports,r.byte_writes,r.word_writes,r.rows,r.returned.registers.ax,word(ss,sp+4))==(0,46,6,40,0,0,0xab00,0xabcd),'Hardwarewidth40BYTE-MUL/colorhighAXretainedthroughreset');vectors+=1
 reset(kind=2,width=40,height=0x100,color=0xabcd);run();require((r.status,r.work,r.byte_writes,r.rows,r.ports,r.returned.registers.ax)==(0,6,0,0,6,0xab00),'Hardwareheight0100lowbyte0/no fill');vectors+=1
 reset(kind=2,width=40,height=0xffff);run(limit=11000);require((r.status,r.work,r.byte_writes,r.ports)==(0,10206,10200,6) and next(e[4] for e in trace if e[1]==3)==1,'Hardware40*DL255/MAX10200/MULCFretained');vectors+=1
 reset(kind=1,width=0xffff,height=0xffff);run();require((r.status,r.word_writes,r.byte_writes)==(0,0,4),'SoftwareIMULsigned-1*-1/lowword1');vectors+=1
 reset(kind=2);run();require((r.status,r.work,r.rows,r.byte_writes,r.ports,r.returned.registers.ax)==(0,12,2,4,6,0xff00),'Hardwarepartialrowpath/byteSTOS');vectors+=1
 for kind in [0,1,2]:
  for df in [0,1]:
   reset(kind=kind,df=df);run();require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1,df),'IFDFretained '+str((kind,df)));vectors+=1
 reset(df=1);run();require([bus[0x30000+o] for o in [0x200,0x1ff,0x24c,0x24b]]==[255]*4 and bus[0x30250]==0x55,'SoftwareDF1/positivecachedstride notnormalized');vectors+=1
 reset(kind=1,df=1);run();require(bytes(bus[0x301fe:0x30202])==bytes([255]*4) and bus[0x30202]==0x55,'STOSWDF1stepsminus2/wordbytesforward');vectors+=1
 for height,rows in [(0,4),(1,4),(2,8),(0x8000,4),(0xffff,4)]:
  reset(width=0,height=height);run();require((r.status,r.rows,r.byte_writes)==(0,rows,0),'Softwaredo-oncewideDECJG '+hex(height));vectors+=1
 reset(planes=[0]*4);run(cb=null);require((r.status,r.work,r.planes,r.bus_writes,word(ss,sp+4))==(0,4,4,22,0xfff),'Allzerosoftwareplanes/stillmutatesSScolor/noadapter');vectors+=1
 for kind,limit,site in [(0,0,0x84e6),(0,1,0x8509),(0,2,0x850b),(1,0,0x849f),(1,1,0x84ba),(2,0,0x8525),(2,4,0x856d),(2,5,0x8570)]:
  reset(kind=kind);run(limit=limit);require((r.status,r.work,r.next_ip)==(3,limit,site),'Pathworkprefix '+str((kind,limit)));vectors+=1
 mode=1;reset(kind=2,width=40,height=1,pointer=0xffff);run();require((r.status,r.next_ip,r.ports,r.returned.registers.es)==(5,0x8560,6,0) and bus[0x200]==255,'LiveESafterports/cachedhardwarepreRETsite');vectors+=1;mode=0
 for kind,bytes_,words in [(0,4,0),(1,0,2),(2,2,0)]:
  mode=2;reset(kind=kind);run();require((r.status,r.byte_writes,r.word_writes)==(0,bytes_,words),'Widthlocalrereadscope '+str(kind));vectors+=1
 mode=3;reset();run();require((r.status,r.planes,r.rows,r.byte_writes,word(ss,sp+4))==(0,1,2,4,0x7fff),'Bytecounter80overflowstops/oneSScolorshift');vectors+=1
 for kind,first,next_,colorword in [(0,0,255,0x7fff),(1,0,0,0xffff),(2,0,0,0xffff)]:
  mode=4;reset(kind=kind,color=0);run();require(r.status==0 and word(ss,sp+4)==colorword,'Colorargaliaspath '+str(kind));require(bus[(0xa0000 if kind==2 else 0x30000)+0x200]==first,'Capturedcurrentcolor '+str(kind));
  if kind<2:require(bus[0x40200]==next_,'Futurecolorpath '+str(kind))
  vectors+=1
 mode=5;reset();run();require((r.status,r.returned.registers.ds)==(0,1),'ActualsavedDSafterfillalias');vectors+=1
 mode=6;reset();run();require((r.status,r.next_ip,r.next_segment)==(0,0x1357,0x2222),'Actualfarframeafterfillalias');vectors+=1;mode=0
 for pointer in range(8,20):
  reset(planes=[0]*4,pointer=pointer);run(cb=null);require((r.status,r.returned.carry,r.current_sp)==(0,1,pointer+4),'FinalADDSP12carry '+str(pointer));vectors+=1
 for kind in [0,2]:
  for pointer in [0xfffd,0xfffe,0xffff]:
   reset(kind=kind,width=0,height=0,pointer=pointer);run();require((r.status,r.current_sp,r.next_ip)==(5,pointer,0x8560 if kind==2 else 0x84d4),'PreRETqualification '+str((kind,pointer)));vectors+=1
 reset();run(cb=null);require((r.status,r.work,r.next_ip)==(4,2,0x850b),'Missingstoreadapterafterplane-rowheads');vectors+=1
 mode=7;reset(kind=2);run();require((r.status,r.work,r.next_ip)==(4,0,0x8525),'Declinedfirstport');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_view_fill.py','sha256':hashlib.sha256((ROOT/'tools/validate_view_fill.py').read_bytes()).hexdigest()}],'limits':'Native843E/fullSS/threepaths/DFretained/packedwordIMULlowword-oddbyte-DLcolor/softwareSSwordcolorshift/wordSTOSDF1/hardwareBYTE-MULheightLow8-MULCF/liveES-afterports/cachedbranchqualifier/SSwidth-counter-color-saves-controlaliases/globalwork/ADDSPcarry only. Originalcomparison/staticproofseparate; no actualcallers-allwriters-geometry-capacities-storage-lifetime-exclusion/realEGA-latches-renderer/CPU-A20/core/resource/CGA/session/fidelity admission.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
