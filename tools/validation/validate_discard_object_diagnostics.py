"""Native782C actual7490/fullSS/far descriptor/cache/counter prefixes and aliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_discard_object import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_discard_object;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;ss=0x9000;sp=0xe000;obj=0x6000
 for memory,count,state in [(bus,len(bus)-1,C.byref(s)),(None,len(bus),C.byref(s)),(bus,len(bus),None)]:
  fn(memory,count,0x1000,ss,sp,state,1,64,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,C.byref(s),1,64,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,C.byref(s),1,64,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(target=3,free=0,stack=0x9000,pointer=0xe000,object_segment=0x6000,df=0):
  nonlocal ss,sp,obj
  ss,sp,obj=stack,pointer,object_segment;C.memset(bus,0,len(bus));s.registers.direction=df
  put(0x6c66,0x7000,0x2000);put(0x6c68,0x705a,0x2000)
  for index in range(6):put(0x7000+index*18+0xe,obj if index==target and target else 0x3000+index,0x2000);put(0x7000+index*18+0x10,0 if index>0 and 5-free<=index<5 else 1,0x2000)
  put(0x202,0xffff,obj);put(0x100,0x200,0x5000);put(0x102,obj,0x5000);put(0xb269,0x10,0x16c9);put(sp,0x1111,ss);put(sp+2,0x2222,ss);put(sp+4,0x100,ss);put(sp+6,0x5000,ss)
 def run(calls=1,scans=64):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),calls,scans,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.scans,r.trims,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.dx,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ds,r.returned.registers.es,r.returned.bp,r.returned.carry)==(0,0xe004,0x2222,0x1111,1,3,0,13,0x6000,0xfff8,0xd789,0x3456,0x4567,0x2000,0x5000,0x5678,0) and word(0xb269,0x16c9)==0xfff8 and word(0x7046,0x2000)==0 and word(0x6c68,0x2000)==0x705a,'Interiorclear/fullstate-SSFNs/counterwrap');vectors+=1
 reset(target=5,free=3);run();require((r.status,r.scans,r.trims,r.bus_writes,word(0x6c68,0x2000))==(0,1,4,14,0x7012),'Toptrim-throughfreepredecessors');vectors+=1
 reset();put(0x7046,0,0x2000);run();require((r.status,r.scans,r.trims)==(0,3,0),'Segmentmatchignoresfreestatus');vectors+=1
 reset();put(0x705a+0xe,obj,0x2000);run();require((r.status,r.scans,r.trims,word(0x7046,0x2000))==(0,1,1,1),'Highestduplicatedsegmentwins');vectors+=1
 reset(target=0);run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.scans,r.trims,r.bus_writes,r.returned.registers.ax,word(r.current_sp,ss),word(r.current_sp+2,ss))==(6,0xdfe6,0x16c9,0x74b3,6,0,14,0x65a5,0x65a5,0x6000),'PreparedfatalpreCALL/excludessentinel/nohandlerfollow');vectors+=1
 reset();run(calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.ds,r.returned.carry)==(3,0x7858,0xdff4,0,7,0x18,0xfff8,0x2000,1),'Counterandargs-beforeCALLbudget');vectors+=1
 reset();run(scans=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.scans,r.bus_writes,word(0xdff0,ss),word(0xdff2,ss))==(3,0x749c,0xdfea,1,0,12,0x785d,0x16c9),'Actualchildfarframe-beforesearchbudget');vectors+=1
 reset(target=5,free=3);run(scans=1);require((r.status,r.next_ip,r.scans,r.trims,r.bus_writes,word(0x706a,0x2000),word(0x6c68,0x2000))==(3,0x74c3,1,0,13,0,0x705a),'Selectedclear-beforetrimbudget');vectors+=1
 reset(target=5,free=3);run(scans=2);require((r.status,r.next_ip,r.scans,r.trims,r.returned.registers.si,r.returned.carry)==(3,0x74c3,1,1,0x7048,0),'Onefreepredecessor-prefix');vectors+=1
 reset(df=1);run();require((r.status,r.returned.registers.direction,r.returned.registers.interrupts_enabled)==(0,1,1),'IFDFunchanged');vectors+=1
 for size in [0,0x7ff2,0x7ff3,0xfff2,0xfff3,0xffff]:
  reset();put(0x202,size,obj);run();require((r.status,word(0xb269,0x16c9),r.returned.registers.bx)==(0,(0x10-2*((size+13)&65535))&65535,(0x10-2*((size+13)&65535))&65535),'Two-stagewordwrap '+str(size));vectors+=1
 reset(target=5,stack=0x2000,pointer=0x707a,object_segment=0x7078);run();require((r.status,r.current_sp,r.next_segment,r.next_ip)==(1,0x706e,0x16c9,0),'StatusaliaseschildfarIP/rawafterRET');vectors+=1
 reset(target=5,stack=0x2000,pointer=0x706a,object_segment=0x5678);run();require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0),'StatusaliasesrootfarIP');vectors+=1
 reset(target=5,stack=0x2000,pointer=0x7068,object_segment=0x1111);run();require((r.status,r.next_segment,r.next_ip)==(0,0,0x1111),'StatusaliasesrootfarCS');vectors+=1
 reset(stack=0x16c9,pointer=0xb269);run();require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0x10f9),'CSwordaliasesrootfarIP');vectors+=1
 reset(stack=0x16c9,pointer=0xb26d);run(scans=4);require((r.status,r.next_ip,r.returned.registers.ds,r.scans)==(6,0x74b3,0x1fe8,1),'CSwordaliasesrootsavedDS-beforechild-zeroedDSmetadatafatal');vectors+=1
 for pointer in [8,9,10,11]:
  reset(pointer=pointer);run();require((r.status,r.returned.carry,r.current_sp)==(0,1,pointer+4),'FinalADDSP4carry/rootSP '+str(pointer));vectors+=1
 for pointer in [13,14,15]:
  reset(pointer=pointer);run();require((r.status,r.current_sp,r.next_ip,r.bus_writes)==(5,(pointer-16)&65535,0x74d3,13),'ChildpreRETqualification');vectors+=1
 for pointer in [0xfffd,0xfffe,0xffff]:
  reset(pointer=pointer);run();require((r.status,r.current_sp,r.next_ip,r.bus_writes)==(5,pointer,0x7864,13),'RootpreRETqualification');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_discard_object.py','sha256':hashlib.sha256((ROOT/'tools/validate_discard_object.py').read_bytes()).hexdigest()}],'limits':'NativeABI/counterwordwrap/livefardescriptor-SSframes/cachematchignorestatus/toptrim/fatalpreCALL/CALL-search-trimbudgets/return-and-savedDSaliases/finalADDSPcarry/preRETqualification only. Originalcomparison/staticproofsseparate; no storage-writers-lifetime-exclusion/historicalCPU-A20/fatalcleanup/core/resources/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
