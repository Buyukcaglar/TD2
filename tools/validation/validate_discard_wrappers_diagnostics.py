"""Native0083/38D4 actual782C-7490/shared budgets/delayed cleanup/far frame effects."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_discard_wrappers import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_discard_wrappers;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,1,0),0x5678,1);r=Result();vectors=0;ss=0x9000;sp=0xe000
 for memory,count,state,entry in [(bus,len(bus)-1,C.byref(s),0),(None,len(bus),C.byref(s),0),(bus,len(bus),None,0),(bus,len(bus),C.byref(s),2)]:
  fn(memory,count,0x1000,ss,sp,entry,state,4,64,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,ss,sp,0,C.byref(s),4,64,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,ss,sp,0,C.byref(s),4,64,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(stack=0x9000,pointer=0xe000,obj=0x6000,df=0):
  nonlocal ss,sp
  ss,sp=stack,pointer;C.memset(bus,0,len(bus));s.registers.direction=df;put(0x6c66,0x7000,0x2000);put(0x6c68,0x705a,0x2000)
  for index in range(6):put(0x7000+index*18+0xe,obj if index==5 else 0x6001 if index==1 else 0x3000+index,0x2000);put(0x7000+index*18+0x10,1,0x2000)
  put(0x202,0xffff,obj);put(0x202,0,0x6001);put(0x100,0x200,0x5000);put(0x102,obj,0x5000);put(0x104,0x200,0x5000);put(0x106,0x6001,0x5000)
  for off in [0x9b2,0x2f60]:put(off,0x100,0x2000);put(off+2,0x5000,0x2000)
  put(0x2f68,0x104,0x2000);put(0x2f6a,0x5000,0x2000);put(0xb269,0x10,0x16c9);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 def run(entry=0,calls=4,scans=64):fn(bus,len(bus),0x1000,ss,sp,entry,C.byref(s),calls,scans,C.byref(r))
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.scans,r.trims,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.es,r.returned.bp,r.returned.registers.ds,r.returned.registers.si,r.returned.registers.di)==(0,0xe004,0x2222,0x1111,2,1,1,18,0x6000,0xfff8,0x5000,0x5678,0x2000,0x3456,0x4567),'0083fullcomposition/fullSSstate');vectors+=1
 reset();run(entry=1);require((r.status,r.current_sp,r.calls,r.scans,r.trims,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.carry)==(0,0xe004,4,5,1,35,0x6001,0xffde,0) and [word(o,ss) for o in [0xdffc,0xdffe,0xdff8,0xdffa]]==[0x100,0x5000,0x104,0x5000],'38D4firstargsretained/secondargsdeferredADDSP8');vectors+=1
 for entry,site in [(0,0x8b),(1,0x38dc)]:
  reset();run(entry=entry,calls=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes)==(3,site,0xdffc,0,2),'OuterCALLbudgetafteractualargPUSHs');vectors+=1
 reset();run(calls=1);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes)==(3,0x7858,0xdfec,1,11),'SharedCALLbudgetatnested7490');vectors+=1
 reset();run(entry=1,calls=2);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes,r.scans,r.trims)==(3,0x38e9,0xdff8,2,20,1,1),'SecondouterCALLbudget/firstargsretained');vectors+=1
 reset();run(entry=1,calls=3);require((r.status,r.next_ip,r.current_sp,r.calls,r.bus_writes,r.scans,r.trims)==(3,0x7858,0xdfe8,3,29,1,1),'SecondnestedCALLbudgetglobalnotreset');vectors+=1
 reset();run(entry=1,scans=1);require((r.status,r.next_ip,r.calls,r.scans,r.trims,r.bus_writes,word(0x706a,0x2000))==(3,0x74c3,2,1,0,17,0),'Sharedsearch-trimbudget-firstpartialcommit');vectors+=1
 reset();run(entry=1,scans=2);require((r.status,r.next_ip,r.calls,r.scans,r.trims,r.bus_writes)==(3,0x749c,4,1,1,34),'Globalscanbudgetexhaustedbeforesecondsearch');vectors+=1
 reset(df=1);run(entry=1);require((r.status,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,1,1),'IFDFretainedthroughallchildren');vectors+=1
 reset();put(0x102,0x6666,0x5000);run(entry=1);require((r.status,r.next_ip,r.calls,r.scans,r.bus_writes,word(r.current_sp,ss),word(r.current_sp+2,ss))==(6,0x74b3,2,6,18,0x65a5,0x6666),'FirstfatalprefixpreventssecondCALL');vectors+=1
 for entry in [0,1]:
  reset(stack=0x2000,pointer=0x7082,obj=0x7078);run(entry=entry);require((r.status,r.next_segment,r.next_ip,r.calls)==(1,0x16c9,0,2),'Statusaliasesnested7490farIP');vectors+=1
  reset(stack=0x2000,pointer=0x7072,obj=0x5678);run(entry=entry);require((r.status,r.next_segment,r.next_ip,r.calls)==(1,0x16c9,0,2),'Statusaliases782CfarIP');vectors+=1
  reset(stack=0x2000,pointer=0x706a,obj=0x5000);run(entry=entry);require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0),'StatusaliaseswrapperrootfarIP');vectors+=1
  reset(stack=0x2000,pointer=0x7068,obj=0x1111);run(entry=entry);require((r.status,r.next_segment,r.next_ip)==(0,0,0x1111),'StatusaliaseswrapperrootfarCS');vectors+=1
  reset(stack=0x16c9,pointer=0xb269);run(entry=entry);require((r.status,r.next_segment,r.next_ip)==(0,0x2222,0x10f9 if entry==0 else 0x10df),'CSwordaliaseswrapperrootfarIP');vectors+=1
 for entry,pointer in [(0,0),(0,3),(1,0),(1,4)]:
  reset(pointer=pointer);run(entry=entry);require((r.status,r.returned.carry,r.current_sp)==(0,1,pointer+4),'FinaldeferredADDcarry');vectors+=1
 for entry,pointer,site in [(0,5,0x7864),(1,5,0x7864),(0,21,0x74d3),(1,25,0x74d3),(0,0xfffd,0x93),(1,0xfffd,0x38f1)]:
  reset(pointer=pointer);run(entry=entry);require((r.status,r.next_ip)==(5,site),'QualifiedpreRETlevel '+hex(site));vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_discard_wrappers.py','sha256':hashlib.sha256((ROOT/'tools/validate_discard_wrappers.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/actual782C-7490/fullSS/globalCALL-search-trimbudgets/entry1firstargsretained-ADDSP8/firstfatalprefix/threelevelreturnaliases/currentCSwordaliases/IFDF/finalcarry/child-rootpreRETqualifications only. Originalcomparison/staticproofsseparate; no callerwriters-storage-lifetime-exclusion/CPU-A20/fatalcleanup/core/resources/session/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
