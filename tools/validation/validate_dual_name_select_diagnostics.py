"""Native0651 dualqueries/lastmatches/fallbacks/IMULDX-CF/SS-BSS-returnaliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_dual_name_select import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_dual_name_select;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,0),0x5678,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,28,C.byref(s)),(bus,len(bus),27,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),28,C.byref(s)),(bus,len(bus),28,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,32,128,8,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,28,C.byref(s),32,128,8,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,28,C.byref(s),32,128,8,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg=0x2000):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg=0x2000):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(count=3,query1=b'ab',query2=b'ZZ',ss=0x9000,sp=28,boundary=False):
  C.memset(bus,0,len(bus));s.registers.direction=0
  for i,name in enumerate([b'AB']*count if boundary else [b'AB',b'ab',b'ZZ']):
   for j,b in enumerate(name+b'\0'):bus[((0x20000+0x8d24+30*i+j)&0xfffff) if 0x8d24+30*i+j<65536 else 0x20000+((0x8d24+30*i+j)&65535)]=b
   put(0x8d3e+30*i,0x1234+i*0x1111)
  for dest,payload in [(0x8428,query1),(0x90b0,query2)]:
   for j,b in enumerate(payload+b'\0'):bus[0x20000+dest+j]=b
  put(0x8a7a,count);put(0x8a82,0xa55a);put(0x9264,0x5aa5);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 def run(calls=32,operations=128,iterations=8,ss=0x9000,sp=28):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),calls,operations,iterations,C.byref(r))
 reset();run(iterations=0);require((r.status,r.current_sp,r.next_ip,r.iterations,r.bus_writes,word(0x9266),word(0x8cfe),word(24,0x9000))==(3,24,0x6ad,0,4,0xffff,0xffff,0),'Twoindexglobals/localbeforecountread');vectors+=1
 reset(count=1);run(calls=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.iterations,r.returned.registers.ax,r.returned.registers.dx,r.bus_writes)==(3,20,0x678,0,1,0x8d24,0,6),'SignedIMUL0/firstqueryargs/beforefarCALL');vectors+=1
 reset(count=1);run(operations=0);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.operations)==(3,14,0x23a8,0x2b51,1,0),'Actualcasecomparefarframe/childoperationprefix');vectors+=1
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.dx,r.returned.carry,r.calls,r.iterations,word(0x9266),word(0x8cfe),word(0x8a82),word(0x9264),bytes(bus[0x28428:0x2842b]),bytes(bus[0x290b0:0x290b3]))==(0,32,0x2222,0x1111,0x5678,0x3456,60,0,0,8,4,1,2,0x2345,0x3456,b'ab\0',b'ZZ\0'),'Separatelastmatches/sourcecasecopies/wordoutputs/signedIMULDxCf');vectors+=1
 for count in [0,1,2,0x8000,0xffff]:
  reset(count=count,query1=b'QQ',query2=b'QQ');run();secondary=1 if count==2 else 0;expected_calls=2*count+2 if count<3 else 2;require((r.status,r.calls,word(0x9266),word(0x8cfe),word(0x8a82),word(0x9264),bytes(bus[0x28428:0x2842b]),bytes(bus[0x290b0:0x290b3]))==(0,expected_calls,0,secondary,0x1234,0x1234+secondary*0x1111,b'AB\0',b'ab\0' if secondary else b'AB\0'),'Primary0/secondarysignedcount>1fallback '+str(count));vectors+=1
 reset(count=1);run(iterations=1);require((r.status,r.next_ip,r.iterations,r.calls,word(24,0x9000))==(3,0x6ad,1,2,1),'TwoqueriesbeforecounterINC/nextcounttestbudget');vectors+=1
 reset(count=3,ss=0x2000,sp=0x8a7e);run(ss=0x2000,sp=0x8a7e);require((r.status,r.calls,r.iterations,word(0x8a7a),word(0x8cfe))==(0,2,1,0,0),'ActualSSlocaloverwritescountbeforefirstread');vectors+=1
 reset(count=0,ss=0x2000,sp=0x9262);run(ss=0x2000,sp=0x9262);require((r.status,r.current_sp,r.next_segment,r.next_ip,word(0x9264))==(0,0x9266,0x1234,0x1111,0x1234),'SecondaryoutputwordaliasesactualrootfarCS');vectors+=1
 reset(count=0,ss=0x2000,sp=0x8d0c);put(0x146a,0xa5a5);run(ss=0x2000,sp=0x8d0c);require((r.status,word(0x8cfe),r.returned.registers.bx,r.returned.registers.dx,r.returned.registers.ax,r.returned.carry)==(0,0x8d0a,0x872c,0xfff2,0xa5a5,1),'SavedBPoverwritesnegativeindex/fullsignedIMUL-DXAX-CF');vectors+=1
 for sp,ip in [(0x8432,0x6d6),(0x90ba,0x719)]:
  reset(count=0,ss=0x2000,sp=sp);run(ss=0x2000,sp=sp);require((r.status,r.next_segment,r.next_ip,r.current_sp)==(1,0x4241,ip,sp-8),'FixedcopydestinationaliaseschildfarCS '+str(sp));vectors+=1
 for count in [1092,1093,1094,1095]:
  reset(count=count,query1=b'AB',query2=b'AB',boundary=True);run(calls=2400,iterations=1200);require((r.status,r.calls,r.iterations,word(0x9266),word(0x8cfe),r.returned.registers.dx,r.returned.carry)==(0,2*count+2,count+1,count-1,count-1,0,int(count-1>1092)),'WholeIMULsignedpositiveboundary '+str(count));vectors+=1
 reset(count=1);s.registers.direction=1;run(operations=0);require((r.status,r.next_ip,r.returned.registers.direction)==(3,0x2b51,1),'IncomingDFnotcleared');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_dual_name_select.py','sha256':hashlib.sha256((ROOT/'tools/validate_dual_name_select.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/twoqueries-lastmatches/primary0-secondarycount>1fallback/signedcount/actualSSFNs-budgetgates/BSSlocal-countalias/output-rootfarCSalias/savedBP-negativeindex-signedIMUL-DX-CF/bothcopydest-childfarCSaliases/whole1092-1093IMULboundary/incomingDF only. Originalcomparison separate; schemas/NUL-capacity/writers/storage/ownership/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
