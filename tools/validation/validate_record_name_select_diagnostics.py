"""Native0730 signedcount/lastcasefoldmatch/fallback/sourceSSargs/BSSaliases."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_name_select import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_record_name_select;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,0),0x5678,0);r=Result();vectors=0
 for memory,count,sp,state in [(bus,len(bus)-1,28,C.byref(s)),(bus,len(bus),27,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),28,C.byref(s)),(bus,len(bus),28,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,16,128,8,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,28,C.byref(s),16,128,8,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,28,C.byref(s),16,128,8,None);require(not any(bus),'Nullresult');vectors+=1
 def put(o,v,sg=0x2000):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(o,sg=0x2000):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(count=3,query=b'ab',ss=0x9000,sp=28):
  C.memset(bus,0,len(bus));s.registers.direction=0
  for i,name in enumerate([b'AB',b'ab',b'ZZ']):
   for j,b in enumerate(name+b'\0'):bus[0x20000+0x865c+32*i+j]=b
   put(0x8676+32*i,0x1234+i*0x1111)
  for j,b in enumerate(query+b'\0'):bus[0x29212+j]=b
  put(0x90aa,count);put(0x8a80,0xa55a);put(sp,0x1111,ss);put(sp+2,0x2222,ss)
 def run(calls=16,operations=128,iterations=8,ss=0x9000,sp=28):fn(bus,len(bus),0x1000,ss,sp,C.byref(s),calls,operations,iterations,C.byref(r))
 reset();run(iterations=0);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.iterations,r.bus_writes,word(0x8cfa),word(24,0x9000))==(3,24,0x1000,0x767,0,3,0xffff,0),'Prologue-global-local-beforecountread');vectors+=1
 reset(count=1);run(calls=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.iterations,r.bus_writes,r.returned.registers.ax,r.returned.registers.cx&255)==(3,20,0x752,0,1,5,0x865c,5),'Actualtwoargs/beforefarcasecompare');vectors+=1
 reset(count=1);run(operations=0);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.operations,r.returned.registers.direction)==(3,14,0x23a8,0x2b51,1,0,0),'Actualchildfarframe/PUSHBP/beforeLODSB');vectors+=1
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ax,r.returned.registers.bx,r.returned.carry,r.calls,r.iterations,word(0x8cfa),word(0x8a80),bytes(bus[0x29212:0x29215]))==(0,32,0x2222,0x1111,0x5678,0x3456,0x4567,0x2345,32,0,4,4,1,0x2345,b'ab\0'),'Lastcasefoldmatch/sourcecasecopy/finalword/argsdroppedbyMOVSPBP');vectors+=1
 for count in [0,0x8000,0xffff]:
  reset(count=count,query=b'QQ');run();require((r.status,r.calls,r.iterations,word(0x8cfa),word(0x8a80),bytes(bus[0x29212:0x29215]))==(0,2,1,0,0x1234,b'AB\0'),'Signedcountskip/fallbackrecord0copiedtwice '+str(count));vectors+=1
 reset(query=b'QQ');run();require((r.status,r.calls,r.iterations,word(0x8cfa),word(0x8a80),bytes(bus[0x29212:0x29215]))==(0,5,4,0,0x1234,b'AB\0'),'No-matchfallback/notanallocation-error');vectors+=1
 reset(count=1);run(iterations=1);require((r.status,r.next_ip,r.iterations,r.calls,word(24,0x9000),word(0x8cfa))==(3,0x767,1,1,1,0),'Parentbudgetbeforefinalcounttest');vectors+=1
 reset(count=3,ss=0x2000,sp=0x90ae);run(ss=0x2000,sp=0x90ae);require((r.status,r.calls,r.iterations,word(0x90aa),word(0x8cfa))==(0,2,1,0,0),'ActualSSlocalaliasesmutablecountbeforefirstread');vectors+=1
 reset(count=0,ss=0x2000,sp=0x8a7e);run(ss=0x2000,sp=0x8a7e);require((r.status,r.current_sp,r.next_segment,r.next_ip,word(0x8a80))==(0,0x8a82,0x1234,0x1111,0x1234),'OutputwordaliasesactualrootfarCS');vectors+=1
 reset(count=0,ss=0x2000,sp=0x8d08);put(0x2736,0xa5a5);run(ss=0x2000,sp=0x8d08);require((r.status,word(0x8cfa),r.returned.registers.bx,r.returned.registers.ax,r.returned.carry)==(0,0x8d06,0xa0c0,0xa5a5,1),'ActualchildsavedBPoverwritesindex/tailwrap/SHLCFbit11');vectors+=1
 reset(count=2,ss=0x2000,sp=0x921c);run(ss=0x2000,sp=0x921c);require((r.status,r.next_segment,r.next_ip,r.current_sp)==(1,0x4241,0x783,0x9214),'FixedquerydestinationaliaseschildfarCS/afterRETneverfollowed');vectors+=1
 reset(count=1);s.registers.direction=1;run(operations=0);require((r.status,r.next_ip,r.returned.registers.direction)==(3,0x2b51,1),'IncomingDFnotclearedbeforeactualLODSB');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_name_select.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_name_select.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/actualfarargs-frames/signedcount/lastcasefoldmatch-sourcecase/fallbackzero-negative/no-match/parent-childbudgets/finalargsMOVSPBP/SSlocal-countalias/selectedword-rootfarCSalias/childsavedBP-index-wrap-CF1/query-childfarCSalias/incomingDF only. Originalcomparison separate; validcounts/NUL/record-indexschema/capacity/allwriters/storage/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
