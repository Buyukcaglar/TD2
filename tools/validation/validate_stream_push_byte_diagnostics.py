"""Native21D6 rawguards/cursorboundary/wordwrap/bytebeforeflags/signedindex/SSFNs."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_stream_push_byte import Registers,StateRegisters,Request,Limits,BufferLimits,PublicLimits,WalkLimits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_stream_push_byte;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,0);r=Result();vectors=0;null=Service();limits=Limits(1,BufferLimits(1,PublicLimits(2,WalkLimits(8,128,8,64,1,1,1,32,8))))
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,70,C.byref(s),C.byref(limits)),(bus,len(bus),69,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),70,C.byref(s),C.byref(limits)),(bus,len(bus),70,None,C.byref(limits)),(bus,len(bus),70,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,70,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,70,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(value=0x1234,flags=1,cursor=0x3003,count=0,base=0x3002,channel=0,ss=0x9000,sp=70):
  C.memset(bus,0,len(bus))
  for o,v in [(0x1200,cursor),(0x1202,count),(0x1204,base),(0x6f26,0x3000),(0x6f28,0x3000),(0x6f2c,16),(0x6f2e,0),(0x6f30,0x2000),(0x6f36,0),(0x3000,0x405),(0x6d2a,16),(0x6d2c,0x2000),(0x6d24,0xffff),(0x6d9b,0x2000)]:put(0x2000,o,v)
  bus[0x21206]=flags;bus[0x21207]=channel
  for i,v in enumerate([0x1111,0x2222,value,0x1200]):put(ss,sp+2*i,v)
 def run(calls=1,buffer=1,cb=null,ss=0x9000,sp=70):
  limits.calls=calls;limits.buffer.calls=buffer;fn(bus,len(bus),0x1000,ss,sp,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 reset(flags=0);run();require((r.status,r.returned.registers.ax,r.returned.carry,r.zero_flag,r.calls,r.bus_writes)==(0,0xffff,0,1,0,3),'Readflagguard/AXFFFFnotnativeerror');vectors+=1
 reset(value=0xffff);run();require((r.status,r.returned.registers.ax,r.zero_flag,r.calls,word(0x2000,0x1200))==(0,0xffff,1,0,0x3003),'FullwordFFFFguard/nooutput');vectors+=1
 reset(cursor=0x3002,count=1);run();require((r.status,r.returned.registers.ax,r.zero_flag,r.returned.carry,r.bus_writes)==(0,0xffff,0,0,3),'Pointerequalsbase/nonzerocountfailureZF0');vectors+=1
 reset();run();require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.di,r.returned.registers.ax,word(0x2000,0x1200),word(0x2000,0x1202),bus[0x23002],bus[0x26e94],r.returned.carry,r.zero_flag)==(0,74,0x2222,0x1111,0x5678,0x3456,0x4567,0x34,0x3002,1,0x34,4,0,1),'Backwardbyte/sideflag/plainfarRETfourframebytes/actualsaves');vectors+=1
 reset(cursor=0x3002,count=0);run();require((r.status,word(0x2000,0x1200),word(0x2000,0x1202),r.bus_writes)==(0,0x3002,1,9),'Boundaryzero-countINCpointerbeforeDEC');vectors+=1
 reset(cursor=0,count=0xffff,base=0x3002);run();require((r.status,word(0x2000,0x1200),word(0x2000,0x1202),bus[0x2ffff])==(0,0xffff,0,0x34),'Rawpointerunderflow/countwrap');vectors+=1
 reset(value=0xfffe,flags=0x51);run();require((r.status,r.returned.registers.ax,bus[0x21206],bus[0x26e94])==(0,0xfe,0x41,0),'FullwordFFFEvalid/flag40skipmetadata');vectors+=1
 reset(value=0,cursor=0x1207,channel=127);run();require((r.status,r.returned.registers.ax,bus[0x21206],bus[0x26e94+762])==(0,0,0,4),'BytewritealiasesflagsbeforeAND-TEST/norevalidation');vectors+=1
 reset(value=0x80,cursor=0x1208,channel=0);run();require((r.status,bus[0x21207],bus[0x26b94],bus[0x26e94])==(0,0x80,4,0),'BytewritealiaseschannelbeforewordCBW/signedindex');vectors+=1
 reset(base=0);run(calls=0);require((r.status,r.current_sp,r.next_ip,r.bus_writes,r.flags_valid)==(3,62,0x21fb,4,0),'ActualargumentPUSH/beforechildnearCALL');vectors+=1
 reset(base=0);run(buffer=0);require((r.status,r.current_sp,r.next_ip,r.calls,r.buffer_calls,r.flags_valid)==(3,54,0x0bf0,1,0,0),'Actualnearframe/childprologue/count/farCALLbudget');vectors+=1
 reset(base=0);run();require((r.status,r.calls,r.buffer_calls,r.public_calls,r.returned.registers.ax,word(0x2000,0x1200),word(0x2000,0x1202),bus[0x23002])==(0,1,1,1,0x34,0x3002,1,0x34),'Actualcompletebuffer-heapcomposition');vectors+=1
 reset(ss=0x2000,sp=0x6e94);run(ss=0x2000,sp=0x6e94);require((r.status,r.current_sp,r.next_segment,r.next_ip,word(0x2000,0x6e94))==(0,0x6e98,0x2222,0x1115,0x1115),'MetadataORaliasesactualfarreturnword/afterallstores');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_stream_push_byte.py','sha256':hashlib.sha256((ROOT/'tools/validate_stream_push_byte.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/rawreadflag-fullwordFFFF-boundarycountguards/wordwrap/backwardbyte-beforeflags-channel/actualsignedindex/near-farSSFNs/fullbuffer-heapcomposition/metadataaliasesrootfarreturn only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, wholecallers/writers/capacity/ownership/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
