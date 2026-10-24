"""Native0BE8 fixedheapcount/AX-onlystream/signedmetadata/orderedaliases/nearRET."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_stream_buffer import Registers,StateRegisters,Request,Limits,PublicLimits,WalkLimits,Result,Service,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_stream_buffer;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x2000,0x4000,0,1),0x5678,0);r=Result();vectors=0;null=Service();limits=Limits(1,PublicLimits(2,WalkLimits(8,128,8,64,1,1,1,32,8)))
 for memory,count,sp,state,bounds in [(bus,len(bus)-1,60,C.byref(s),C.byref(limits)),(bus,len(bus),59,C.byref(s),C.byref(limits)),(bus,len(bus),0xffff,C.byref(s),C.byref(limits)),(None,len(bus),60,C.byref(s),C.byref(limits)),(bus,len(bus),60,None,C.byref(limits)),(bus,len(bus),60,C.byref(s),None)]:
  fn(memory,count,0x1000,0x9000,sp,state,bounds,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and r.flags_valid==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,60,C.byref(s),C.byref(limits),null,None,C.byref(r));require(r.status==2 and r.bus_writes==0,'Invalid '+field);setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,60,C.byref(s),C.byref(limits),null,None,None);require(not any(bus),'Nullresult');vectors+=1
 def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|bus[(at+1)&0xfffff]<<8
 def reset(channel=0,failed=False,stream=0x1200):
  C.memset(bus,0,len(bus))
  for o,v in [(0x6f26,0 if failed else 0x3000),(0x6f28,0x3000),(0x6f2c,16),(0x6f2e,0),(0x6f30,0x2000),(0x6f36,0),(0x3000,0x405),(0x6d2a,0xffff if failed else 16),(0x6d2c,0x2000),(0x6d24,0xffff),(0x6d9b,0x2000),(stream,0xa55a),(stream+2,0x1357),(stream+4,0x2468)]:put(0x2000,o,v)
  bus[0x20000+stream+6]=0;bus[0x20000+stream+7]=channel;put(0x9000,60,0x1111);put(0x9000,62,stream)
 def run(calls=1,public=2,iterations=128,cb=null):
  limits.calls=calls;limits.public_heap.calls=public;limits.public_heap.walk.iterations=iterations;fn(bus,len(bus),0x1000,0x9000,60,C.byref(s),C.byref(limits),cb,None,C.byref(r))
 reset();run(calls=0);require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.returned.bp,r.returned.registers.ax,word(0x9000,54))==(3,0x0bf0,54,3,58,0x200,0x200),'Actualrootprologue/fixedcount200/beforefarCALL');vectors+=1
 reset();run(public=0);require((r.status,r.next_ip,r.current_sp,r.calls,r.flags_valid)==(3,0x26e5,44,1,0),'Actualfarframe/publicprologue/beforeheapCALL');vectors+=1
 reset();run(iterations=0);require((r.status,r.next_ip,r.current_sp,r.public_calls,r.heap_calls,r.flags_valid)==(3,0x2700,42,1,0,0),'Actualnestednearframe/CLDprefix');vectors+=1
 for channel in [0,19,127,128,255]:
  reset(channel);run();index=6*(channel if channel<128 else channel-256);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.returned.bp,r.returned.registers.si,r.returned.registers.ax,r.returned.registers.dx,word(0x2000,0x1200),word(0x2000,0x1202),word(0x2000,0x1204),bus[0x21206],word(0x2000,0x6e96+index),r.returned.carry,r.zero_flag)==(0,62,0x23a8,0x1111,0x5678,0x3456,0x3002,0x2000,0x3002,0,0x3002,8,0x200,int(channel>=128),int(channel==0)),'AX-onlystream/signedmetadataindex '+str(channel));vectors+=1
 for channel in [0,19,128,255]:
  reset(channel,failed=True);run();index=6*(channel if channel<128 else channel-256);fallback=(0x6e95+index)&65535;require((r.status,r.returned.registers.ax,r.returned.registers.dx,word(0x2000,0x1200),word(0x2000,0x1204),bus[0x21206],word(0x2000,0x6e96+index),r.returned.carry,r.zero_flag)==(0,fallback,0,fallback,fallback,4,1,int(channel>=128),0),'Failurefallback/signedindex/size1 '+str(channel));vectors+=1
 reset(stream=0x6e92);run();require((r.status,r.returned.registers.ax,word(0x2000,0x6e96),word(0x2000,0x6e92),word(0x2000,0x6e94))==(0,0x200,0x200,0x200,0),'Metadatawritealiasesstreampointer beforefinalreread');vectors+=1
 record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_stream_buffer.py','sha256':hashlib.sha256((ROOT/'tools/validate_stream_buffer.py').read_bytes()).hexdigest()}],'limits':'Nativeinterfaces/realnestedSSframes/fixedcount200/AX-onlystream/signedbyteindex/success200-fallback1/sourceorderedmetadataalias/actualnearRET andbudgets only. Originalcomparison separate; syntheticDOSnoINTframes/historicalCPU-A20unqualified, wholecallers/writers/capacity/ownership/lifetime/exclusion/core/session/fidelity open.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
