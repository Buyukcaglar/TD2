"""Motion rawFLAGS rejection, actual far frames, clamps and prefix diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_motion_flags_bus import Registers,StateRegisters,Result,require

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 fn=C.CDLL(str(lib)).td2ega_motion_flags_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
 bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x8000,0,0),0x5678,0);r=Result();vectors=0
 invalid=[(None,len(bus),0xe000,2,0xffff,C.byref(s)),(bus,len(bus)-1,0xe000,2,0xffff,C.byref(s)),(bus,len(bus),0xe000,2,0xffff,None),(bus,len(bus),19,2,0xffff,C.byref(s)),(bus,len(bus),0xffe1,2,0xffff,C.byref(s)),(bus,len(bus),0xe000,0,0xffff,C.byref(s)),(bus,len(bus),0xe000,0x102,0xffff,C.byref(s)),(bus,len(bus),0xe000,0x1002,0xffff,C.byref(s)),(bus,len(bus),0xe000,2,0xffdf,C.byref(s)),(bus,len(bus),0xe000,3,0xffff,C.byref(s)),(bus,len(bus),0xe000,0x202,0xffff,C.byref(s)),(bus,len(bus),0xe000,0x402,0xffff,C.byref(s))]
 for m,n,sp,f,mask,state in invalid:
  fn(m,n,0x1000,0x9000,sp,f,mask,state,1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,2,0xffff,C.byref(s),1,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,2,0xffff,C.byref(s),1,None);require(not any(bus),'Nulloutput');vectors+=1
 def put(sg,o,v,width=2):
  at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255
  if width==2:bus[(at+1)&0xfffff]=(v>>8)&255
 def word(sg,o):
  at=((sg<<4)+(o&65535))&0xfffff;return bus[at]|(bus[(at+1)&0xfffff]<<8)
 for mask in [0xffff,0xffef]:
  C.memset(bus,0,len(bus));put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222)
  fn(bus,len(bus),0x1000,0x9000,0xe000,2,mask,C.byref(s),0,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.flags_word,r.flags_mask)==(3,0xdff2,0x16b3,0x114,0,8,0x46,0xffff),'BeforeCALLNEGDXfullflags');require(word(0x9000,0xe000)==0x1111 and word(0x9000,0xe002)==0x2222,'Prefixrootframe');vectors+=1
  fn(bus,len(bus),0x1000,0x9000,0xe000,2,mask,C.byref(s),1,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.flags_word,r.flags_mask,r.flags_valid,r.zero_flag)==(0,0xe004,0x2222,0x1111,1,13,3,0xffff,1,0),'ActualRETF8thenrootplainRETF/fullterminalCMP');vectors+=1
 # Lowerclamp changes data toF180; originalCMP8000,F180 stillreturnsCF1/ZF0/SF1.
 C.memset(bus,0,len(bus));put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222);put(0x5000,0x2f46,0x8000);put(0x5000,0x3322,1)
 fn(bus,len(bus),0x1000,0x9000,0xe000,2,0xffef,C.byref(s),1,C.byref(r));require(r.status==0 and word(0x5000,0x2f46)==0xf180 and r.flags_word==0x83 and r.flags_mask==0xffff,'PreclampoperandFLAGSretained');vectors+=1
 # DampingterminalSUBAXAX defines allarithflags andpreservesIFDF.
 C.memset(bus,0,len(bus));put(0x9000,0xe000,0x1111);put(0x9000,0xe002,0x2222);put(0x5000,0x336e,1,1);put(0x5000,0x2f46,0x100);s.registers.interrupts_enabled=1;s.registers.direction=1;s.carry=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0xed7,0xffef,C.byref(s),1,C.byref(r));require((r.status,r.calls,r.flags_word,r.flags_mask,r.returned.carry,r.zero_flag)==(0,0,0x646,0xffff,0,1),'DampingSUBfullflags/IFDFpreserved');vectors+=1
 deps=['tools/validate_motion_flags_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonlyinvalidbeforeeffects/rawFLAGS-mask-Stateconsistency/nulloutput/actualSSargumentandfarframes/budgetprefixNEGDX/actualRETF8thenplainRETF/terminalpreclampCMPversusdampingSUB/fullFLAGSdefined/IFDFpreserved. Originalequivalence separate; whole420A-403B/caller-writers-domain-capacity-lifetime-IRQ-core/game/fidelity open.'}
 out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
