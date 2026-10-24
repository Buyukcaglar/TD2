"""Native-only defined-mask interface, return-path and AF-unknown checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_flags import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');fn=C.CDLL(str(lib)).td2ega_record_flags;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0,0,8,0,0,0,0x4000,0,0,0),0x3813,0);r=Result()
 for memory,count,sp,state in [(bus,len(bus)-1,16,C.byref(s)),(bus,len(bus),15,C.byref(s)),(bus,len(bus),0xffff,C.byref(s)),(None,len(bus),16,C.byref(s)),(bus,len(bus),16,None)]:
  fn(memory,count,0x1000,0x9000,sp,state,128,C.byref(r));require(r.body.status==2 and r.defined_mask==0 and r.return_site==0 and not any(bus),'Invalid beforeeffects')
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),128,C.byref(r));require(r.body.status==2 and r.defined_mask==0,'Invalid '+field);setattr(target,field,0)
 fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),128,None);require(not any(bus),'Nullout no effects')
 def put(at,v):bus[at]=v&255;bus[at+1]=v>>8
 put(0x90010,0x1111);bus[0x433b9]=1;fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),0,C.byref(r));require((r.body.status,r.body.next_ip,r.defined_mask,r.return_site)==(3,0x4fda,0x603,0),'PrefixdoesnotclaimunmodeledstatusFLAGS')
 put(0x43815,0xfff0);put(0x43817,0);fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),128,C.byref(r));require(r.body.status==0 and r.return_site==0x4fa9 and r.body.returned.registers.ax==0 and (r.defined_flags&0x40)==0 and r.defined_mask==0xed7,'AX0withZF0 reject')
 s.registers.ax=0xa55a;s.registers.dx=0xffff;put(0x43815,0xffff);put(0x43817,0xa55a);bus[0x433b9]=0;bus[0x433b4]=1;fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),128,C.byref(r));require(r.body.status==0 and r.return_site==0x5021 and r.body.returned.registers.ax!=0 and (r.defined_flags&0x40)!=0 and r.defined_mask==0xed7,'NonzeroAXwithZF1 skip')
 s.registers.ax=s.registers.dx=0;put(0x43815,0);put(0x43817,0);bus[0x433b9]=1;fn(bus,len(bus),0x1000,0x9000,16,C.byref(s),128,C.byref(r));require(r.body.status==0 and r.return_site==0x5016 and r.defined_mask==0xec7 and (r.defined_mask&0x10)==0 and (r.defined_flags&0x44)==0x44,'XORreturnAFunknown/notclaimedzero')
 record={'schema':1,'result':'pass','vectors':13,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_record_flags.py','sha256':hashlib.sha256((ROOT/'tools/validate_record_flags.py').read_bytes()).hexdigest()}],'limits':'Eightinvalid/noeffects, nullout, prefixmask andthree returnpath/mask/AX-ZF discriminators. Nativeonly; definedFlags/mask notrawPUSHF, CPUreserved/undefinedimage/stackwordownership/POPF/wholeparent/core/IRQ/runtime/gameplay/fidelity remainseparate.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':13}))
if __name__=='__main__':main()
