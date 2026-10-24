"""Native-only rejection and DEC80/poststore-table intent checks."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_fields_bus import Registers,StateRegisters,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_sample_fields_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*4+[C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();state=StateRegisters(Registers(0,0xb123,0,0,0,0,0x5000,0,0,0),0,0);r=Result();vectors=0
 for memory,count,sp,e,s in [(None,len(bus),0xe000,0,C.byref(state)),(bus,len(bus)-1,0xe000,0,C.byref(state)),(bus,len(bus),0xffff,0,C.byref(state)),(bus,len(bus),0xe000,2,C.byref(state)),(bus,len(bus),0xe000,0,None)]:
  fn(memory,count,0x1000,0x9000,sp,e,s,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=state if field=='carry' else state.registers;setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,0);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),None);require(not any(bus),'Nulloutput');vectors+=1
 bus[0x523aa]=1;bus[0x533b3]=0x80;bus[0x9e000]=0x11;bus[0x9e001]=0x11;fn(bus,len(bus),0x1000,0x9000,0xe000,1,C.byref(state),C.byref(r));require((r.status,r.bus_writes,r.returned.registers.bx,r.returned.carry,r.zero_flag,bus[0x533b3])==(0,0,0xb17f,1,0,0x80),'DEC80JLtakesoverflowbranch');vectors+=1
 bus[0x5332a]=0xa0;bus[0x5332b]=0x48;fn(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(state),C.byref(r));require(r.status==0 and r.returned.registers.bx==0x4840 and bytes(bus[0x5332a:0x5332c])==b'\x40\x48' and bytes(bus[0x55fd8:0x55fda])==b'\x40\x48','Storebeforetablealias');vectors+=1
 deps=['tools/validate_sample_fields_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Elevennative-onlyinvalid/null/DEC80-JL-overflow/post332Astore-tablealias intentchecks. Separatefromoriginalequivalence/whole403B/caller-platform-IRQ-core/game-fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
