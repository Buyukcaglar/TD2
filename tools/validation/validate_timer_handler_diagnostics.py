"""Native-only timer-handler budget/argument/adapter diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_timer_handler import Registers,Port,Call,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    dll=C.CDLL(str(library));fn=dll.td2ega_timer_handler;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,Port,Call,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    load,ds=0x1000,0x278f;m=(C.c_uint8*0x100000)();start=Registers(0,0,0,0,0,0,ds,0,0,0);events=[];reject_port=[False];reject_call=[False]
    def port(ctx,q,v):events.append(['port',q.contents.port]);v.contents.value=0;return not reject_port[0]
    def call(ctx,bus,q,r):
        events.append(['call',q.contents.kind]);C.memmove(r,C.byref(q.contents.registers),C.sizeof(Registers));r.contents.di=0xfffc;return not reject_call[0]
    ps,cb=Port(port),Call(call);out=Result()
    fn(m,len(m),load,C.byref(start),0x202,ps,cb,None,0,C.byref(out));require(out.status==3 and not events and not any(m),'Zero budget no effects')
    start.interrupts_enabled=2;fn(m,len(m),load,C.byref(start),0x202,ps,cb,None,32,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid flags no effects');start.interrupts_enabled=0
    reject_port[0]=True;fn(m,len(m),load,C.byref(start),0x202,ps,cb,None,32,C.byref(out));require(out.status==4 and events==[['port',0x20]] and not any(m),'Rejected PIC request before group updates');reject_port[0]=False;events.clear()
    m[ds*16+0x5e95]=1
    struct.pack_into('<H',m,ds*16+0x5e88,0x1234);struct.pack_into('<H',m,ds*16+0x5e8a,0x5678)
    reject_call[0]=True;fn(m,len(m),load,C.byref(start),0x202,ps,cb,None,32,C.byref(out));require(out.status==4 and out.old_interrupts==1 and struct.unpack_from('<2H',m,0x20)==(0x1234,0x5678),'Rejected old ISR retains installed IVT prefix');reject_call[0]=False;events.clear()
    m[ds*16+0x5e95]=0;struct.pack_into('<2H',m,ds*16+0x5f12,0x100,0x7000)
    fn(m,len(m),load,C.byref(start),0x202,ps,cb,None,32,C.byref(out));require(out.status==3 and out.steps==32 and out.callbacks==31,'Callback DI cycle is diagnostic without five-row clamp')
    record={'schema':1,'result':'pass','vectors':5,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_timer_handler.py','sha256':hashlib.sha256((ROOT/'tools/validate_timer_handler.py').read_bytes()).hexdigest()}],'limits':'Five native-only API/budget/adapter diagnostics. No original instruction/IRQ/PIC/BIOS executes; excluded from differential totals/original error equivalence.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
