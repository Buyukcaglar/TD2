"""Native-only keyboard argument/flag/port-failure diagnostics."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_keyboard import Registers,Port,Result,require


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    dll=C.CDLL(str(library));install=dll.td2ega_keyboard_install;install.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),Port,C.c_void_p,C.POINTER(Result)];restore=dll.td2ega_keyboard_restore;restore.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Registers),Port,C.c_void_p,C.POINTER(Result)];irq=dll.td2ega_keyboard_irq;irq.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,Port,C.c_void_p,C.POINTER(Result)];bios=dll.td2ega_keyboard_bios;bios.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint16,C.POINTER(Result)]
    for fn in [install,restore,irq,bios]:fn.restype=None
    m=(C.c_uint8*0x100000)();r=Registers(0x100,0,0,0,0,0,0x278f,0,2,0);out=Result();events=[];reject_at=[1]
    def port(ctx,q,v):events.append([q.contents.operation,q.contents.port]);v.contents.value=0x55;return len(events)!=reject_at[0]
    cb=Port(port);install(m,len(m),0x16c9,C.byref(r),cb,None,C.byref(out));require(out.status==2 and not events and not any(m),'Invalid flag has no effects');r.interrupts_enabled=0
    bios(m,len(m),0x1000,C.byref(r),0x202,0x202,C.byref(out));require(out.status==2 and not events and not any(m),'Entryflag/register mismatch has no effects')
    restore(m,len(m),C.byref(r),cb,None,C.byref(out));require(out.status==4 and events==[[0,0x21]] and not any(m),'Rejected initial PIC read has no writes');events.clear();reject_at[0]=3
    irq(m,len(m),0x1000,C.byref(r),0x202,cb,None,C.byref(out));require(out.status==4 and events==[[0,0x60],[0,0x61],[1,0x61]] and not any(m),'Rejected latch write precedes key-state/EOI effects')
    record={'schema':1,'result':'pass','vectors':4,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_keyboard.py','sha256':hashlib.sha256((ROOT/'tools/validate_keyboard.py').read_bytes()).hexdigest()}],'limits':'Four native-only API/port diagnostics. No original instruction/PIC/keyboard/BIOS/IRQ executes; excluded from original differential totals/error equivalence.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
