"""Native-only rejection checks for the logic entry/frame interface."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from validate_sprite_draw import Registers,StateRegisters,Result,Service,require

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();library=args.library.resolve();output=args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths')
    dll=C.CDLL(str(library));draw=dll.td2ega_sprite_logic;resume=dll.td2ega_sprite_logic_kernel
    for fn in [draw,resume]:
        fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();incoming=StateRegisters(Registers(0,0,0,0,0,0,0x278f,0,1,1),0x5678,1);result=Result();calls=[]
    def callback(*unused):calls.append(1);return 1
    adapter=Service(callback)
    for fn,count,sp,entry,service in [(draw,len(bus)-1,0xe000,0,adapter),(draw,len(bus),0xe000,3,adapter),(draw,len(bus),256,0,adapter),(resume,len(bus),0xfff0,0x7dec,adapter),(draw,len(bus),0xe000,0,Service())]:
        fn(bus,count,0x1000,0x9000,sp,entry,C.byref(incoming),service,None,512,C.byref(result))
        require(result.status==2 and result.work==result.calls==result.writes==0 and not calls and not any(bus),'Invalid profile before effects')
    incoming.carry=2
    draw(bus,len(bus),0x1000,0x9000,0xe000,0,C.byref(incoming),adapter,None,512,C.byref(result))
    require(result.status==2 and result.work==result.calls==result.writes==0 and not calls and not any(bus),'Invalid carry before effects')
    record={'schema':1,'result':'pass','vectors':6,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sprite_draw.py','sha256':hashlib.sha256((ROOT/'tools/validate_sprite_draw.py').read_bytes()).hexdigest()}],'limits':'Six native-only invalid bus/entry/root-frame/resume-frame/adapter/flag checks. Separate from original far returns, raw control transfers and work prefixes; no actual device/renderer/IRQ/core/gameplay/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'result':'pass','vectors':6}))

if __name__=='__main__':main()
