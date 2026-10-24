"""Compare six near control entries and actual4612 with synthetic shared data."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_sim_targets import Result as Registers,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class ScanResult(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','target','di','direction']]+[('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));functions={name:getattr(dll,'td2ega_'+name) for name in ['decelerate_target','decelerate_fixed','adjust_scaled_target','update_limit_counter','update_interval_state']}
    for fn in functions.values():fn.argtypes=[C.POINTER(C.c_uint8),C.POINTER(Registers),C.POINTER(Registers)];fn.restype=None
    scan=dll.td2ega_small_control_dispatch;scan.argtypes=[C.POINTER(C.c_uint8),C.POINTER(C.c_uint8),C.POINTER(Registers),C.c_uint16,C.c_uint16,C.POINTER(ScanResult)];scan.restype=None
    entries={'scan':0x44a6,'decelerate_target':0x45fc,'decelerate_fixed':0x44d8,'adjust_scaled_target':0x45bf,'update_limit_counter':0x4639,'update_interval_state':0x4afa};coverage=Counter();vectors=instructions=0;ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536));boundary=[0,1,4,5,6,29,30,31,63,64,95,96,99,100,559,560,599,600,639,640,641,0x7ffe,0x7fff,0x8000,0x8001,0xfffe,0xffff]
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;starts=set();active={}
        for ip,length in [(0x44a6,68),(0x45bf,122),(0x4639,59),(0x4afa,99)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            require(address in starts,'Controls escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x44ba:active['target']=struct.unpack('<H',bytes(u.mem_read(ds*16+0x33dc+u.reg_read(UC_X86_REG_BX),2)))[0]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        def compare(kind,changes,category,ax=0xbeef,dx=0x7654,shared=False):
            nonlocal vectors,instructions
            data=bytearray(baseline)
            for at,value,width in changes:
                if width==1:data[at]=value
                else:struct.pack_into('<H',data,at,value)
            es=ds if shared else 0x7000;esdata=bytearray(baseline);esdata[0x33d6:0x33db]=bytes([0,1,0x7f,0x80,0xff])
            if kind=='scan':
                data[0x33d6:0x33db]=bytes([0xff,0x80,0x7f,1,0]);struct.pack_into('<5H',data,0x33dc,0x44bf,0x44c5,0x44c5,0x44d2,0x44d2)
                if shared:esdata=data
            uc.mem_write(ds*16,bytes(data))
            if es!=ds:uc.mem_write(es*16,bytes(esdata))
            uc.mem_write(ss*16+sp-16,b'\xa5'*16+struct.pack('<H',0x100)+b'\xa5'*8);incoming=Registers(ax,0xa55a,0x4567,dx);flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_ES,es)]
            for reg,val in preserved+[(UC_X86_REG_DI,0x2345),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[kind]),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,target=0);uc.emu_start(cs*16+entries[kind],cs*16+0x100,count=256);gb=(C.c_uint8*65536).from_buffer_copy(data)
            if kind=='scan':
                eb=gb if shared else (C.c_uint8*65536).from_buffer_copy(esdata);scanned=ScanResult();scan(gb,eb,C.byref(incoming),0x2345,(flags>>10)&1,C.byref(scanned));result=scanned.registers;di=scanned.di;direction=scanned.direction;require(scanned.status==0 and scanned.target==active['target'],'Scan target/domain')
                if not shared:require(bytes(eb)==bytes(uc.mem_read(es*16,65536)),'ES readview unchanged')
            else:result=Registers();functions[kind](gb,C.byref(incoming),C.byref(result));di=0x2345;direction=(flags>>10)&1
            label=f'{load:x}/{kind}/{category}/{changes}/{ax:x}/{dx:x}/{shared}'
            require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label);require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX))==(result.ax,result.bx,result.cx,result.dx),'Scratch outputs '+label)
            require(uc.reg_read(UC_X86_REG_DI)==di and (uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==direction,'DI/DF '+label);require(uc.reg_read(UC_X86_REG_EFLAGS)&0x200==flags&0x200 and all(uc.reg_read(reg)==val for reg,val in preserved),'IF/preserved '+label);require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'Near return '+label);require(bytes(uc.mem_read(ss*16+sp,10))==struct.pack('<H',0x100)+b'\xa5'*8,'Frame/upperguard')
            coverage[category]+=1;instructions+=active['instructions'];vectors+=1
        for value in range(65536):
            compare('scan',[(0x90a8,value&1,1)],'all_scan_AX_words',ax=value,shared=bool(value&1))
            compare('decelerate_target',[(0x52ce,value,2),(0x2f56,value&1,1)],'all_deceleration_words',dx=0x640)
            compare('update_interval_state',[(0x52cc,value,2),(0x3371,1,1),(0x33d5,0,1),(0x52cf,5,1)],'all_interval_words')
        for value in boundary:
            for amount in boundary:
                for enabled in [0,1]:
                    changes=[(0x52ce,value,2),(0x2f56,enabled,1)];compare('decelerate_target',changes,'deceleration_boundaries',dx=amount);compare('decelerate_fixed',changes,'fixed_deceleration_boundaries',dx=amount)
        for high in range(256):
            for low in [0,1,0xff]:
                for coefficient in [0,1,0x7f,0x80,0xff]:
                    for amount in [0,1,0xff,0x100,0x7fff,0x8000,0xffff]:
                        for control in [0,0xff]:compare('adjust_scaled_target',[(0x52ce,(high<<8)|low,2),(0x324a+(high>>2),coefficient,1),(0x336c,control,1)],'scaled_index_coefficient_boundaries',dx=amount)
        for counter in range(256):
            for value in boundary:
                for lower,upper in [(100,200),(200,100),(0,0xffff),(0x8000,0x7fff)]:compare('update_limit_counter',[(0x33b3,counter,1),(0x332c,value,2),(0x23aa,lower,2),(0x23a8,upper,2)],'counter_signed_DEC_and_limits')
        for value in boundary:
            for mode in range(256):
                for flag,level in [(0,5),(0,6),(1,5)]:compare('update_interval_state',[(0x52cc,value,2),(0x3371,mode,1),(0x33d5,flag,1),(0x52cf,level,1)],'interval_modes_and_thresholds')
        rng=random.Random(0x45bf)
        for _ in range(1024):compare('adjust_scaled_target',[(0x52ce,rng.randrange(65536),2),(0x336c,rng.randrange(256),1),(0x2f56,rng.randrange(256),1)],'varied_scaled_states',dx=rng.randrange(65536))
    gb=(C.c_uint8*65536)();eb=(C.c_uint8*65536)();incoming=Registers(1,0,0,0);eb[0x33da]=1;struct.pack_into('<H',gb,0x33e4,0x1234);diagnostic=ScanResult();scan(gb,eb,C.byref(incoming),0,0,C.byref(diagnostic));require(diagnostic.status==2,'Native unknown target diagnostic')
    record={'schema':1,'function_ids':['FN-EGA-000372','FN-EGA-000373','FN-EGA-000376','FN-EGA-000377','FN-EGA-000379','FN-EGA-000382'],'result':'pass','vectors':vectors,'native_only_diagnostics':1,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_control_ops.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sim_targets.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_targets.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Six complete near controls andactual4612, serialized syntheticsharedgroup anddistinctES scanner views. AllAX/target/intervalword domains, signedDEC overflow, computedindex/coefficient andstateboundaries; rawscanner targettable limitedtothreeobservedhandlers. ActualES/DS callercontext/tablewriters, resourcefield schemas/units, IRQ/fullstate/game/fidelity remainopen; incidentalflags andnativeunknown-target diagnostic separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
