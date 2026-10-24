"""Exhaustively compare6585 key words and complete16FC:0002 installer.

Synthetic group data only. No keyboard IRQ, callback body or device executes.
"""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Binding(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','wrote','extended_read','write_offset','ax','bx']]


class Install(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','writes','ax','bx','dx']]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_key_binding;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(Binding)];native.restype=None;install=dll.td2ega_key_install;install.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Install)];install.restype=None
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000;seed=bytes((i*37+11)&255 for i in range(65536));keys=[0xa,0xb,0x10,0x11,0x13,0x18];callbacks=[0x645a,0x646f,0x6508,0x64c7,0x6488,0x6518]
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;installer_cs=load+0x16fc;starts=set();active={}
        for segment,ip,length in [(0x6c9,0x6585,47),(0x16fc,2,121)]:
            first=segment*16+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write((load+segment)*16+ip,bytes(code));starts.update((load+segment)*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            require(address in starts,'Binding escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x6585:active['calls'].append(list(struct.unpack('<3H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,6)))))
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        def writer(u,access,address,size,value,_):
            if ds*16<=address<ds*16+65536:require(size==2,'Binding word writer');active['writes'].append((address-ds*16,value&65535))
            else:require(ss*16+sp-40<=address and address+size<=ss*16+sp+10,'Unexpected binding CPU writer')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_MEM_WRITE,writer)
        uc.mem_write(ds*16,seed);gb=(C.c_uint8*65536).from_buffer_copy(seed);expected=bytearray(seed);prior=None
        preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234),(UC_X86_REG_CX,0x7654)]
        for key in range(65536):
            if prior is not None:
                uc.mem_write(ds*16+prior,seed[prior:prior+2]);gb[prior:prior+2]=seed[prior:prior+2];expected[prior:prior+2]=seed[prior:prior+2]
            callback=key^0xa55a;ignored_segment=key^0x1357;flags=2|((key&1)<<10)|(((key>>1)&1)<<9)
            uc.mem_write(ss*16+sp,struct.pack('<5H',0x100,0xa000,key,callback,ignored_segment))
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6585),(UC_X86_REG_SP,sp),(UC_X86_REG_DX,0x4567),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,calls=[],writes=[]);uc.emu_start(cs*16+0x6585,0xa0100,count=64);result=Binding();native(gb,65536,key,callback,ignored_segment,C.byref(result));label=f'{load:x}/{key:04x}'
            require(result.status==0,'Native status '+label);wanted=[(result.write_offset,callback)] if result.wrote else [];require(active['writes']==wanted,'Original writer '+label)
            if result.wrote:struct.pack_into('<H',expected,result.write_offset,callback)
            require(bytes(gb)==expected==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_DX))==(result.ax,result.bx,0x4567),'Scratch registers '+label)
            require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label);require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Far return '+label)
            require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'IF/DF '+label);require(bytes(uc.mem_read(ss*16+sp+4,6))==struct.pack('<3H',key,callback,ignored_segment),'Arguments '+label)
            coverage['negative_write' if result.wrote and key>=0x8000 else 'positive_write' if result.wrote else 'extended_read' if result.extended_read else 'no_effect']+=1
            if result.wrote and result.write_offset==0x66e6:coverage['ring_cursor_alias']+=1
            prior=result.write_offset if result.wrote else None;instructions+=active['instructions'];vectors+=1
        for fill in [0,0xff,0xa5,0x3c]:
            for flags in [2,0x202,0x402,0x602]:
                group=bytes([fill])*65536;uc.mem_write(ds*16,group);gb=(C.c_uint8*65536).from_buffer_copy(group);uc.mem_write(ss*16+sp,struct.pack('<2H',0x100,0xa000))
                for reg,val in preserved+[(UC_X86_REG_CS,installer_cs),(UC_X86_REG_IP,2),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
                active.update(instructions=0,calls=[],writes=[]);uc.emu_start(installer_cs*16+2,0xa0100,count=256);result=Install();install(gb,65536,cs,C.byref(result))
                require(active['calls']==[[k,o,cs] for k,o in zip(keys,callbacks)],'Six installer argument triples');require(active['writes']==[(0x6048+2*k,o) for k,o in zip(keys,callbacks)],'Six ordered installer writes')
                require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)) and result.status==0 and result.writes==6,'Installer group/status')
                require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_DX))==(result.ax,result.bx,result.dx),'Installer scratch');require(all(uc.reg_read(reg)==val for reg,val in preserved),'Installer preserved');require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Installer return');require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'Installer IF/DF')
                coverage['complete_installer']+=1;instructions+=active['instructions'];vectors+=1
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());call_sites=[{'owner':f['entry'],**c} for f in graph['functions'] for c in f['calls'] if c['target']=='06C9:6585'];require(len(call_sites)==6 and all(c['owner']=='16FC:0002' for c in call_sites),'Discovered setter caller domain changed')
    record={'schema':1,'function_ids':['FN-EGA-000154','FN-EGA-000357'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_key_bindings.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'discovered_setter_calls':call_sites,'actual_installer_keys':keys,'actual_installer_callbacks':callbacks,'limits':'All65536 literal keywords at two loadbases plus32 completeinstaller cases; synthetic fullgroup, IF/DF, ignoredsegment and orderedwriters. Only six discovered calls have smallconstant keydomain. General negative-key alias writes are literal helper effects, not evidence of their reachability or ring reset. No actual keyboard/callback/IRQ, caller lifetime/platform/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
