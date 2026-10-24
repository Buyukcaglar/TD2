"""Compare4281/43C3 and actual4612/4441 on synthetic fullgroup states."""
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
from validate_mutable_control import State
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Result(C.Structure):
    _fields_=[('registers',Registers),('bp',C.c_uint16),('status',C.c_uint16)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));functions={'update':dll.td2ega_update_input_control,'pair':dll.td2ega_advance_control_pair}
    functions['pair'].argtypes=[C.POINTER(C.c_uint8),C.POINTER(Registers),C.c_uint16,C.POINTER(Result)]
    functions['update'].argtypes=[C.POINTER(C.c_uint8),C.POINTER(State),C.POINTER(Registers),C.c_uint16,C.POINTER(Result)]
    for fn in functions.values():fn.restype=None
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536));boundary=[0,1,5,6,7,95,96,99,100,199,200,201,299,300,301,500,0x7ffe,0x7fff,0x8000,0x8001,0xfffe,0xffff]
    for load in [0x1000,0x2345]:
        cpus={f:Uc(UC_ARCH_X86,UC_MODE_16) for f in [1,2]}
        for cpu in cpus.values():cpu.mem_map(0,0x100000)
        cs=load+0x6c9;starts=set();active={}
        for ip,length in [(0x4281,521),(0x4612,39)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            for cpu in cpus.values():cpu.mem_write(cs*16+ip,bytes(code))
            starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):require(address in starts,'Inputcontrol escaped instruction fence');active['instructions']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        for form,cpu in cpus.items():
            cpu.mem_write(cs*16+0x42ad,bytes([0x77 if form==1 else 0x75]));cpu.hook_add(UC_HOOK_CODE,fetch);cpu.hook_add(UC_HOOK_INTR,interrupt)
        def compare_one(kind,changes,category,form):
            nonlocal vectors,instructions
            uc=cpus[form];state=State();state.load_segment=load;state.branch_42ad=form
            data=bytearray(baseline)
            for at,value,width in changes:
                if width==1:data[at]=value
                else:struct.pack_into('<H',data,at,value)
            uc.mem_write(ds*16,bytes(data));uc.mem_write(ss*16+sp-16,b'\xa5'*16+struct.pack('<H',0x100)+b'\xa5'*8);incoming=Registers(0xaa55,0xa55a,0x4567,0x7654);flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);entry=0x4281 if kind=='update' else 0x43c3;preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345),(UC_X86_REG_ES,0x1234)]
            for reg,val in preserved+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active['instructions']=0;uc.emu_start(cs*16+entry,cs*16+0x100,count=256);gb=(C.c_uint8*65536).from_buffer_copy(data);result=Result();
            if kind=='update':functions[kind](gb,C.byref(state),C.byref(incoming),0x5678,C.byref(result))
            else:functions[kind](gb,C.byref(incoming),0x5678,C.byref(result))
            require(result.status==0,'Native branch state');r=result.registers;label=f'{load:x}/{kind}/{category}/{form}/{changes}'
            require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label);require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_BP))==(r.ax,r.bx,r.cx,r.dx,result.bp),'Registers/BP '+label)
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'Near return '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved) and uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'IF/DF/preserved '+label);require(bytes(uc.mem_read(ss*16+sp,10))==struct.pack('<H',0x100)+b'\xa5'*8,'Frame/upperguard');coverage[category]+=1;instructions+=active['instructions'];vectors+=1
        def compare(kind,changes,category):
            for form in ([1,2] if kind=='update' else [1]):compare_one(kind,changes,category,form)
        for high in range(256):
            for gear in range(256):
                pair=(high<<8)|0x7b;compare('pair',[(0x2f4c,0x4567,2),(0x3324,0x4567,2),(0x2f4e,pair,2),(0x3326,pair,2),(0x33b0,0,1),(0x2f56,gear,1)],'all_retained_BH_and_low_indices')
        for key in range(256):
            for stage in [0,1]:
                for activity in [0,1,2]:
                    for low,high in [(0,0),(0,1),(1,0),(1,1),(0xff,0x80)]:
                        for automatic in [0,1]:
                            for latched in [0,1]:compare('update',[(0x33b0,key,1),(0x33d5,stage,1),(0x8a9a,activity,2),(0x3365,low,1),(0x3366,high,1),(0x90a8,automatic,1),(0x3367,latched,1),(0x33af,(key>>6)&1,1),(0x5490,(key>>7)&1,1),(0x332c,[0,100,500,0x7fff,0x8000,0xffff][key%6],2),(0x23aa,200,2),(0x23ac,300,2),(0x23ae,100,2)],'all_input_byte_and_branch_profiles')
        for selector in range(256):
            for value in range(256):compare('update',[(0x33b0,0x11,1),(0x33d5,0,1),(0x8a9a,2,2),(0x3365,0,1),(0x3366,0,1),(0x90a8,0,1),(0x33af,1,1),(0x5490,0,1),(0x2407,selector,1),(0x2410,value,1)],'all_alternate_record_byte_indices')
        for x in boundary:
            for y in boundary:
                for tx,ty,reference in [(x,y,0),(0,0,y),(0x7fff,0x8000,y),(0x8000,0x7fff,y)]:compare('pair',[(0x2f4c,x,2),(0x2f4e,y,2),(0x3324,tx,2),(0x3326,ty,2),(0x23c8,reference,2),(0x33b0,0,1)],'pair_signed_step_boundaries')
        rng=random.Random(0x4281)
        for _ in range(4096):
            changes=[(at,rng.randrange(256),1) for at in [0x33b0,0x33d5,0x3365,0x3366,0x3367,0x90a8,0x33af,0x5490,0x2f56,0x23a6,0x2418,0x33c6,0x3329]]+[(at,rng.randrange(65536),2) for at in [0x8a9a,0x332c,0x23aa,0x23ac,0x23ae,0x3328,0x52ce,0x2f4c,0x2f4e,0x3324,0x3326,0x23c8]];compare('update',changes,'varied_update_states');compare('pair',changes,'varied_pair_states')
    record={'schema':1,'function_ids':['FN-EGA-000368','FN-EGA-000369'],'result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_control.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_mutable_control.py','sha256':hashlib.sha256((ROOT/'tools/validate_mutable_control.py').read_bytes()).hexdigest()},{'path':'tools/validate_sim_targets.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_targets.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'code_states':{'42AD':['initial_JA','prepared_JNE'],'43C3':'unmodified'},'limits':'Explicit branch-form inputs; Complete4281/43C3 with actual4612/4441, serialized syntheticfullgroup, retainedbytehalves/indexaliases andBPclobber/preserve, signed/unsigned boundary andstatepublication. Actualresourcefield/table schema/units, callerflag/IRQ/fullstate/game/fidelity remainopen. NoBIOS/input/device ororiginalresource executes.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
