"""Compare16B8:0000 with actual search helpers, including first-failure fallthrough."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_find_files import Registers,Request,Response,Service,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','index','es','direction']]+[('next_calls',C.c_uint32),('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_find_nth;native.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint16,Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];native.restype=None
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536))
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x16b8;search_cs=load+0x6c9;starts=set();active={}
        for segment,ip,length in [(0x16b8,0,58),(0x6c9,0x5ef4,111)]:
            first=segment*16+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write((load+segment)*16+ip,bytes(code));starts.update((load+segment)*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):require(address in starts,'Nthsearch escaped instruction fence');active['instructions']+=1
        def service(model,operation,ax,cx,dx,segment,write):
            require(segment==ds,'DOS group');model['events'].append([operation,ax,cx,dx,segment])
            if operation==0:require(dx==0x5dee,'SetDTA pointer');model['selected']=[ds,0x5dee];return (model['searches']+0x5a)&65535,0
            require(model['selected']==[ds,0x5dee],'DTA selection')
            if operation==1:
                require(model['searches']==0 and dx==0x120 and cx&255==6,'FindFirst profile');failed=active['first_fail']
            else:
                require(operation==2 and model['searches']>=1 and dx==0x5dee,'FindNext profile');failed=int(active['next_fail'] is not None and model['next_calls']==active['next_fail']);model['next_calls']+=1
                if active['first_fail']:model['continued_after_first_failure']+=1
            name=(f'F{model["searches"]:07X}.PES'.encode()+b'\0');require(len(name)==13,'Synthetic name');data=bytearray((i*31+5)&255 for i in range(43));data[30:43]=name
            count=7 if failed else 43
            if count:write(bytes(data[:count]))
            model['searches']+=1;return 0xd018,failed
        def interrupt(u,num,_):
            require(num==0x21,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);require(ax>>8 in [0x1a,0x4e,0x4f],'DOS operation');operation={0x1a:0,0x4e:1,0x4f:2}[ax>>8];av,cf=service(active['guest'],operation,ax,u.reg_read(UC_X86_REG_CX),u.reg_read(UC_X86_REG_DX),u.reg_read(UC_X86_REG_DS),lambda b:u.mem_write(ds*16+0x5dee,b));u.reg_write(UC_X86_REG_AX,av);u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|cf)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345)]
        def model():return {'events':[],'selected':[0xdead,0xbeef],'searches':0,'next_calls':0,'continued_after_first_failure':0}
        def compare(ordinal,first_fail,next_fail,stale,category):
            nonlocal vectors,instructions
            data=bytearray(baseline);name=b'C:\\DIR\\*.PES\0';data[0x120:0x120+len(name)]=name;struct.pack_into('<H',data,0x5dec,stale);uc.mem_write(ds*16,bytes(data));frame=struct.pack('<4H',0x400,0xa000,0x120,ordinal);uc.mem_write(ss*16+sp-32,b'\xa5'*32+frame+b'\xa5'*8);incoming=Registers(0xa55a,0xa55a,0x4567,0x7654);flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10)
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(first_fail=first_fail,next_fail=next_fail,guest=model(),instructions=0);uc.emu_start(cs*16,0xa0400,count=4000000);gb=(C.c_uint8*65536).from_buffer_copy(data);native_model=model();errors=[]
            def native_service(ctx,request_ptr,response_ptr):
                try:
                    q=request_ptr.contents;require(q.dta_offset==0x5dee,'NativeDTA coordinate');response_ptr.contents.ax,response_ptr.contents.carry=service(native_model,q.operation,q.ax,q.cx,q.dx,q.ds,lambda b:C.memmove(q.dta,b,len(b)));return 1
                except Exception as e:errors.append(str(e));return 0
            callback=Service(native_service);result=Result();native(gb,65536,ds,0x120,ordinal,C.byref(incoming),0x6789,(flags>>10)&1,callback,None,65536,C.byref(result));label=f'{load:x}/{ordinal:x}/{first_fail}/{next_fail}/{stale:x}/{category}'
            require(not errors and result.status==0,'Native service '+label+str(errors));require(native_model==active['guest'],'Request/DTA/sequence '+label);require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            r=result.registers;require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_ES))==(r.ax,r.bx,r.cx,r.dx,result.es),'Registers/ES '+label);require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==result.direction and uc.reg_read(UC_X86_REG_EFLAGS)&0x200==flags&0x200,'IF/DF '+label)
            require(all(uc.reg_read(reg)==val for reg,val in preserved) and (uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4),'Farreturn/preserved '+label);require(bytes(uc.mem_read(ss*16+sp,8))==frame,'Both arguments unchanged')
            require(bytes(uc.mem_read(ss*16+sp-6,4))==struct.pack('<2H',result.index,r.ax),'Original localindex/lastresult '+label);require(result.next_calls==native_model['next_calls'],'Next count')
            coverage[category]+=1;coverage['first_failure_continuation_cases']+=int(native_model['continued_after_first_failure']>0);coverage['conditional_ring_write_witness']+=int(first_fail and stale==0x66e6 and bytes(gb[0x66e6:0x66e8])!=data[0x66e6:0x66e8]);instructions+=active['instructions'];vectors+=1
        for ordinal in range(65536):compare(ordinal,0,0,0,'all_signed_ordinal_words')
        for ordinal in [0,1,2,3,7,32,0x7ffe,0x7fff,0x8000,0xffff]:
            for first_fail in [0,1]:
                for next_fail in [0,1,2,None]:
                    if ordinal in [0x7ffe,0x7fff] and next_fail is None:continue
                    for stale in [0,0x5d88,0x5dec,0x5e0d,0x66e6,0xffff]:compare(ordinal,first_fail,next_fail,stale,'stale_failure_and_sequence_profiles')
        compare(0x7fff,0,None,0,'maximum_signed_ordinal_sequence')
    # Work budget is a native diagnostic after real prefix effects, not an
    # extra original failure path. A missing adapter is also native-only.
    diagnostics=0
    for max_next in [0,1]:
        data=(C.c_uint8*65536)();incoming=Registers();r=Result();native(data,65536,0,0,2,C.byref(incoming),0,0,Service(),None,max_next,C.byref(r));require(r.status==2,'Native adapter diagnostic');diagnostics+=1
    record={'schema':1,'function_id':'FN-EGA-000351','result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_find_nth.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_find_files.py','sha256':hashlib.sha256((ROOT/'tools/validate_find_files.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete16B8:0000 plusactual5EF4/5F4E, recoverednativecomposition andsyntheticDOSsearch responses. Signedordinaldomain,firstfailure-nextfallthrough, globalDTA/stalebasename andconditionalalias effects preserved. Syntheticnextsuccessafterfirstfailure isnotactualDOSbehavior orreachable ringreset proof; documentedvalidsearch-block/callerlifetime remainsopen. Nofilesystem/resource/IRQ/core/game/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
