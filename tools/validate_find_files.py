"""Compare5EF4/5F4E path/DTA effects with synthetic DOS search services."""
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
from validate_sim_targets import Result as Registers,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['operation','ax','cx','dx','ds','dta_offset']]+[('dta',C.POINTER(C.c_uint8))]


class Response(C.Structure):
    _fields_=[('ax',C.c_uint16),('carry',C.c_uint16)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Request),C.POINTER(Response))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','found','es','direction','replacement_offset','prefix_copied']]+[('registers',Registers)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));first=dll.td2ega_find_first;first.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint16,Service,C.c_void_p,C.POINTER(Result)];first.restype=None;next_fn=dll.td2ega_find_next;next_fn.argtypes=first.argtypes[:3]+first.argtypes[4:];next_fn.restype=None
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000;baseline=bytes((i*37+11)&255 for i in range(65536));canonical=b'FIXTURE.PES\0\xd7';require(len(canonical)==13,'Synthetic name size')
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;offset,length=0x6c90+0x5ef4,111;code=bytearray(image[offset:offset+length])
        for r in relocs:
            if offset<=r<offset+length:struct.pack_into('<H',code,r-offset,(struct.unpack_from('<H',code,r-offset)[0]+load)&65535)
        uc.mem_write(cs*16+0x5ef4,bytes(code));starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x5ef4)};active={}
        def fetch(u,address,size,_):
            require(address in starts,'Findhelper escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x5f19:active['prefix']+=1
            if address==cs*16+0x5f3c:active['replacement']=u.reg_read(UC_X86_REG_DI)
        def service(model,operation,ax,cx,dx,segment,write):
            require(segment==ds,'DOS search segment');model['events'].append([operation,ax,cx,dx,segment])
            if operation==0:
                require(dx==0x5dee and len(model['events'])==1,'SetDTA sequence');model['selected']=[ds,0x5dee];return active['set_ax'],active['set_cf']
            require(model['selected']==[ds,0x5dee] and operation==(1 if active['kind']=='first' else 2),'Find sequence/currentDTA')
            if operation==1:require(dx==active['coordinate'] and cx&255==6,'First filename/attribute lowbyte')
            else:require(dx==0x5dee,'Next retainsDX')
            data=bytearray((i*31+5)&255 for i in range(43));data[30:43]=active['name'];count=active['partial'] if active['fail'] else 43
            if count:write(bytes(data[:count]))
            return 0xd018,active['fail']
        def interrupt(u,num,_):
            require(num==0x21,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);require(ax>>8 in [0x1a,0x4e,0x4f],'DOS operation');operation={0x1a:0,0x4e:1,0x4f:2}[ax>>8];av,cf=service(active['guest'],operation,ax,u.reg_read(UC_X86_REG_CX),u.reg_read(UC_X86_REG_DX),u.reg_read(UC_X86_REG_DS),lambda data:u.mem_write(ds*16+0x5dee,data));u.reg_write(UC_X86_REG_AX,av);u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|cf)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345)]
        def compare(kind,coordinate,category,fail=0,partial=0,name=canonical,raw=None,set_cf=0):
            nonlocal vectors,instructions
            data=bytearray(baseline)
            if kind=='next':struct.pack_into('<H',data,0x5dec,coordinate)
            if raw is not None:
                for i,value in enumerate(raw):data[(coordinate+i)&65535]=value
            uc.mem_write(ds*16,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);incoming=Registers(0xaa55,0xa55a,(coordinate&0xff00)|0x67,0x7654);frame=struct.pack('<3H',0x400,0xa000,coordinate);uc.mem_write(ss*16+sp-16,b'\xa5'*16+frame+b'\xa5'*8);entry=0x5ef4 if kind=='first' else 0x5f4e
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,incoming.ax),(UC_X86_REG_BX,incoming.bx),(UC_X86_REG_CX,incoming.cx),(UC_X86_REG_DX,incoming.dx),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(kind=kind,coordinate=coordinate,name=name,fail=fail,partial=partial,set_ax=coordinate^0x5a33,set_cf=set_cf,guest={'events':[],'selected':[0xdead,0xbeef]},prefix=0,replacement=0,instructions=0);uc.emu_start(cs*16+entry,0xa0400,count=2048);gb=(C.c_uint8*65536).from_buffer_copy(data);model={'events':[],'selected':[0xdead,0xbeef]};errors=[]
            def native_service(ctx,request_ptr,response_ptr):
                try:
                    q=request_ptr.contents;require(q.dta_offset==0x5dee and C.addressof(q.dta.contents)==C.addressof(gb)+0x5dee,'NativeDTA view');response_ptr.contents.ax,response_ptr.contents.carry=service(model,q.operation,q.ax,q.cx,q.dx,q.ds,lambda b:C.memmove(q.dta,b,len(b)));return 1
                except Exception as e:errors.append(str(e));return 0
            callback=Service(native_service);result=Result()
            if kind=='first':first(gb,65536,ds,coordinate,C.byref(incoming),0x6789,(flags>>10)&1,callback,None,C.byref(result))
            else:next_fn(gb,65536,ds,C.byref(incoming),0x6789,(flags>>10)&1,callback,None,C.byref(result))
            label=f'{load:x}/{kind}/{coordinate:x}/{category}/{fail}/{partial}/{set_cf}'
            require(not errors and result.status==0,'Native service '+label+str(errors));require(model==active['guest'],'Request/currentDTA state '+label);require(bytes(gb)==bytes(uc.mem_read(ds*16,65536)),'Full group '+label)
            r=result.registers;require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_ES))==(r.ax,r.bx,r.cx,r.dx,result.es),'Registers/ES '+label)
            require(result.found==int(not fail) and result.replacement_offset==active['replacement'] and result.prefix_copied==active['prefix'],'Copy/path observations '+label);require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==result.direction and uc.reg_read(UC_X86_REG_EFLAGS)&0x200==flags&0x200,'IF/DF '+label);require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label)
            require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4) and bytes(uc.mem_read(ss*16+sp,6))==frame,'Farreturn/unchanged argument '+label);coverage[category]+=1;coverage['failure' if fail else 'found']+=1;coverage['prefix87']+=int(result.prefix_copied==87);instructions+=active['instructions'];vectors+=1
        for coordinate in range(65536):
            compare('first',coordinate,'all_filename_near_offsets');compare('next',coordinate,'all_replacement_near_offsets')
        for kind in ['first','next']:
            for coordinate in [0,0x120,0x5d87,0x5d88,0x5dec,0x5dee,0x5e0b,0x5e0c,0x5e0d,0xfff0,0xffff]:
                for fail in [0,1]:
                    for partial in [0,7,43]:
                        for set_cf in [0,1]:compare(kind,coordinate,'service_failure_and_alias_profiles',fail,partial,b'X'*13,set_cf=set_cf)
        for count in [0,1,85,86,87,88,255]:
            for separator in [b'A',b':',b'\\']:
                raw=(b'A'*max(0,count-1)+separator if count else b'')+b'\0'
                for coordinate in [0x120,0x5d87,0x5d88,0xfff0,0xffff]:compare('first',coordinate,'prefix_separator_and_limit',raw=raw)
    diagnostics=0
    for callback in [Service(),Service(lambda ctx,req,res:0)]:
        data=(C.c_uint8*65536)();incoming=Registers();result=Result();first(data,65536,0,0,C.byref(incoming),0,0,callback,None,C.byref(result));require(result.status==2,'Native service diagnostic');diagnostics+=1
    record={'schema':1,'function_ids':['FN-EGA-000143','FN-EGA-000144'],'result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_find_files.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sim_targets.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_targets.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'api_reference':'docs/recovery/evidence/msdos-api-reference-v1.json','limits':'Complete5EF4/5F4E, serializedsyntheticDOS1A/4E/4F andfullgroup. GlobalDTA/path/basename ownership, CHattribute preservation,87byteprefix andliteral13byteforwardcopy/alias/wrap,near5D88/zero returns andconditionalES/DF preserved. NoactualDOSsearch/filesystem/version, callerinterleaving/resource/schema/core/game/fidelity acceptance. Native service diagnostics outsideoriginal.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
