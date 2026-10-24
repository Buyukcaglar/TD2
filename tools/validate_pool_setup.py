"""Compare6F1E/6F86/6FD6 with explicit synthetic DOS AX/BX/CF profiles."""
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
    _fields_=[(n,C.c_uint16) for n in ['operation','ax','bx','es']]


class Response(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['ax','bx','carry']]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Request),C.POINTER(Response))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','stage','es']]+[('registers',Registers),('cleared',C.c_uint32)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest();require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));setup=dll.td2ega_pool_setup;setup.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(Registers),C.c_uint16,Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];setup.restype=None;fixed=dll.td2ega_pool_setup_fixed;fixed.argtypes=setup.argtypes[:4]+setup.argtypes[5:];fixed.restype=None;remaining=dll.td2ega_pool_remaining;remaining.argtypes=[C.POINTER(C.c_uint8),C.POINTER(Registers),C.POINTER(Registers)];remaining.restype=None
    baseline=bytes((i*37+11)&255 for i in range(65537));profiles=[[(0x6100,0x4321),(0,None),(0,None)],[(8,0xffff),(8,0x100),(8,0x80)],[(0,0),(0xffff,0),(0x1234,0)],[(0xffff,0),(1,0xffff),(0xffff,1)],[(0x8000,0x8000),(0xff,0xa000),(0,0x8000)],[(0x1234,0x5678),(0xabcd,0x1111),(0x5678,0x2222)]]
    vectors=instructions=0;coverage=Counter();ds,ss,sp=0x5000,0x9000,0x8000
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;starts=set();active={}
        for ip,length in [(0x6f1e,117),(0x6fd6,18)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
        def fetch(u,address,size,_):
            require(address in starts,'Poolinterface escaped instruction fence');active['instructions']+=1
            if address==cs*16+0x6f7b:active['cleared']+=1
        def service(model,op,ax,bx,es):
            index=len(model);require(index<3 and op==(0 if index==0 else 1),'DOS request order');model.append([op,ax,bx,es]);response_ax,response_bx=active['profile'][index];return response_ax,bx if response_bx is None else response_bx,(active['carries']>>index)&1
        def interrupt(u,num,_):
            require(num==0x21,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);require(ax>>8 in [0x48,0x4a],'Unexpected DOS request');av,bv,cf=service(active['guest'],0 if ax>>8==0x48 else 1,ax,u.reg_read(UC_X86_REG_BX),u.reg_read(UC_X86_REG_ES));u.reg_write(UC_X86_REG_AX,av);u.reg_write(UC_X86_REG_BX,bv);u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|cf)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt);preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x3456),(UC_X86_REG_DI,0x2345)]
        def prepare(entry,flags,argument):
            frame=struct.pack('<3H',0x400,0xa000,argument);uc.mem_write(ss*16+sp-32,b'\xa5'*32+frame+b'\xa5'*8)
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xa55a),(UC_X86_REG_BX,0x1234),(UC_X86_REG_CX,0x4567),(UC_X86_REG_DX,0x7654),(UC_X86_REG_ES,0x2345),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,cleared=0,guest=[])
        def check(regs,es,flags):
            require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_ES))==(regs.ax,regs.bx,regs.cx,regs.dx,es),'Register outputs');require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x400,sp+4),'Farreturn/frame');require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers');require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==flags&0x600,'IF/DF')
        for initialized in [0,1,0xffff]:
            for left in [0,0x68e2,0xfff0,0xfff1]:
                for rows in [1,2,49]:
                    for kind in ['setup','fixed']:
                        for requested in ([0,1,0xa000,0xffff] if kind=='setup' else [0xa000]):
                            for pi,profile in enumerate(profiles if initialized==0 else profiles[:1]):
                                for carries in (range(8) if initialized==0 else [0]):
                                    right=(left+rows*18)&65535;data=bytearray(baseline);struct.pack_into('<H',data,0x68da,initialized);struct.pack_into('<4H',data,0x6c66,left,0x1234,0x5678,right);uc.mem_write(ds*16,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);prepare(0x6f1e if kind=='setup' else 0x6f86,flags,requested);active.update(profile=profile,carries=carries);uc.emu_start(cs*16+(0x6f1e if kind=='setup' else 0x6f86),0xa0400,count=1024);gb=(C.c_uint8*65537).from_buffer_copy(data);incoming=Registers(0xa55a,0x1234,0x4567,0x7654);result=Result();model=[];errors=[]
                                    def native_service(ctx,request_ptr,response_ptr):
                                        try:
                                            q=request_ptr.contents;response_ptr.contents.ax,response_ptr.contents.bx,response_ptr.contents.carry=service(model,q.operation,q.ax,q.bx,q.es);return 1
                                        except Exception as e:errors.append(str(e));return 0
                                    callback=Service(native_service)
                                    if kind=='setup':setup(gb,65537,cs,ds,requested,C.byref(incoming),0x2345,callback,None,32768,C.byref(result))
                                    else:fixed(gb,65537,cs,ds,C.byref(incoming),0x2345,callback,None,32768,C.byref(result))
                                    label=f'{load:x}/{kind}/{initialized:x}/{left:x}/{rows}/{requested:x}/{pi}/{carries}'
                                    require(not errors and result.status==0 and result.stage==4,'Native status '+label+str(errors));require(model==active['guest'],'DOS request/response flow '+label);require(bytes(gb)==bytes(uc.mem_read(ds*16,65537)),'Full group/adjacentbyte '+label);require(result.cleared==active['cleared']==rows-1,'Status clear count '+label)
                                    try:check(result.registers,result.es,flags)
                                    except RuntimeError as e:raise RuntimeError(str(e)+' '+label)
                                    require(bytes(uc.mem_read(ss*16+sp+4,2))==struct.pack('<H',requested),'Caller argument unchanged');coverage[kind]+=1;coverage['initialized_skip' if initialized else 'allocate_resize']+=1;coverage['word_near_wrap']+=int(left==0xfff1);instructions+=active['instructions'];vectors+=1
        for pointer in range(65536):
            data=bytearray(baseline);struct.pack_into('<HHH',data,0x6c68,pointer,0x1234,0x6c54);uc.mem_write(ds*16,bytes(data));prepare(0x6fd6,0x602,0);uc.emu_start(cs*16+0x6fd6,0xa0400,count=32);gb=(C.c_uint8*65537).from_buffer_copy(data);incoming=Registers(0xa55a,0x1234,0x4567,0x7654);result=Registers();remaining(gb,C.byref(incoming),C.byref(result));check(result,0x2345,0x602);require(bytes(gb)==bytes(uc.mem_read(ds*16,65537)) and not active['guest'],'Capacity readonly');coverage['all_active_near_pointers']+=1;instructions+=active['instructions'];vectors+=1
    diagnostics=0
    for callback,budget in [(Service(),48),(Service(lambda ctx,req,res:0),48),(Service(),0)]:
        data=(C.c_uint8*65537)();struct.pack_into('<4H',data,0x6c66,0x68e2,0,0,0x6c54)
        if budget==0:struct.pack_into('<H',data,0x68da,1)
        r=Result();incoming=Registers();setup(data,65537,0x16c9,0x5000,0xa000,C.byref(incoming),0,callback,None,budget,C.byref(r));require(r.status==2,'Native service/budget diagnostic');diagnostics+=1
    record={'schema':1,'function_ids':['FN-EGA-000176','FN-EGA-000177','FN-EGA-000178'],'result':'pass','vectors':vectors,'native_only_diagnostics':diagnostics,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_pool_setup.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_sim_targets.py','sha256':hashlib.sha256((ROOT/'tools/validate_sim_targets.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete6F1E/6F86/6FD6, serialized syntheticordinarygroup/DOSAX-BX-CF profiles. IgnoredCF, retainedBX/AXlowthroughresizes, initializedskip, interiorstatusreset, near/wordwrap andallcapacityactivepointers. No actualDOSallocation/process/payload/lifetime, callerflag/IRQ/core/resource/game/fidelity acceptance; native service/budgetdiagnostics outsideoriginal. ReturnES0/nearoffset0 remain coordinates, nothostNULL.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
