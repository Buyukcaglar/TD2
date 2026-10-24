"""Compare5E1C/5E8A metadata control to explicit native service adapters.

All lengths, stack seeds and service responses are synthetic. No file/corpus
decode or real DOS service executes. Errors stop before fatal16A7:0002.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:
        raise RuntimeError(message)


class Request(ctypes.Structure):
    _fields_ = [(name,ctypes.c_uint16) for name in ['operation','handle','filename_offset','count']] + [('header_destination',ctypes.POINTER(ctypes.c_uint8))]


class Response(ctypes.Structure):
    _fields_ = [(name,ctypes.c_uint16) for name in ['ax','dx','carry']]


class Result(ctypes.Structure):
    _fields_ = [(name,ctypes.c_uint16) for name in ['status','failed_operation','paragraphs','handle','handle_valid']] + [('final_header',ctypes.c_uint8*4)]


Service = ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.POINTER(Request),ctypes.POINTER(Response))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    library,output=args.library.resolve(),args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=ctypes.CDLL(str(library))
    file_fn,header_fn=dll.td2ega_file_paragraphs,dll.td2ega_header_paragraphs
    file_fn.argtypes=[Service,ctypes.c_void_p,ctypes.c_uint16,ctypes.POINTER(Result)]
    header_fn.argtypes=[Service,ctypes.c_void_p,ctypes.c_uint16,ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(Result)]
    file_fn.restype=header_fn.restype=None
    file_cases=[{'kind':'file','size':value,'seek_carry':sc,'rewind_carry':rc,'open_error':False}
                for value in [0,1,15,16,65535,65536,0xfffff,0x100000,0xfffffff0,0xffffffff]
                for sc in [0,1] for rc in [0,1]]
    header_cases=[{'kind':'header','size':value,'header_first':first,'read_carry':cf,'read_ax':ax,'write_bytes':written,'open_error':False}
                  for value in [0,1,15,16,0xfffff,0x100000,0xfffff1,0xffffff] for first in [0,1,255]
                  for cf,ax,written in [(0,4,4),(1,4,0),(1,4,1),(1,5,0),(0,3,3),(0,0,0)]]
    file_cases.append({'kind':'file','size':0,'seek_carry':0,'rewind_carry':0,'open_error':True})
    header_cases.append({'kind':'header','size':0,'header_first':0,'read_carry':0,'read_ax':4,'write_bytes':4,'open_error':True})
    rows=[]
    ds=ss=0x5000;sp=0xe000;header_at=ds*16+sp-8;seed=b'\x17\x23\x45\x67'
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9
        first,length=0x6c90+0x5e1c,0x5ef4-0x5e1c
        code=bytearray(image[first:first+length])
        for r in relocs:
            if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
        uc.mem_write(cs*16+0x5e1c,bytes(code))
        starts={cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,0x5e1c)}
        active={}

        def code_hook(u,address,size,_):
            require(address in starts,'Metadata helper escaped code fence')
            if address==cs*16+0x5e3c:
                active['fatal']=True;u.emu_stop();return
            active['instructions']+=1

        def write_hook(u,access,address,size,value,_):
            require(ss*16+sp-64<=address and address+size<=ss*16+sp+6,'Unexpected metadata writer')

        def service(model,operation,handle,filename,count,write_bytes):
            model['events'].append(operation)
            if operation==0:
                require(filename==0x120,'Filename coordinate')
                return (2,0,1) if active['case']['open_error'] else (active['handle'],0,0)
            require(handle==active['handle'],'Handle flow')
            case=active['case']
            if operation==3:return case['size']&65535,case['size']>>16,case['seek_carry']
            if operation==4:return 5,0xabcd,case['rewind_carry']
            if operation==1:
                require(count==4 and case['kind']=='header','Header read count')
                data=bytes([case['header_first']])+case['size'].to_bytes(3,'little')
                write_bytes(data[:case['write_bytes']])
                return case['read_ax'],0,case['read_carry']
            require(operation==2,'Unknown service')
            return (5,0,1) if active['close_carry'] else (0,0,0)

        def interrupt(u,number,_):
            require(number==0x21,'Unexpected interrupt')
            ax=u.reg_read(UC_X86_REG_AX);ah=ax>>8
            if ah==0x3d:
                require(ax&255==0 and u.reg_read(UC_X86_REG_DS)==ds,'Open profile');op=0
            elif ah==0x42:
                require(ax&255 in [0,2] and u.reg_read(UC_X86_REG_CX)==0 and u.reg_read(UC_X86_REG_DX)==0,'Seek position request');op=3 if ax&255==2 else 4
            elif ah==0x3f:
                require(u.reg_read(UC_X86_REG_DS)*16+u.reg_read(UC_X86_REG_DX)==header_at,'DS=SS stack-header address');op=1
            else:
                require(ah==0x3e,'Unknown DOS operation');op=2
            result_ax,result_dx,carry=service(active['guest'],op,u.reg_read(UC_X86_REG_BX),u.reg_read(UC_X86_REG_DX),u.reg_read(UC_X86_REG_CX),
                                             lambda data:u.mem_write(header_at,data) if data else None)
            u.reg_write(UC_X86_REG_AX,result_ax)
            if op in [3,4]:u.reg_write(UC_X86_REG_DX,result_dx)
            u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|carry)

        uc.hook_add(UC_HOOK_CODE,code_hook);uc.hook_add(UC_HOOK_MEM_WRITE,write_hook);uc.hook_add(UC_HOOK_INTR,interrupt)
        for case in file_cases+header_cases:
            for handle in [0,0xffff]:
                for close_carry in [0,1]:
                    uc.mem_write(ss*16+sp-64,b'\xa5'*64+struct.pack('<3H',0x100,0x8000,0x120))
                    uc.mem_write(header_at,seed)
                    entry=0x5e1c if case['kind']=='file' else 0x5e8a
                    preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_ES,0x6789),
                               (UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x4567),(UC_X86_REG_DI,0x3456)]
                    for reg,value in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,value)
                    active.update(case=case,handle=handle,close_carry=close_carry,guest={'events':[]},instructions=0,fatal=False)
                    uc.emu_start(cs*16+entry,0x80100,count=256)
                    model={'events':[]};errors=[]

                    def native_service(context,request_ptr,response_ptr):
                        try:
                            request=request_ptr.contents
                            def write_bytes(data):
                                require(bool(request.header_destination),'Native header destination')
                                if data:ctypes.memmove(request.header_destination,data,len(data))
                            ax,dx,cf=service(model,request.operation,request.handle,request.filename_offset,request.count,write_bytes)
                            response_ptr.contents.ax,response_ptr.contents.dx,response_ptr.contents.carry=ax,dx,cf
                            return 1
                        except Exception as error:
                            errors.append(str(error));return 0

                    callback=Service(native_service);result=Result();seedbuf=(ctypes.c_uint8*4).from_buffer_copy(seed)
                    if case['kind']=='file':file_fn(callback,None,0x120,ctypes.byref(result))
                    else:header_fn(callback,None,0x120,seedbuf,ctypes.byref(result))
                    require(not errors,'Native adapter: '+str(errors))
                    require(model==active['guest'],'Metadata service ordering')
                    fatal=case['open_error'] or case['kind']=='header' and case['read_ax']!=4
                    require(result.status==int(fatal)==int(active['fatal']),'Metadata status')
                    require(result.handle_valid==int(not case['open_error']) and (not result.handle_valid or result.handle==handle),'Handle metadata')
                    if case['kind']=='header':require(bytes(result.final_header)==bytes(uc.mem_read(header_at,4)),'Original uninitialized/partiallyinitialized header state')
                    if fatal:
                        require(uc.reg_read(UC_X86_REG_CS)==cs and uc.reg_read(UC_X86_REG_IP)==0x5e3c,'Fatal fence')
                        require(uc.reg_read(UC_X86_REG_DS)==load+0x178f and uc.reg_read(UC_X86_REG_AX)==0x5d7a,'Fatal reporting context')
                        require(model['events']==([0] if case['open_error'] else [0,1,2]),'Short/error read closesbeforefatal; openerror doesnot')
                    else:
                        require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Normal far-return/frame')
                        require(all(uc.reg_read(reg)==value for reg,value in preserved),'Preserved registers/segments')
                        require(uc.reg_read(UC_X86_REG_AX)==result.paragraphs,'Paragraph result')
                        count=case['size'] if case['kind']=='file' else int.from_bytes(bytes(result.final_header)[1:4],'little')
                        require(result.paragraphs==((count>>4)+bool(count&15))&65535,'Defined round/truncate reference')
                    rows.append({'load_segment':load,**case,'handle':handle,'close_carry':close_carry,'status':result.status,
                                 'paragraphs':result.paragraphs if not fatal else None,'events':model['events'],'instructions':active['instructions']})
    diagnostics=0
    for kind in ['file','header']:
        for callback in [Service(),Service(lambda context,req,res:0)]:
            result=Result()
            if kind=='file':file_fn(callback,None,0,ctypes.byref(result))
            else:header_fn(callback,None,0,(ctypes.c_uint8*4)(),ctypes.byref(result))
            require(result.status==2,'Native service diagnostic');diagnostics+=1
    result=Result();header_fn(Service(lambda context,req,res:1),None,0,None,ctypes.byref(result))
    require(result.status==2,'Null seed diagnostic');diagnostics+=1
    file_fn(Service(),None,0,None);header_fn(Service(),None,0,None,None);diagnostics+=2
    result={'schema':1,'result':'pass','function_ids':['FN-EGA-000141','FN-EGA-000142'],'image_sha256':sha,
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_file_paragraphs.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'vectors':len(rows),'native_only_diagnostics':diagnostics,'original_instructions_executed':sum(r['instructions'] for r in rows),
            'cases':rows,'limits':'SyntheticDOS serviceprofile/stackseeds only, normalreturn orfatalprefix. Seekcarry/rewind/close results ignored; headerCF1AX4 acceptance usesexplicitseed. ActualDOS ABI, fatalcleanup, everycaller allocation/profile andsuppliedresource/fullcodec/game/fidelity acceptance remainopen.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
