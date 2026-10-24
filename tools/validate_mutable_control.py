"""Compare13A8:002E/0163 and embedded007E with native control-state fields.

Synthetic INT11 and readonly comparison views; loaded copies only. No actual
firmware/disk/process executes, and no timer meaning is assigned.
"""
import argparse
from collections import Counter
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


def require(test,message):
    if not test:raise RuntimeError(message)


class State(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['load_segment','selected_word','saved_near_return']]+[
        (name,ctypes.c_uint8) for name in ['scratch_24','scratch_2a','scratch_2b','own_nop_bb','own_nop_154','own_nop_3da',
                                        'returns_state','branch_424a','branch_4275','branch_42ad','principal_5656']]


class Result(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['status','ax','bx','cx','dx','low_0010','low_0012',
                'query_count','stub_call_count','near_return_count']]+[('near_returns',ctypes.c_uint16*2)]


Query=ctypes.CFUNCTYPE(ctypes.c_uint16,ctypes.c_void_p,ctypes.c_uint16)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();library,output=args.library.resolve(),args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=ctypes.CDLL(str(library));native=dll.td2ega_mutable_main
    native.argtypes=[ctypes.POINTER(State),ctypes.c_uint16,ctypes.c_uint16,Query,ctypes.c_void_p,ctypes.POINTER(Result)];native.restype=None
    reset=dll.td2ega_mutable_control_reset;reset.argtypes=[ctypes.POINTER(State)];reset.restype=ctypes.c_uint16
    counts=Counter();total_instructions=0;index=0
    def check_control(uc,state,load):
        base=load*16+0x6c90
        opcodes={0:0x76,1:0x77,2:0x75}
        require([uc.mem_read(base+at,1)[0] for at in [0x1bf7,0x424a,0x4275,0x42ad]]==[
            0xcb if state.returns_state else 0xf8,opcodes[state.branch_424a],opcodes[state.branch_4275],opcodes[state.branch_42ad]],'Native control fields/original mutable bytes')
        require(uc.mem_read((load+0x178f)*16+0x5656,1)[0]==state.principal_5656,'Aliased principal flag')

    for load in [0x1000,0x2345]:
        relocated=bytearray(image)
        for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
        for drive,first,second,df,readonly_profile in itertools.product(list(range(26))+[0x80,0xff,0x100,0xffff],range(4),range(4),[0,1],range(3)):
            uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);uc.mem_write(load*16,bytes(relocated))
            cs=load+0x13a8;ss=load+0x178f;body=cs*16;sp=[0xe000,0xd000][index&1]
            caller_ds=[0x5000,0x6000][(index>>1)&1];initial_dx=[0,0xffff,0x5555,0x100][index&3]
            extra=[0,0x3f,0xff00,0xff3f][index&3]
            responses=[(first<<6)|extra,(second<<6)|([0xff3f,0xff00,0x3f,0][index&3])]
            state=State();state.load_segment=load;state.selected_word=drive;state.saved_near_return=0xa5a5
            state.scratch_24=0xa5;state.scratch_2a=[0,0x55,0xaa,0xff][index&3];state.scratch_2b=0xa5
            uc.mem_write(body+0x24,b'\xa5');uc.mem_write(body+0x2a,bytes([state.scratch_2a,state.scratch_2b])+struct.pack('<H',state.saved_near_return))
            uc.mem_write(ss*16+0x5657,struct.pack('<H',drive))
            if readonly_profile:
                # Force ignored CMPS equality/last-word mismatch without
                # altering executed code or original files. DF changes spans.
                for destination,count in [(0x25e,16),(0x14,4)]:
                    source_start=0x1b2-(count-1)*2 if df else 0x1b2
                    dest_start=destination-(count-1)*2 if df else destination
                    raw=bytes(uc.mem_read(body+source_start,count*2))
                    uc.mem_write(body+dest_start,raw)
                    uc.mem_write(0xf0000+dest_start,raw)
                    if readonly_profile==2:
                        at=destination-(count-1)*2 if df else destination+(count-1)*2
                        value=uc.mem_read(body+at,1)[0]^1;uc.mem_write(body+at,bytes([value]));uc.mem_write(0xf0000+at,bytes([value]))
            uc.mem_write(ss*16+sp-0x100,b'\xa5'*0x104);uc.mem_write(ss*16+sp,struct.pack('<HH',0x100,0x8000))
            preserved=[(UC_X86_REG_DS,caller_ds),(UC_X86_REG_SS,ss),(UC_X86_REG_ES,0x4444),(UC_X86_REG_BP,0x1111),
                       (UC_X86_REG_SI,0x2222),(UC_X86_REG_DI,0x3333)]
            for reg,value in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2e),(UC_X86_REG_SP,sp),(UC_X86_REG_DX,initial_dx),
                (UC_X86_REG_EFLAGS,2|((index&1)<<9)|(df<<10)|(index&1))]:uc.reg_write(reg,value)
            active={'queries':[],'stubs':0,'returns':[],'instructions':0}
            allowed={0x10,0x11,0x12,0x13,ss*16+0x5656}
            allowed.update(body+at for at in [0x24,0x2a,0x2b,0x2c,0x2d,0xbb,0x154,0x3da])
            allowed.update(load*16+0x6c90+at for at in [0x1bf7,0x424a,0x4275,0x42ad])

            def code(u,address,size,_):
                ip=address-body
                require(u.reg_read(UC_X86_REG_CS)==cs and (0x2e<=ip<0x1ad or ip in [0x3d3,0x3eb]),'Mutable helper escaped body/stub fence')
                if ip==0x3d3:active['stubs']+=1
                if ip==0x162:active['returns'].append(struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP),2)))[0])
                active['instructions']+=1

            def write(u,access,address,size,value,_):
                require(ss*16+sp-0x100<=address and address+size<=ss*16+sp+4 or all(address+i in allowed for i in range(size)),'Unexpected mutable write')

            def interrupt(u,number,_):
                require(number==0x11 and len(active['queries'])<2,'Unexpected actual IRQ/service')
                value=responses[len(active['queries'])];active['queries'].append(value);u.reg_write(UC_X86_REG_AX,value)

            uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write);uc.hook_add(UC_HOOK_INTR,interrupt)
            uc.emu_start(body+0x2e,0x80100,count=4096)
            native_queries=[]
            def equipment(context,query_index):
                native_queries.append(query_index);return responses[query_index]
            query=Query(equipment);result=Result();native(ctypes.byref(state),sp,initial_dx,query,None,ctypes.byref(result))
            require(result.status==0 and native_queries==list(range(len(active['queries']))) and result.query_count==len(active['queries']),'Query order/count')
            require([result.ax,result.bx,result.cx,result.dx]==[uc.reg_read(reg) for reg in [UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX]],'Mutable register outputs')
            require(result.stub_call_count==active['stubs'] and list(result.near_returns[:result.near_return_count])==active['returns'],'Stub/saved near-return context')
            require([state.scratch_24,state.scratch_2a,state.scratch_2b,state.saved_near_return]==[
                uc.mem_read(body+0x24,1)[0],uc.mem_read(body+0x2a,1)[0],uc.mem_read(body+0x2b,1)[0],struct.unpack('<H',bytes(uc.mem_read(body+0x2c,2)))[0]],'Own scratch mutation')
            require([state.own_nop_bb,state.own_nop_154,state.own_nop_3da]==[1]*3 and all(uc.mem_read(body+at,1)[0]==0x90 for at in [0xbb,0x154,0x3da]),'Prepared-boundary flags')
            check_control(uc,state,load)
            require((result.low_0010,result.low_0012)==struct.unpack('<HH',bytes(uc.mem_read(0x10,4))),'Physical low-memory effects')
            require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
            require(all(uc.reg_read(reg)==value for reg,value in preserved),'Preserved caller segments/registers')
            flags=uc.reg_read(UC_X86_REG_EFLAGS)
            require(flags&0x8c5==0x44 and flags&0x100==0 and (flags>>10)&1==df and (flags>>9)&1==(index&1),'Defined flags/TF/IF/DF')
            counts['main']+=1;total_instructions+=active['instructions'];index+=1
        for cf,df,variant in itertools.product([0,1],[0,1],range(4)):
            uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);uc.mem_write(load*16,bytes(relocated))
            cs=load+0x13a8;ds=0x5000;ss=0x7000;sp=0x8000
            state=State();state.load_segment=load;state.returns_state=variant&1
            state.branch_424a=state.branch_4275=state.branch_42ad=2;state.principal_5656=0xa5
            uc.mem_write(ss*16+sp,struct.pack('<H',0xf000))
            for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x163),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,2|cf|(df<<10))]:uc.reg_write(reg,value)
            uc.emu_start(cs*16+0x163,cs*16+0xf000,count=32)
            ax=reset(ctypes.byref(state));check_control(uc,state,load)
            require(ax==uc.reg_read(UC_X86_REG_AX) and uc.reg_read(UC_X86_REG_DS)==ds and uc.reg_read(UC_X86_REG_SP)==sp+2,'Reset near-frame/AX/DS')
            require(uc.reg_read(UC_X86_REG_CS)==cs and uc.reg_read(UC_X86_REG_IP)==0xf000 and uc.reg_read(UC_X86_REG_EFLAGS)&0x401==cf|(df<<10),'Reset preserves flags')
            counts['reset']+=1
    diagnostics=0;result=Result()
    for state_ptr,query in [(None,Query()),(ctypes.byref(State()),Query())]:
        native(state_ptr,0,0,query,None,ctypes.byref(result));require(result.status==2,'Native invalid argument diagnostic');diagnostics+=1
    native(None,0,0,Query(),None,None);diagnostics+=1
    result={'schema':1,'result':'pass','function_id':'FN-EGA-000255','covered_original_local_helpers':['FN-EGA-000256','FN-EGA-000257'],
            'image_sha256':sha,'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_mutable_control.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'vectors':sum(counts.values()),'vectors_by_operation':dict(counts),'native_only_diagnostics':diagnostics,
            'main_original_instructions_executed':total_instructions,
            'limits':'Serialized fixed suppliedstub/AX-onlyINT11 profile, readonlyignoredcomparisons, TF0/nonwrappingstack. Main/embeddedhelper plusseparate reset; noactualfirmware/disk/IRQ/hostselfmodification, supportedruntimeprofile/fullmutablegraph orcore/game/fidelity acceptance.086Csemantics unchanged.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
