"""Comparefour complete initialization entries and native helper composition.

Synthetic64KiB data/ports/vectors only; no resource decode, actualIRQ, callback
body or game loop. Initialized byte-ring preservation is checked separately.
"""
import argparse
from collections import Counter
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
import validate_timer_control as control
from validate_timer_callbacks import Result as CallbackResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *


def require(test,message):
    if not test:raise RuntimeError(message)


class InstallResult(ctypes.Structure):
    _fields_=[('status',ctypes.c_uint16),('timer',control.Result),('callbacks',CallbackResult*2)]


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
    specs=[('zero',0x3ff9,'td2ega_zero_simulation_state','FN-EGA-000125'),('view',0x38f2,'td2ega_reset_view_state','FN-EGA-000111'),
           ('reset',0x1e31,'td2ega_reset_session_state','FN-EGA-000082'),('install',0x3f40,'td2ega_install_simulation_state','FN-EGA-000124')]
    entry_strings={f'06C9:{entry:04X}' for _,entry,*_ in specs}|{'06C9:5427','06C9:601C','06C9:614C'}
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text())
    offsets={ip for f in graph['functions'] if f['entry'] in entry_strings for ip in f['instructions']}
    dll=ctypes.CDLL(str(library));functions={}
    for kind,entry,name,fid in specs:
        fn=getattr(dll,name);fn.restype=None;fn.argtypes=[ctypes.POINTER(ctypes.c_uint8)]+([ctypes.POINTER(control.State),ctypes.POINTER(InstallResult)] if kind=='install' else [])
        functions[kind]=fn
    counts=Counter();instructions=0;ds,ss,sp=0x5000,0x7000,0x8000
    for load in [0x1000,0x2345]:
        data=bytearray(image)
        for r in relocs:struct.pack_into('<H',data,r,(struct.unpack_from('<H',data,r)[0]+load)&65535)
        cs=load+0x6c9;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);uc.mem_write(load*16,bytes(data));active={}

        def code(u,address,size,_):
            require(u.reg_read(UC_X86_REG_CS)==cs and u.reg_read(UC_X86_REG_IP) in offsets,'Initialization escaped instruction fence')
            op=u.mem_read(address,1)[0]
            if op in [0xfa,0xfb]:active['events'].append([0,0,int(op==0xfb)])
            active['instructions']+=1

        def write(u,access,address,size,value,_):
            require(ds*16<=address and address+size<=ds*16+65536 or ss*16+sp-32<=address and address+size<=ss*16+sp+4 or 0x20<=address and address+size<=0x24,'Unexpected initialization writer')

        def port_in(u,port,size,_):
            require(size==1 and port in [0x21,0x61],'Unexpected portread');value=active['ports'][port];active['events'].append([1,port,value]);return value

        def port_out(u,port,size,value,_):
            require(size==1 and port in [0x21,0x61,0x43,0x40],'Unexpected portwrite');active['events'].append([2,port,value]);active['ports'][port]=value

        def interrupt(*_):raise RuntimeError('Unexpected actual IRQ/service')
        uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write);uc.hook_add(UC_HOOK_INTR,interrupt)
        uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for kind,entry,name,fid in specs:
            for case in range(260):
                if case==256:initial=b'\0'*65536
                elif case==257:initial=b'\xff'*65536
                else:initial=bytes((i*37+case*17)&255 for i in range(65536))
                initial=bytearray(initial)
                initial[0x3b51:0x3b98]=bytes((case+i*3)&255 for i in range(71))
                struct.pack_into('<H',initial,0x3811,[0,1,0x3b33,0xffff][case&3])
                ring_before=bytes(initial[0x66e6:0x67e8])
                device=control.State();device.current_cs=cs;device.vector_offset=0x61bf if case&1 else 0x1234
                device.vector_segment=cs if case&2 else 0x4321;device.pic_mask=[0,3,0xa5,255][case&3]
                device.speaker_control=[255,0xa5,3,0][case&3];device.control_43=0x9d
                uc.mem_write(ds*16,bytes(initial));uc.mem_write(0x20,struct.pack('<HH',device.vector_offset,device.vector_segment))
                uc.mem_write(ss*16+sp-32,b'\xa5'*32+struct.pack('<HH',0x100,0x8000))
                initial_if=(case>>2)&1;initial_df=(case>>3)&1
                for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),
                    (UC_X86_REG_BP,0x1234),(UC_X86_REG_EFLAGS,2|(initial_if<<9)|(initial_df<<10))]:uc.reg_write(reg,value)
                active.update(events=[],instructions=0,ports={0x21:device.pic_mask,0x61:device.speaker_control,0x43:0x9d,0x40:0})
                uc.emu_start(cs*16+entry,0x80100,count=2048)
                native_data=(ctypes.c_uint8*65536).from_buffer(initial)
                if kind=='install':
                    result=InstallResult();functions[kind](native_data,ctypes.byref(device),ctypes.byref(result))
                    require(result.status==0 and all(r.status==0 for r in result.callbacks),'Native helper composition')
                    require(active['events']==[[e.kind,e.port,e.value] for e in result.timer.events[:result.timer.event_count]],'Ordered combined port/IF effects')
                else:
                    functions[kind](native_data);require(not active['events'],'Data-only init hasnoport/IF effects')
                require(bytes(uc.mem_read(ds*16,65536))==bytes(initial),'Full initialized data segment')
                require(bytes(initial[0x66e6:0x67e8])==ring_before,'No per-session byte-ring reset')
                require(struct.unpack('<HH',bytes(uc.mem_read(0x20,4)))==(device.vector_offset,device.vector_segment),'Combined vector effects')
                require([active['ports'][p] for p in [0x21,0x61,0x43]]==[device.pic_mask,device.speaker_control,device.control_43],'Combined port state')
                require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
                require(uc.reg_read(UC_X86_REG_DS)==ds and uc.reg_read(UC_X86_REG_SS)==ss and uc.reg_read(UC_X86_REG_BP)==0x1234,'Preserved group/stack/base')
                require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==(1 if kind=='install' else initial_if),'Final IF')
                require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==(0 if kind=='install' else initial_df),'CLD only in3F40')
                counts[kind]+=1;instructions+=active['instructions']
    diagnostics=0;result=InstallResult();device=control.State();good_data=(ctypes.c_uint8*65536)()
    for data_ptr,device_ptr in [(None,ctypes.byref(device)),(good_data,None),(good_data,ctypes.byref(device))]:
        functions['install'](data_ptr,device_ptr,ctypes.byref(result));require(result.status==2,'Native invalid input/profile diagnostic');diagnostics+=1
    functions['install'](None,None,None);diagnostics+=1
    dependencies=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_timer_control.py','tools/validate_timer_callbacks.py']]
    result={'schema':1,'result':'pass','function_ids':[spec[3] for spec in specs],'image_sha256':sha,
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_session_init.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'validator_dependencies':dependencies,'vectors':sum(counts.values()),'vectors_by_operation':dict(counts),'native_only_diagnostics':diagnostics,
            'original_instructions_executed':instructions,
            'limits':'Four isolatedcompleteinitialization entries andnativehelpercomposition, serializedsyntheticgroup/port/vectorprofile. Byte-ring unchangedinallcases; otherindexedresetwriters notexcluded. Originalincidentalregister/flag uses, actualresource/SS/IRQ/caller/fullstate/game/fidelity acceptance remainopen.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
