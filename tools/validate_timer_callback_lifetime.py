"""Executeactual3FD9 setup tail and1BEB exit call with callback helpers.

Only opaque registrations and synthetic port state. Callback bodies never run.
The exit slice stops before either mutable state-return epilogue.
"""
import argparse
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


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    output=ap.parse_args().output.resolve()
    require(not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text())
    offsets={ip for f in graph['functions'] if f['entry'] in ['06C9:601C','06C9:614C'] for ip in f['instructions']}
    offsets.update([0x3fd9,0x3fde,0x3fe1,0x3fe2,0x3fe3,0x3fe8,0x3feb,0x3fee,0x3fef,0x3ff0,0x3ff5,0x3ff8,0x1beb])
    ctl_path=ROOT/'analysis/build/timer-control-repro/td2ega_timer_control.dll'
    cb_path=ROOT/'analysis/build/timer-callbacks-repro/td2ega_timer_callbacks.dll'
    ctl=ctypes.CDLL(str(ctl_path)).td2ega_timer_install_fixed
    ctl.argtypes=[ctypes.POINTER(control.State),ctypes.POINTER(control.Result)];ctl.restype=None
    cb=ctypes.CDLL(str(cb_path)).td2ega_callback_add
    cb.argtypes=[ctypes.POINTER(control.CallbackWords),ctypes.c_uint16,ctypes.c_uint16,ctypes.POINTER(CallbackResult)];cb.restype=None
    baseline=b'\xa5'*65536;rows=[];ds,ss,sp=0x5000,0x7000,0x8000
    for load in [0x1000,0x2345]:
        relocated=bytearray(image)
        for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
        cs=load+0x6c9
        for port_seed in [0,3,0xa5,255]:
            for initial_if in [0,1]:
                uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);uc.mem_write(load*16,bytes(relocated))
                state=control.State();state.current_cs=cs;state.vector_offset=0x1234;state.vector_segment=0x4321
                state.field_5e95=0x5a;state.pic_mask=port_seed;state.speaker_control=port_seed;state.control_43=0x9d
                for i in range(12):state.callbacks.word[i]=0x1111+i
                for i in range(40):state.histogram[i]=i+1
                uc.mem_write(ds*16,control.data_view(state,baseline));uc.mem_write(0x20,struct.pack('<HH',state.vector_offset,state.vector_segment))
                active={'stop':None,'instructions':0,'events':[],'ports':{0x21:port_seed,0x61:port_seed,0x43:0x9d,0x40:0}}

                def code(u,address,size,_):
                    ip=u.reg_read(UC_X86_REG_IP)
                    if ip==active['stop']:
                        u.emu_stop();return
                    require(u.reg_read(UC_X86_REG_CS)==cs and ip in offsets,'Lifetime composition escaped body fence')
                    op=u.mem_read(address,1)[0]
                    if op in [0xfa,0xfb]:active['events'].append([0,0,int(op==0xfb)])
                    active['instructions']+=1

                def write(u,access,address,size,value,_):
                    require(ds*16<=address and address+size<=ds*16+65536 or ss*16+sp-32<=address and address+size<=ss*16+sp+8 or 0x20<=address and address+size<=0x24,'Unexpected composition writer')

                def port_in(u,port,size,_):
                    require(size==1 and port in [0x21,0x61],'Unexpected portread');value=active['ports'][port];active['events'].append([1,port,value]);return value

                def port_out(u,port,size,value,_):
                    require(size==1 and port in [0x21,0x61,0x43,0x40],'Unexpected portwrite');active['ports'][port]=value;active['events'].append([2,port,value])

                def interrupt(*_):raise RuntimeError('Unexpected actual IRQ/service')
                uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write);uc.hook_add(UC_HOOK_INTR,interrupt)
                uc.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);uc.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)

                def guest(entry,stop=None,args=()):
                    uc.mem_write(ss*16+sp-32,b'\xa5'*32+struct.pack('<HH',0x100,0x8000)+b''.join(struct.pack('<H',v) for v in args))
                    for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                        (UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x1234),(UC_X86_REG_EFLAGS,2|(initial_if<<9))]:uc.reg_write(reg,value)
                    active.update(stop=stop,events=[])
                    uc.emu_start(cs*16+entry,0x80100,count=1024)
                    require(uc.reg_read(UC_X86_REG_SP)==sp+(0 if stop else 4),'Composition frame')
                    require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP))==((cs,stop) if stop else (0x8000,0x100)),'Composition return/stop')

                def compare_state():
                    require(bytes(uc.mem_read(ds*16,65536))==control.data_view(state,baseline),'Original/native combined data')
                    require(struct.unpack('<HH',bytes(uc.mem_read(0x20,4)))==(state.vector_offset,state.vector_segment),'Combined vector')

                guest(0x3fd9)
                result=control.Result();ctl(ctypes.byref(state),ctypes.byref(result))
                for offset in [0x6269,0x403b]:
                    cr=CallbackResult();cb(ctypes.byref(state.callbacks),offset,cs,ctypes.byref(cr));require(cr.status==0,'Native setup registration')
                require(active['events']==[[e.kind,e.port,e.value] for e in result.events[:result.event_count]],'Setup port/IF composition')
                compare_state();installed=list(state.callbacks.word[:6]);require(installed[:4]==[0x6269,cs,0x403b,cs] and installed[5]==0,'Two callbacks andterminator')
                guest(0x1beb,0x1bf0)
                ctl(ctypes.byref(state),ctypes.byref(result));compare_state()
                require(active['events']==[[e.kind,e.port,e.value] for e in result.events[:result.event_count]],'Exit installer port/IF composition')
                cleared=list(state.callbacks.word[:6]);require(cleared[:2]==[0,0] and cleared[2:4]==[0x403b,cs],'Logical empty list retains stale later slot')
                guest(0x614c,args=(0x75ea,cs))
                cr=CallbackResult();cb(ctypes.byref(state.callbacks),0x75ea,cs,ctypes.byref(cr));compare_state()
                require(list(state.callbacks.word[:4])==[0x75ea,cs,0x403b,0],'Music registration hides stale simulation slot')
                rows.append({'load_segment':load,'port_seed':port_seed,'initial_if':initial_if,'installed_words':installed,
                             'after_exit_words':cleared,'after_music_words':list(state.callbacks.word[:6]),'instructions':active['instructions']})
    dependencies=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_timer_control.py','tools/validate_timer_callbacks.py']]
    libraries=[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [ctl_path,cb_path]]
    result={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'vectors':len(rows),'original_instructions_executed':sum(r['instructions'] for r in rows),'validator_dependencies':dependencies,
            'native_libraries':libraries,'cases':rows,
            'conclusion':'Actual3FD9tail installs601C thenregisters6269/403B. Actual1BEBcall601C clearsfirstcallbackpair beforestate-returnepilogue; laterrowsremainstale butfirstsegment0 terminateswalk. Subsequent75EA registration clearsnextsegment, hidingstale403B. These effectsagreewithcombinednative timercontrol/callbacks.',
            'limits':'Fenced caller tails/syntheticdata/ports only; no callbackbody oractualIRQ, earlier3F40/1B2C/sessionguards, completephaseownership/movingresourceexclusion, timerunits orgame/fidelity acceptance. StopsbeforeconditionalCLC/RETFepilogue.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
