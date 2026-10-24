"""Compare601C/6059/610A to serialized native port/vector effect model.

Port callbacks are synthetic state only. No real I/O, IRQ, old handler, timer
cadence or external086C reader executes. Divide faults stop at their prefix.
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *


def require(test,message):
    if not test:raise RuntimeError(message)


class CallbackWords(ctypes.Structure):
    _fields_=[('word',ctypes.c_uint16*12)]


class State(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['current_cs','vector_offset','vector_segment','saved_offset','saved_segment',
        'reload','remaining','relay_remaining','histogram_index']]+[('histogram',ctypes.c_uint16*40),('callbacks',CallbackWords)]+[
        (name,ctypes.c_uint8) for name in ['field_5e94','field_5e95','pic_mask','speaker_control','control_43']]


class Event(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['kind','port','value']]


class Result(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['status','enables_interrupts','divisor','event_count']]+[('events',Event*32)]


WORD_FIELDS={'saved_offset':0x5e88,'saved_segment':0x5e8a,'relay_remaining':0x5e96,'reload':0x5e98,'remaining':0x5e9a,'histogram_index':0x5e9c}


def data_view(state,baseline):
    data=bytearray(baseline)
    for name,offset in WORD_FIELDS.items():struct.pack_into('<H',data,offset,getattr(state,name))
    data[0x5e94]=state.field_5e94;data[0x5e95]=state.field_5e95
    data[0x5e9e:0x5eee]=struct.pack('<40H',*state.histogram)
    data[0x5f12:0x5f2a]=struct.pack('<12H',*state.callbacks.word)
    return bytes(data)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();library,output=args.library.resolve(),args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries={'06C9:601C','06C9:6059','06C9:610A'}
    offsets={ip for f in graph['functions'] if f['entry'] in entries for ip in f['instructions']}
    dll=ctypes.CDLL(str(library));functions={}
    for name,kind in [('td2ega_timer_install_divisor','divisor'),('td2ega_timer_install_fixed','fixed'),('td2ega_timer_cleanup','cleanup')]:
        fn=getattr(dll,name);fn.restype=None
        fn.argtypes=[ctypes.POINTER(State)]+([ctypes.c_uint16] if kind=='divisor' else [])+[ctypes.POINTER(Result)]
        functions[kind]=fn
    template=State()
    template.saved_offset=0x4567;template.saved_segment=0x5678;template.reload=0x6789;template.remaining=0x789a
    template.relay_remaining=0x89ab;template.histogram_index=0x9abc
    for i in range(40):template.histogram[i]=(i*713+1)&65535
    for i in range(12):template.callbacks.word[i]=(i*0x1111+0x1234)&65535
    template.field_5e94=0xa5;template.field_5e95=0x5a;template.control_43=0x9d
    baseline=bytes((i*29+7)&255 for i in range(65536));counts=Counter();faults=0;instructions=0;ds,ss,sp=0x5000,0x7000,0x8000
    for load in [0x1000,0x2345]:
        cs=load+0x6c9;active={}

        def code_hook(u,address,size,_):
            require(u.reg_read(UC_X86_REG_CS)==cs and u.reg_read(UC_X86_REG_IP) in offsets,'Timer control escaped instruction fence')
            op=u.mem_read(address,1)[0]
            if op in [0xfa,0xfb]:active['events'].append([0,0,int(op==0xfb)])
            active['instructions']+=1

        def write_hook(u,access,address,size,value,_):
            if ss*16+sp-4<=address and address+size<=ss*16+sp+6:return
            require(ds*16<=address and address+size<=ds*16+65536 or 0x20<=address and address+size<=0x24,'Unexpected timer write')
            flag=(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1
            if address<0x24 or ds*16+0x5f12<=address<ds*16+0x5f16:require(flag==0,'Vector/firstcallback writes must be masked')
            if ds*16+0x5e9e<=address<ds*16+0x5eee:require(flag==1,'Histogram reset occurs afterSTI, beforelaterCLI')

        def port_in(u,port,size,_):
            require(size==1 and port in [0x21,0x61],'Unexpected input port/width')
            value=active['ports'][port];active['events'].append([1,port,value]);return value

        def port_out(u,port,size,value,_):
            require(size==1 and port in [0x21,0x61,0x43,0x40],'Unexpected output port/width')
            active['events'].append([2,port,value]);active['ports'][port]=value

        def interrupt(u,number,_):
            require(number==0 and active['kind']=='divisor','Unexpected actual IRQ/service')
            active['fault']=True;u.emu_stop()

        def fresh_cpu():
            cpu=Uc(UC_ARCH_X86,UC_MODE_16);cpu.mem_map(0,0x100000)
            cpu.mem_write(cs*16+0x601c,image[0x6c90+0x601c:0x6c90+0x614c])
            cpu.hook_add(UC_HOOK_CODE,code_hook);cpu.hook_add(UC_HOOK_MEM_WRITE,write_hook);cpu.hook_add(UC_HOOK_INTR,interrupt)
            cpu.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);cpu.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
            return cpu
        uc=fresh_cpu()
        for kind in ['divisor','fixed','cleanup']:
            divisors=[0,1,2,3,4,0x2e9c,0x7fff,0x8000,0xffff,0xfffe,0xfffd] if kind=='divisor' else [0]
            for divisor,own_offset,own_segment,pic,speaker,initial_if,initial_df in itertools.product(divisors,[0,1],[0,1],[0,3,0xa5,255],[0,3,0xa5,255],[0,1],[0,1]):
                # Fenced exceptions leave internal fault-delivery state in a
                # reused Unicorn CPU. Do not continue that CPU into a fixture.
                if active.get('fault'):uc=fresh_cpu()
                state=State.from_buffer_copy(bytes(template));state.current_cs=cs
                state.vector_offset=0x61bf if own_offset else 0x1234;state.vector_segment=cs if own_segment else 0x4321
                state.pic_mask=pic;state.speaker_control=speaker
                uc.mem_write(ds*16,data_view(state,baseline));uc.mem_write(0x20,struct.pack('<HH',state.vector_offset,state.vector_segment))
                uc.mem_write(ss*16+sp-4,b'\xa5'*4+struct.pack('<3H',0x100,0x8000,divisor))
                entry={'divisor':0x6059,'fixed':0x601c,'cleanup':0x610a}[kind]
                for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),
                    (UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x1234),(UC_X86_REG_SI,0x2345),(UC_X86_REG_DI,0x3456),
                    (UC_X86_REG_EFLAGS,3|(initial_if<<9)|(initial_df<<10))]:uc.reg_write(reg,value)
                active.update(events=[],ports={0x21:pic,0x61:speaker,0x43:state.control_43,0x40:0},instructions=0,kind=kind,fault=False)
                uc.emu_start(cs*16+entry,0x80100,count=512)
                result=Result();before=bytes(state)
                if kind=='divisor':functions[kind](ctypes.byref(state),divisor,ctypes.byref(result))
                else:functions[kind](ctypes.byref(state),ctypes.byref(result))
                native_events=[[e.kind,e.port,e.value] for e in result.events[:result.event_count]]
                require(native_events==active['events'],'Ordered port/IF effects')
                require(result.status==int(active['fault']),'Divide fault prefix')
                require(bytes(uc.mem_read(ds*16,65536))==data_view(state,baseline),'Full data-state effect')
                require(struct.unpack('<HH',bytes(uc.mem_read(0x20,4)))==(state.vector_offset,state.vector_segment),'Vector ownership/save/install result')
                require([active['ports'][p] for p in [0x21,0x61,0x43]]==[state.pic_mask,state.speaker_control,state.control_43],'Port snapshot state')
                if active['fault']:
                    require(bytes(state)==before and not active['events'],'Divide fault no state/port effects')
                    require(uc.reg_read(UC_X86_REG_CS)==cs and uc.reg_read(UC_X86_REG_IP)==0x6061 and uc.reg_read(UC_X86_REG_SP)==sp-2,'Divide fault frame/fence')
                    faults+=1
                else:
                    require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
                    require(all(uc.reg_read(reg)==value for reg,value in [(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x1234),(UC_X86_REG_SI,0x2345),(UC_X86_REG_DI,0x3456)]),'Preserved registers')
                enabled=not active['fault'] and (kind!='cleanup' or own_offset and own_segment)
                require(result.enables_interrupts==int(enabled),'Native interrupt-enable effect')
                require((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1==(1 if enabled else initial_if),'Final IF')
                require((uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1==initial_df,'DF preservation')
                counts[kind]+=1;instructions+=active['instructions']
    diagnostics=0
    for kind in functions:
        result=Result()
        if kind=='divisor':functions[kind](None,3,ctypes.byref(result));functions[kind](None,3,None)
        else:functions[kind](None,ctypes.byref(result));functions[kind](None,None)
        require(result.status==2,'Native null-state diagnostic');diagnostics+=2
    result={'schema':1,'result':'pass','function_ids':['FN-EGA-000147','FN-EGA-000148','FN-EGA-000149'],'image_sha256':sha,
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_control.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'vectors':sum(counts.values()),'vectors_by_operation':dict(counts),'divide_fault_prefixes':faults,'native_only_diagnostics':diagnostics,
            'original_instructions_executed':instructions,
            'limits':'Serialized syntheticport/vector/data snapshots only. Divisors/rawcounterwords have nounitsassigned; external086C reader untouched. No realhardware/IRQ/oldhandler/cadence, fullconcurrency/caller/platform/game/fidelity acceptance.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
