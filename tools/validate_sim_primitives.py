"""Compare fourteen near arithmetic/state entries with native C primitives.

Synthetic64KiB data only. No simulation callback, resources, dispatch table,
game loop or device executes. Original scratch registers are checked where
exposed; complete caller use of other flags/registers remains a separate gate.
"""
import argparse
from collections import Counter
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


class Product(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['applied','product_low','clamped_high','old_target']]


class Curve(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint16) for name in ['index','half','shifted','mixed_word']]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();library,output=args.library.resolve(),args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    specs={
        'sum':(0x448a,'td2ega_sum_eight_samples','FN-EGA-000371'),
        'product':(0x4612,'td2ega_clamp_product_target','FN-EGA-000378'),
        'interval':(0x4d26,'td2ega_signed_interval_overlap','FN-EGA-000386'),
        'snapshot1':(0x4929,'td2ega_snapshot_stage_one','FN-EGA-000426'),
        'snapshot2':(0x4947,'td2ega_snapshot_stage_two','FN-EGA-000427'),
        'arm50':(0x494d,'td2ega_arm_transition_50','FN-EGA-000428'),
        'arm3c':(0x495d,'td2ega_arm_transition_3c','FN-EGA-000429'),
        'curve':(0x499a,'td2ega_update_curve_record','FN-EGA-000430'),
        'toggle0':(0x49c9,'td2ega_toggle_control_bit','FN-EGA-000431'),
        'toggle1':(0x49cf,'td2ega_toggle_control_bit','FN-EGA-000432'),
        'toggle2':(0x49d5,'td2ega_toggle_control_bit','FN-EGA-000433'),
        'raise':(0x49db,'td2ega_raise_byte_threshold','FN-EGA-000434'),
        'lower':(0x49e1,'td2ega_lower_byte_threshold','FN-EGA-000435'),
        'clear':(0x5427,'td2ega_clear_transition','FN-EGA-000126')}
    dll=ctypes.CDLL(str(library));functions={};byte_ptr=ctypes.POINTER(ctypes.c_uint8)
    for kind,(entry,name,fid) in specs.items():
        fn=getattr(dll,name);fn.restype=None
        if kind=='product':fn.argtypes=[byte_ptr,ctypes.POINTER(Product)]
        elif kind=='interval':fn.argtypes=[ctypes.c_uint16]*4+[ctypes.POINTER(ctypes.c_uint16)];fn.restype=ctypes.c_uint16
        elif kind=='curve':fn.argtypes=[byte_ptr,ctypes.c_uint16,ctypes.POINTER(Curve)]
        elif kind.startswith('toggle'):fn.argtypes=[byte_ptr,ctypes.c_uint16];fn.restype=ctypes.c_uint16
        elif kind.startswith('arm'):fn.argtypes=[byte_ptr,ctypes.c_uint16]
        else:fn.argtypes=[byte_ptr]
        functions[kind]=fn
    rng=random.Random(0x448a4d26);fixtures=[]
    def add(kind,overrides=(),params=()):fixtures.append((kind,list(overrides),params))
    def w(at,value):return at,2,value
    def b(at,value):return at,1,value
    edges=[0,1,2,0x31f,0x320,0x3200,0x7fff,0x8000,0xfffe,0xffff]
    signed_edges=[0,1,2,0x7ffe,0x7fff,0x8000,0x8001,0xfffe,0xffff]
    for values in itertools.product(signed_edges,repeat=4):add('interval',[w(0x3334,values[2]),w(0x3336,values[3])],values)
    for _ in range(4096):
        values=tuple(rng.randrange(65536) for _ in range(4));add('interval',[w(0x3334,values[2]),w(0x3336,values[3])],values)
    for multiplier,sample,enabled,old in itertools.product(edges,edges,[0,1,255],[0,0x7fff,0xffff]):
        add('product',[w(0x3328,multiplier),w(0x52ce,sample),b(0x2f56,enabled),w(0x332c,old)])
    for _ in range(512):add('product',[w(0x3328,rng.randrange(65536)),w(0x52ce,rng.randrange(65536)),b(0x2f56,rng.randrange(256)),w(0x332c,rng.randrange(65536))])
    for value in range(256):add('sum',[b(0x335d+i,value) for i in range(8)]+[w(0x52ce,value*257)])
    for i,value in itertools.product(range(8),[0,1,127,128,254,255]):add('sum',[b(0x335d+j,value if j==i else 0) for j in range(8)])
    for _ in range(128):add('sum',[b(0x335d+i,rng.randrange(256)) for i in range(8)]+[w(0x52ce,rng.randrange(65536))])
    for enabled,first,second in itertools.product([0,1,0xffff],edges[:5],edges[:5]):add('snapshot1',[w(0x9410,enabled),w(0x331e,first),w(0x942e,second)])
    for value in range(256):add('snapshot2',[b(0x3371,value)])
    record_bases=[0,1,0xffb0,0xffc4,0x529e,0x52a2,0x3318,0x337b,0xffff]
    for record,existing in itertools.product(record_bases,[0,1,0xffff]):add('arm50',[w(0x52da,existing)],(record,))
    for record,existing,sample,flag in itertools.product(record_bases,[0,1,0xffff],[0,0x3200,0x3201,0xffff],[0,0x80]):
        # Initialize the target byte BEFORE fixed fields, retaining aliases.
        add('arm3c',[b((record+0x3c)&65535,flag),w(0x52da,existing),w(0x52ce,sample)],(record,))
    for index,input_value in itertools.product(range(256),edges+[43,44,45,0x3fff,0x4000,0x8001]):add('curve',[b(0x533e,index)],(input_value,))
    for _ in range(512):add('curve',[b(0x533e,rng.randrange(256))],(rng.randrange(65536),))
    for kind,offset in [('toggle0',0x37f7),('toggle1',0x37f6),('toggle2',0x37f8),('raise',0x337a),('lower',0x337a)]:
        for value in range(256):add(kind,[b(offset,value)])
    for _ in range(136):add('clear',[w(0x52da,rng.randrange(65536))]+[b(at,rng.randrange(256)) for at in [0x33b6,0x33b7,0x33b8,0x33ba]])
    baseline=bytes((i*17+31)&255 for i in range(65536));counts=Counter();instructions=0;ds,ss,sp=0x5000,0x7000,0x8000
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;starts=set()
        for start,end in [(0x448a,0x44a6),(0x4612,0x4639),(0x4d26,0x4d3f),(0x4929,0x49e7),(0x5427,0x5439)]:
            code=image[0x6c90+start:0x6c90+end];uc.mem_write(cs*16+start,code)
            starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,start))
        active={}

        def code_hook(u,address,size,_):
            require(address in starts,'Primitive escaped code fence');active['instructions']+=1

        def write_hook(u,access,address,size,value,_):
            if active['ss']*16+sp-4<=address and address+size<=active['ss']*16+sp+2:return
            require(ds*16<=address and address+size<=ds*16+65536,'Unexpected primitive memory write: '+active['kind']+' '+hex(address));active['data_writes']+=1

        def interrupt(*_):raise RuntimeError('Unexpected service/IRQ')
        uc.hook_add(UC_HOOK_CODE,code_hook);uc.hook_add(UC_HOOK_MEM_WRITE,write_hook);uc.hook_add(UC_HOOK_INTR,interrupt)
        for kind,overrides,params in fixtures:
            data=bytearray(baseline)
            for at,width,value in overrides:data[at:at+width]=value.to_bytes(width,'little')
            case_ss=ds if kind=='curve' else ss
            if kind=='curve':data[sp-4:sp+2]=b'\xa5'*4+struct.pack('<H',0xf000)
            entry=specs[kind][0];uc.mem_write(ds*16,bytes(data));uc.mem_write(case_ss*16+sp-4,b'\xa5'*4+struct.pack('<H',0xf000))
            ax,bx,bp=0xbeef,0x1234,0x5678
            if kind=='interval':ax,bx=params[:2]
            if kind.startswith('arm'):bp=params[0]
            if kind=='curve':bx=params[0]
            for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_DS,ds),(UC_X86_REG_SS,case_ss),
                (UC_X86_REG_SP,sp),(UC_X86_REG_ES,0x6789),(UC_X86_REG_AX,ax),(UC_X86_REG_BX,bx),(UC_X86_REG_CX,0x3456),
                (UC_X86_REG_DX,0xabcd),(UC_X86_REG_BP,bp),(UC_X86_REG_SI,0x4567),(UC_X86_REG_DI,0x789a),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,value)
            active.update(instructions=0,data_writes=0,ss=case_ss,kind=kind);uc.emu_start(cs*16+entry,cs*16+0xf000,count=128)
            require(uc.reg_read(UC_X86_REG_CS)==cs and uc.reg_read(UC_X86_REG_IP)==0xf000 and uc.reg_read(UC_X86_REG_SP)==sp+2,'Near return/frame')
            require(all(uc.reg_read(reg)==value for reg,value in [(UC_X86_REG_DS,ds),(UC_X86_REG_SS,case_ss),(UC_X86_REG_ES,0x6789),(UC_X86_REG_SI,0x4567),(UC_X86_REG_DI,0x789a)]),'Preserved segments/index registers')
            require(uc.reg_read(UC_X86_REG_EFLAGS)&0x600==0x600,'DF/IF unchanged')
            native_data=(ctypes.c_uint8*65536).from_buffer(data)
            if kind=='interval':
                lower=ctypes.c_uint16();overlap=functions[kind](*params,ctypes.byref(lower))
                require(overlap==((uc.reg_read(UC_X86_REG_EFLAGS)>>6)&1) and lower.value==uc.reg_read(UC_X86_REG_AX),'Signed interval result/zero flag')
                require(uc.reg_read(UC_X86_REG_CX)==0x3456 and uc.reg_read(UC_X86_REG_BX)==bx and active['data_writes']==0,'Interval readonly/preserved caller words')
            elif kind=='product':
                result=Product();functions[kind](native_data,ctypes.byref(result))
                if result.applied:
                    require((result.product_low,result.clamped_high,result.old_target)==(uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_CX)),'Product result words')
                else:require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_CX))==(ax,0xabcd,0x3456),'Disabled product scratch registers')
            elif kind=='curve':
                result=Curve();functions[kind](native_data,params[0],ctypes.byref(result))
                require((result.index,result.half,result.shifted,result.mixed_word)==(uc.reg_read(UC_X86_REG_BP),uc.reg_read(UC_X86_REG_BX),uc.reg_read(UC_X86_REG_CX),uc.reg_read(UC_X86_REG_AX)),'Curve arithmetic/scratch outputs')
            elif kind.startswith('arm'):functions[kind](native_data,params[0])
            elif kind.startswith('toggle'):require(functions[kind](native_data,int(kind[-1]))==0,'Valid toggle selector')
            else:functions[kind](native_data)
            if kind!='interval':require(bytes(uc.mem_read(ds*16,65536))==bytes(data),'Primitive original/native whole data segment')
            counts[kind]+=1;instructions+=active['instructions']
    diagnostics=0
    data=bytearray(baseline);native_data=(ctypes.c_uint8*65536).from_buffer(data)
    for selector in [3,0xffff]:
        require(functions['toggle0'](native_data,selector)==2 and bytes(data)==baseline,'Invalid native toggle selector diagnostic');diagnostics+=1
    result={'schema':1,'result':'pass','function_ids':[spec[2] for spec in specs.values()],'image_sha256':sha,
            'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sim_primitives.c').read_bytes()).hexdigest(),
            'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'vectors':sum(counts.values()),'vectors_by_operation':dict(counts),'native_only_diagnostics':diagnostics,
            'original_instructions_executed':instructions,
            'limits':'Fourteen isolated near entries, twelve nativeexports, synthetic64KiB data. State effects andnamed arithmetic outputs only; otherincidental flags/registers, validcaller/dispatch/record domains, fullsimulation/core/resource/game/fidelity acceptance remainopen. NoCPUinterpreter ororiginaltables inC.'}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
