"""Compare1E59 and actual780E with explicit SS/DS views and divide prefixes."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_music_tick import Registers,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','bp','table_offset','record_offset']]+[(n,C.c_uint32) for n in ['steps','samples','deleted']]+[('registers',Registers)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_prepare_records;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint32,C.POINTER(Result)];fn.restype=None
    cases=[]
    for first,second,multiplier in itertools.product(range(51),[0,1,3,49,50],[0,1,1000]):cases.append(('all_record_count_boundaries',{'first':first,'second':second,'multiplier':multiplier}))
    for threshold,cursor,pattern in itertools.product([0,1,2,127,128,254,255],[0,1,255,256,65535],range(4)):cases.append(('delete_threshold_cursor_patterns',{'first':49,'second':49,'threshold':threshold,'cursor':cursor,'pattern':pattern,'multiplier':1000}))
    boundary=[0,1,999,1000,1001,0x7fff,0x8000,0xffff]
    for multiplier,value,second in itertools.product(boundary,boundary,[False,True]):cases.append(('multiply_divide_prefixes',{'first':0 if second else 1,'second':1 if second else 0,'multiplier':multiplier,'value':value}))
    for first,second in itertools.product([0,1,3,4,49,50],[0,1,3,4,49,50]):cases.append(('independent_SS_without_deletion',{'first':first,'second':second,'multiplier':1000,'separate_ss':True}))
    for alias in [0x2ed,0x2d4,0x1b4]:cases.append(('conditional_SS_alias_writes',{'first':0 if alias==0x2d4 else 1,'second':1 if alias==0x2d4 else 0,'multiplier':1000,'value':1,'alias':alias,'cursor':0x100}))
    rng=random.Random(0x1e59)
    for _ in range(2048):cases.append(('varied_terminated_tables',{'first':rng.randrange(50),'second':rng.randrange(50),'multiplier':rng.randrange(2001),'threshold':rng.randrange(256),'cursor':rng.randrange(65536),'pattern':rng.randrange(4),'value':rng.randrange(65536),'type':rng.randrange(1,256)}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:1E59','06C9:780E']];require(len(fenced)==2,'Caller/sampler fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];coverage=Counter();vectors=instructions=faults=0;sites=set();active={};sp=0xe000
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def fetch(u,address,size,_):
            require(address in starts,'Record preparation escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address==cs*16+0x780e:
                require(bytes(u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))==struct.pack('<2H',0x1e7e,cs),'Actualsampler farframe');active['samples']+=1
            if address==cs*16+0x1e84:active['deleted']+=1
        def interrupt(u,num,_):require(num==0 and u.reg_read(UC_X86_REG_IP)==0x1ea7,'ExpectedDIVoverflow only');active['fault']=True;u.emu_stop()
        def make_cpu():
            cpu=Uc(UC_ARCH_X86,UC_MODE_16);cpu.mem_map(0,0x100000);cpu.hook_add(UC_HOOK_CODE,fetch);cpu.hook_add(UC_HOOK_INTR,interrupt);return cpu
        uc=None
        for category,c in cases:
            if uc is None:uc=make_cpu()
            ss=ds+c['alias'] if 'alias' in c else 0x9000 if c.get('separate_ss') else ds;data=bytearray(base);data[ss*16+0x3813:ss*16+0x3b33]=bytes(800);pattern=c.get('pattern',0);ring=bytes(0 if pattern==0 else 255 if pattern==1 else i if pattern==2 else [0x80,0x7f][i&1] for i in range(256));data[ds*16+0x66e8:ds*16+0x67e8]=ring
            for table,count in [(0x3813,c['first']),(0x39a3,c['second'])]:
                for i in range(count):
                    at=ss*16+table+i*8;data[at:at+8]=bytes([c.get('type',1),0x55])+struct.pack('<H',c.get('value',(i*317+11)&65535))+bytes([0x66,0x77])+struct.pack('<H',0xaaaa)
            struct.pack_into('<H',data,ds*16+0x380d,c.get('multiplier',1000));data[ds*16+0x920c]=(-c.get('threshold',0))&255;struct.pack_into('<H',data,ds*16+0x66e6,c.get('cursor',0));frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-32:ss*16+sp+8]=b'\xa5'*32+frame+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10);incoming=Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1)
            for reg,val in list(zip(regids,values(incoming)[:8]))+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x1e59),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            active.update(instructions=0,samples=0,deleted=0,sites=set(),fault=False,ss=ss);uc.emu_start(cs*16+0x1e59,0x11210,count=100000);label=f'{load:x}/{category}/{c}'
            if active['fault']:require(uc.reg_read(UC_X86_REG_SP)==sp-2,'DIVprefixframe '+label)
            else:require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Originalfarreturn '+label)
            gb=(C.c_uint8*len(data)).from_buffer_copy(data);result=Result();fn(gb,len(data),ss,C.byref(incoming),0x5678,10000,C.byref(result));require(result.status==(1 if active['fault'] else 0),'Originalreturn/fault domain '+label);actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Full nonstack bus '+label);r=result.registers;require([uc.reg_read(reg) for reg in regids]==values(r)[:8] and uc.reg_read(UC_X86_REG_BP)==result.bp,'Scratch/segments/BP '+label);require(uc.reg_read(UC_X86_REG_SS)==ss and ((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'SS/IFDF '+label);require(bytes(uc.mem_read(ss*16+sp-2,2))==struct.pack('<H',0x5678) and bytes(uc.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'SavedBP/rootframe '+label);require((result.samples,result.deleted)==(active['samples'],active['deleted']),'Consumption/deletion counts '+label)
            if result.status==0 and ss==ds and c['first']<50 and c['second']<50:require(result.samples==max(c['first']-3,0)+max(c['second']-3,0),'Terminatedtable consumption invariant '+label)
            coverage[category]+=1;coverage['divide_fault_prefix']+=int(active['fault']);coverage['normal_return']+=int(not active['fault']);coverage['same_DS_SS_'+str(ss==ds)]+=1;instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
            if active['fault']:faults+=1;uc=None # Never reuse an x86 CPU after a fenced DIV exception.
    deps=['src/recovered/td2ega_byte_ring.c','src/recovered/td2ega_byte_ring.h'];record={'schema':1,'function_id':'FN-EGA-000083','result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_prepare_records.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps]+[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':sum(len(f['instructions']) for f in fenced),'original_DIV_fault_prefixes':faults,'limits':'Complete1E59+actual780E andlinkednativebyte-source composition, serializedsynthetic20bitbus. SS BP+SI fields distinctfromDSglobals/deletion/ring; count/threshold/cursor/overlap/divideprefix andconsumption order retained. FreshCPUafterDIVfault; nativebudgetdiagnostics separate. ConditionalSSalias fixtures are notactualcaller/resetproof. No realresources/IRQ/exclusion/fullstate/gamecore/RNGmeaning/gameplay/fidelity acceptance.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
