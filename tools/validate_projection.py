"""Compare21C3 and actual13A3:0038, including signed IDIV fault/work prefixes."""
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
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('fault_site',C.c_uint16)]+[(n,C.c_uint32) for n in ['work','iterations','lookups','scans']]+[('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));project=dll.td2ega_projection_step;project.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];project.restype=None;lookup=dll.td2ega_signed_byte_lookup;lookup.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(StateRegisters)];lookup.restype=C.c_uint16
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:21C3','13A3:0038']];require(len(fenced)==2,'Projection/lookup fences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
    cases=[('projection',desc,math,table,1000,same) for desc,math,table,same in itertools.product(range(8),range(8),range(4),[0,1])]
    cases += [('divide_zero',0,1,0,1000,same) for same in [0,1]]+[('divide_overflow',0,6,0,1000,same) for same in [0,1]]
    cases += [('work_prefix',desc,math,table,budget,same) for desc,math,table,budget,same in itertools.product([0,7],[1,6],[0,1],[0,1,2,3,10,20],[0,1])]
    cases += [('lookup',al,value,0,0,same) for al,value,same in itertools.product(range(256),[0,1,0x7fff,0x8000,0xffff,0x1234,0xff80],[0,1])]
    for load in [0x1000,0x2345]:
        cs,hs,ds=load+0x6c9,load+0x13a3,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={((load+int(f['entry'][:4],16))*16+ip) for f in fenced for ip in f['instructions']};u=None
        def code(cpu,address,size,_):
            require(address in starts,'Projection escaped fence '+hex(address))
            if address in [cs*16+0x21c5,cs*16+0x23d0]:
                if active['work']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['work']+=1;active['iterations' if address==cs*16+0x21c5 else 'scans']+=1
            if address==hs*16+0x38:active['lookups']+=1
            if address==cs*16+0x23fa:active['pre_divide_flags']=u.reg_read(UC_X86_REG_EFLAGS)
            active['instructions']+=1;active['sites'].add(address-load*16)
        def interrupt(cpu,num,_):
            require(num==0 and u.reg_read(UC_X86_REG_CS)==cs and u.reg_read(UC_X86_REG_IP)==0x23fa,'Only actualIDIV dividefault');active['fault']=True;u.emu_stop()
        for category,desc,math,table,budget,same in cases:
            if u is None:u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
            ss=ds if same else 0x9000;data=bytearray(base);is_lookup=category=='lookup';rng=random.Random(desc*1009+math*313+table)
            def put(at,v):struct.pack_into('<H',data,ds*16+(at&65535),v&65535)
            if is_lookup:
                al=desc;index=al if al<128 else 256-al;put(0x5560+2*index,math)
            else:
                offsets=[0,1,7,8,25,0xffff,0x8000,0x7fff];pointer=(0x3b34+offsets[math])&65535
                for i in range(25):data[ds*16+((pointer-i)&65535)]=((i*17+desc*13)&127)|(128 if (i+math)&1 else 0)
                flags_values=[0,8,0x40,0x80,0x88,0xc0,0xff,1];signed_values=[0,1,0x7f,0x80,0xff,0x7e,0x81,8]
                for i in range(128):put(0x347e+4*i,flags_values[(i+desc)%8]|(signed_values[(i+math)%8]<<8));put(0x3480+4*i,signed_values[(i+desc+math)%8]|(((i*31+desc)&255)<<8))
                for i in range(129):put(0x5560+2*i,[i*3,-i*257,[0,1,0x7fff,0x8000,0xffff,0x1234,0xff80][i%7],i*499][desc%4])
                weights=[0,1,0xfff,0x7fff,0x8000,0xffff,0x100,0x4000];widths=[0,1,4,16,80,0x7fff,0x8000,0xffff]
                for i in range(25):put(0x2728+2*i,weights[(i+desc)%8]);put(0x26f6+2*i,weights[(i+math)%8]);put(0x275a+2*i,widths[(i+desc+math)%8])
                fields={0x2c26:pointer,0x700:(pointer-[0,1,7,8,0xffff,24,0x8000,0x7fff][desc])&65535,0x2c64:[0,1,0x7fff,0x8000,0xffff,0x100,0xff00,0x4000][math],0x2c22:[0,1,0x7fff,0x8000,0xffff,0x100,0xff00,0x4000][desc],0x2c24:[0xba00,0xba01,0,0x45ff,0x4600,0x7fff,0x8000,0xffff][math],0x2c20:[0,1,0x7fff,0x8000,0xffff,0x100,0xff00,0x4000][(desc+math)%8],0x2c2a:17,0x2c66:[0,80,0x7fff,0x8000][table],0x2c2e:[80,0,0x8000,0xffff][table],0x2c2c:[80,0,0x7fff,0x8000][table],0x2c68:[0,80,0x7fff,0x8000][table],0x2c7e:[0,1,0x7fff,0x8000][table]}
                for at,v in fields.items():put(at,v)
                data[ds*16+0x2c96]=rng.randrange(256);data[ds*16+0x2c97]=flags_values[desc];data[ds*16+0x2c98]=flags_values[(desc+1)%8];data[ds*16+0x37f6]=math&1
                entries={0:[],1:[(1,30,0,255)],2:[(1,4,0,0xffff),(8,15,0xffff,0x8000),(16,30,0x7fff,0)],3:[(1,0xffff,0,1)]}[table]
                if category=='divide_zero':entries=[(1,1,0,1)]
                if category=='divide_overflow':entries=[(1,0xffff,0,0x7fff)]
                for i,row in enumerate(entries):
                    for j,v in enumerate(row):put(0x37a6+i*8+j*2,v)
            frame=struct.pack('<2H',0x100,0x1111) if is_lookup else struct.pack('<H',0x100);data[ss*16+sp-8:ss*16+sp+len(frame)+4]=b'\xa5'*8+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers((0xa500|desc) if is_lookup else 0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);entrycs=hs if is_lookup else cs;entryip=0x38 if is_lookup else 0x21c3;end=0x11210 if is_lookup else cs*16+0x100
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,entrycs),(UC_X86_REG_IP,entryip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            active.update(work=0,iterations=0,scans=0,lookups=0,limit=budget,prefix=False,fault=False,instructions=0,sites=set());u.emu_start(entrycs*16+entryip,end,count=500000);label=f'{load:x}/{category}/{desc}/{math}/{table}/{budget}/{same}';require(active['prefix'] or active['fault'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111 if is_lookup else cs,0x100,sp+(4 if is_lookup else 2)),'Original return/prefix/fault '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data)
            if is_lookup:r=StateRegisters();require(lookup(bus,len(bus),C.byref(incoming),C.byref(r))==0,'Native lookup status');coverage['standalone_lookup']+=1
            else:
                out=Result();project(bus,len(bus),C.byref(incoming),budget,C.byref(out));require(out.status==(1 if active['fault'] else 3 if active['prefix'] else 0),'Native projectionstatus '+label);require(out.work==active['work'] and out.iterations==active['iterations'] and out.scans==active['scans'] and out.lookups==active['lookups'],'Work/iteration/scan/lookup counts '+label);require(out.fault_site==(0x23fa if active['fault'] else 0),'Faultsite '+label);r=out.returned;coverage['projection_fault' if active['fault'] else 'projection_prefix' if active['prefix'] else 'projection_normal']+=1
            actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-8:ss*16+sp]=expected[ss*16+sp-8:ss*16+sp];require(actual==expected,'Full nonframebus '+label);require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require(((active['pre_divide_flags'] if active['fault'] else u.reg_read(UC_X86_REG_EFLAGS))&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF/pre-IDIV-faultCF '+label);require(bytes(u.mem_read(ss*16+sp,len(frame)+4))==frame+b'\xa5'*4,'Rootframeguard '+label);coverage[category]+=1;coverage['same_DS_SS_'+str(same)]+=1;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
            if active['fault']:u=None
    missing=sorted((address-load*16) for address in starts if address-load*16 not in sites);require(not missing,'Unexercised instruction sites '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000089','FN-EGA-000254'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_projection.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete21C3+actual13A30038 serializedDS/table/list/indexeddata/25iteration body andsignedALlookup, arithmeticflags/unsignedMUL/signedIDIVfaultprefixes/workprefixes/CFIFDF andnear-vs-farreturns compared. FreshCPUafteractualdividefault; faultCF comparedwithpre-IDIVflags, no post-IDIVarithmeticflagclaim. Original tablecontents/geometry/units/callerbounds/listlifetimes/DS-SSintegration/renderer/IRQ/core/game/fidelity remainopen; no resource decode. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
