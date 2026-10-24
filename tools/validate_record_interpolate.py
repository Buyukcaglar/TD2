"""Compare2477 plusactualself-modifying06C3, SS/DS views and RET6 argument pool."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','stack_segment','current_sp','return_bytes']]+[(n,C.c_uint32) for n in ['work','iterations','helper_calls','attribute_words','line_words']]+[('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_record_interpolate;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:2477','06C9:06C3']];require(len(fenced)==2,'Caller/helper fences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000;sources=[0x2a2c,0x2a5e,0x2ac2,0x2af4,0x2bee,0x2bbc];forms=[(0x40,0x40),(0x48,0x48),(0x40,0x48),(0x48,0x40)];cases=list(itertools.product(range(9),[0,1],range(4),[2,0x203,0x402,0x603],[4096]));cases += list(itertools.product([2,5,8],[0,1],[0,1],[2,0x603],[0,1,2,10,100,500]))
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for f in fenced for ip in f['instructions']}
        for pattern,same,form,flags,budget in cases:
            ss=ds if same else 0x9000;data=bytearray(base);data[cs*16+0x71f],data[cs*16+0x735]=forms[form]
            if pattern==0:heights=[8]*25
            elif pattern==1:heights=[17-i for i in range(25)]
            elif pattern==2:heights=[30-3*i for i in range(25)]
            elif pattern==3:heights=list(range(25))
            elif pattern==4:heights=([0x7fff,0x8000,0xffff,17,0,1,8,9]*4)[:25]
            else:
                height={5:1,6:1,7:0x104e,8:0xe69}[pattern];heights=[height+259]+[height]*24
            minima=[];minimum=17
            for height in heights:
                signed=height if height<0x8000 else height-65536;minimum=min(minimum,signed);minima.append(minimum)
            minima[0]=17
            if pattern>=5:minima[0]=heights[1]+(257 if pattern in [6,7] else 258)
            for i in range(25):
                struct.pack_into('<H',data,ds*16+0x2b26+2*i,heights[i]&65535);struct.pack_into('<H',data,ds*16+0x2b58+2*i,minima[i]&65535)
                for row,source in enumerate(sources):struct.pack_into('<H',data,ds*16+source+2*i,((i*7+row*13)%120-20)&65535)
                struct.pack_into('<H',data,ds*16+0x2bbc+2*i,1 if pattern==8 else (0xab00|i))
                if not same:
                    struct.pack_into('<H',data,ss*16+0x2b26+2*i,(heights[i]+(3 if i%3==0 and pattern<5 else 0))&65535)
                    for row,source in enumerate(sources):struct.pack_into('<H',data,ss*16+source+2*i,(i*11-row*17+60)&65535)
            struct.pack_into('<H',data,ds*16+0x5348,80);frame=struct.pack('<H',0x100);data[ss*16+sp-64:ss*16+sp+6]=b'\xa5'*64+frame+b'\xa5'*4;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);active={'work':0,'iterations':0,'helper_calls':0,'attribute_words':0,'line_words':0,'prefix':False,'instructions':0,'sites':set()}
            def code(cpu,address,size,_):
                require(address in starts,'2477/06C3 escapedfence');ip=address-cs*16;rep_word=ip in [0x252d,0x73d] and u.reg_read(UC_X86_REG_CX)!=0;tick=ip in [0x2481,0x6f1,0x6f9,0x6ff,0x709,0x70f,0x71d,0x72f] or rep_word
                if tick:
                    if active['work']==budget:active['prefix']=True;u.emu_stop();return
                    active['work']+=1
                if ip==0x2481:active['iterations']+=1
                if ip==0x6c3:
                    active['helper_calls']+=1;current=u.reg_read(UC_X86_REG_SP);ret=struct.unpack('<H',u.mem_read(ss*16+current,2))[0];require(ret in [0x2533,0x2536,0x2539,0x253c,0x253f],'Fivecaller nearframes/RET6pool')
                if ip==0x252d and rep_word:active['attribute_words']+=1
                if ip in [0x6f1,0x726,0x738] or (ip==0x73d and rep_word):active['line_words']+=1
                if ip in [0x71f,0x735]:require(bytes(u.mem_read(address,1))[0] in [0x40,0x48],'Patchedarithrewrite')
                active['instructions']+=1;active['sites'].add(ip)
            def interrupt(*_):raise RuntimeError('Unexpectedinterrupt')
            u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2477),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            u.emu_start(cs*16+0x2477,cs*16+0x100,count=1000000);label=f'{load:x}/{pattern}/{same}/{form}/{flags:x}/{budget}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'OriginalnearRET/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),budget,C.byref(out));require(out.status==(3 if active['prefix'] else 0),'Nativestatus '+label);require(all(getattr(out,n)==active[n] for n in ['work','iterations','helper_calls','attribute_words','line_words']),'Work/call/write counts '+label);require(out.current_sp==u.reg_read(UC_X86_REG_SP) and out.return_bytes==2 and out.stack_segment==ss,'VirtualnearRET6 pool/currentSP '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Fullnonframebus/orderedargs/aliases '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers/SSpreviousDS-current '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Rootnearframeguard '+label)
            if pattern in [6,7] and not active['prefix']:require(out.helper_calls==0,'CL1notCX1directpoint branch '+label)
            coverage['pattern_'+str(pattern)]+=1;coverage['original_work_prefix' if active['prefix'] else 'original_normal_nearRET']+=1;coverage['same_DS_SS_'+str(same)]+=1;coverage['helper_RET6_calls']+=out.helper_calls;coverage['attribute_words']+=out.attribute_words;coverage['line_words']+=out.line_words;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
    require(len(sites)==len(starts),'Allcaller/helper instructionlocations '+str(sorted(address-cs*16 for address in starts if address-cs*16 not in sites)));record={'schema':1,'result':'pass','function_id':'FN-EGA-000090','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_interpolate.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete2477+actual06C3 serializedcallercomposition: DS-current/SS-previous, ESDS/DF0, signedSUB-JGE/CL1notCX1, prepared15words/fiveRET6reverse-ordercalls, attribute-before-linewrites/snapshot/source/outputaliases andpersistentINC-DECpair compared. Prefixesstopbeforeoriginalwork, notnormalreturn/error. Actualcaller/SS-DS/record/outputbounds/IRQreentry/fullmutablegraph/resource/renderer/core/game/fidelity pending; native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
