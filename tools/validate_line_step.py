"""Compare06C3 self-modifying interpolation, DF/count quirks and near RET6."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','stack_segment','current_sp','return_bytes','opcode_first','opcode_second']]+[('work',C.c_uint32),('words',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_line_step;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in graph['functions'] if f['entry']=='06C9:06C3');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000;cases=[];bounds=[0,1,2,79,80,81,0x7fff,0x8000,0xffff]
    for first,second,bound,denom,count,df in itertools.product(bounds,bounds,[0,1,80,0x7fff,0x8000,0xffff],[0,1,17],[2,7],[0,1]):cases.append(('endpoint_signed_grid',first,second,bound,denom,count,df,256))
    for pair,count,denom,df in itertools.product([(0,1),(1,0),(1,17),(17,1),(80,81),(0xffff,0x8000)],[0,1,2,7,17,0x100,0x101,0xffff],[0,1,2,17,0xffff],[0,1]):cases.append(('word_count_profiles',pair[0],pair[1],80,denom,count,df,256))
    for first,second,budget,df in itertools.product([1,17],[1,17],[0,1,2,3,4,5,10],[0,1]):cases.append(('ordered_patch_prefix',first,second,80,17,2,df,budget))
    cases += [('complete_count_wrap',1,17,80,17,0,0,1000000),('complete_count_wrap',1,17,80,17,1,0,1000000),('complete_count_wrap',17,1,80,17,1,0,1000000),('complete_count_wrap',1,1,80,17,0,0,1000000)]
    forms=[(0x40,0x40),(0x48,0x48),(0x40,0x48),(0x48,0x40),(0x90,0xcc)]
    for load in [0x1000,0x2345]:
        cs,ds,ss,es=load+0x6c9,load+0x178f,0x9000,0x7000;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);base[es*16:es*16+65536]=bytes([0x5a])*65536;starts={cs*16+ip for ip in f['instructions']}
        for case_index,(category,first,second,bound,denom,count,df,budget) in enumerate(cases):
            u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);data=bytearray(base);pair=forms[case_index%len(forms)];data[cs*16+0x71f]=pair[0];data[cs*16+0x735]=pair[1];struct.pack_into('<H',data,ds*16+0x5348,bound);destination=0xfffe if category!='complete_count_wrap' and (case_index&4) else 0;frame=struct.pack('<4H',0x100,destination,second,first);data[ss*16+sp-8:ss*16+sp+12]=b'\xa5'*8+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(df<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,count,denom,0x3456,0x2345,ds,es,(flags>>9)&1,df),0x5678,flags&1);active={'work':0,'words':0,'prefix':False,'instructions':0,'sites':set()}
            def code(cpu,address,size,_):
                require(address in starts,'06C3escapedfence')
                ip=address-cs*16;rep_word=ip==0x73d and u.reg_read(UC_X86_REG_CX)!=0;tick=ip in [0x6f1,0x6f9,0x6ff,0x709,0x70f,0x71d,0x72f] or rep_word
                if tick:
                    if active['work']==budget:active['prefix']=True;u.emu_stop();return
                    active['work']+=1
                if ip in [0x6f1,0x726,0x738] or rep_word:active['words']+=1
                if ip in [0x71f,0x735]:require(bytes(u.mem_read(address,1))[0] in [0x40,0x48],'Patchedarithmetic mustberewrittenbeforeexecution')
                active['instructions']+=1;active['sites'].add(ip)
            def interrupt(*_):raise RuntimeError('Unexpectedinterrupt/mid-entry')
            u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6c3),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            u.emu_start(cs*16+0x6c3,cs*16+0x100,count=2000000);label=f'{load:x}/{category}/{first:x}/{second:x}/{bound:x}/{denom:x}/{count:x}/{df}/{budget}/{pair}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+8),'OriginalRET6/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,destination,second,first,C.byref(incoming),budget,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.work==active['work'] and out.words==active['words'],'Nativework/word/status '+label);require(out.current_sp==u.reg_read(UC_X86_REG_SP) and out.stack_segment==ss and out.return_bytes==8,'NativeRET6/frame '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-8:ss*16+sp]=expected[ss*16+sp-8:ss*16+sp];require(actual==expected,'Fullnonframebus/CSmutations '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,12))==frame+b'\xa5'*4,'Nearframe/arguments/guard '+label);finalpair=(bus[cs*16+0x71f],bus[cs*16+0x735]);require((out.opcode_first,out.opcode_second)==finalpair,'Observedcodepair '+label);coverage['opcode_pair_'+hex(finalpair[0])+'_'+hex(finalpair[1])]+=1;coverage[category]+=1;coverage['original_work_prefix' if active['prefix'] else 'original_normal_RET6']+=1;coverage['DF_'+str(df)]+=1;coverage['word_writes']+=out.words;coverage['work']+=out.work;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
            if category=='complete_count_wrap':require(out.status==0 and out.words==(65537 if count==1 else 65536),'Uncorrectedzero/one countwrites '+label)
        print(json.dumps({'load_segment':hex(load),'vectors_completed':vectors}))
    require(len(sites)==len(starts),'All06C3 instructionlocations');record={'schema':1,'result':'pass','function_id':'FN-EGA-000069','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_line_step.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete06C3 serializeddirect-entry/nearRET6/implicitCX-DX/DFSTOSW/signedclipping/suboverflow/unsignedbranch-signedloop/orderedCS071F0735INC-DECpatch effects compared. FreshCPUperfixture, includesmixed/unknowninitialunusedbytes andworkprefixesbetweenpatches/innernonprogress. Count0/1 interpolation quirks retained. Explicitnativeargs representoriginal3SSwords; controlframes/data/code separateexceptauthoredpatches. No actualIRQ/reentrancy/fullmutabletransitiongraph/callerbounds/2477integration/resource/renderer/core/game/fidelity; native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
