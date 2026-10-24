"""Compare088E signed clamp passes, LOOP zero count, word wrap and bounded prefixes."""
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
    _fields_=[('status',C.c_uint16),('words',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_near_clamp;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in graph['functions'] if f['entry']=='06C9:088E');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000;group=b''.join(struct.pack('<H',(i*257)&65535) for i in range(32768));cases=[]
    for ax,bx,same in itertools.product(range(17),[0,1,79,80,0x7fff,0x8000,0xfffe,0xffff],[0,1]):cases.append(('bounded_five_passes',ax,17,bx,400000,same))
    for bp,amount,bx,same in itertools.product([0,1,17,92,0x7fff,0x8000,0xffff],[1,2],[0,80,0x8000,0xffff],[0,1]):cases.append(('word_pointer_and_signed_boundaries',(bp-amount)&65535,bp,bx,400000,same))
    cases.append(('zero_LOOP_count_normal',17,17,80,400000,0))
    for ax,bp,bx,budget in [(17,17,0xffff,100000),(18,17,80,256),(0,0,80,0),(0xffff,0,0x8000,0),(0x7fff,0x8000,80,0),(0,17,80,1),(0,17,80,17),(0,17,80,18)]:cases.append(('bounded_instruction_prefix',ax,bp,bx,budget,0))
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=group;starts={cs*16+ip for ip in f['instructions']}
        def code(cpu,address,size,_):
            require(address in starts,'088E escaped fence')
            if address==cs*16+0x8a4:
                if active['words']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['words']+=1
            active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for category,ax,bp,bx,budget,same in cases:
            ss=ds if same else 0x9000;data=bytearray(base);struct.pack_into('<H',data,ds*16+0x5348,bx)
            if category=='bounded_five_passes':
                for row in range(5):
                    for index,value in enumerate([0,1,79,80,81,0x7fff,0x8000,0xffff,2,78,82,0x8001,0xfffe,0x7ffe,0x4000,0xc000,0]):struct.pack_into('<H',data,ds*16+0x9c4+184*row+2*index,value)
            frame=struct.pack('<H',0x100);data[ss*16+sp-2:ss*16+sp+6]=b'\xa5'*2+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(ax,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),bp,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x88e),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            active.update(words=0,limit=budget,prefix=False,instructions=0,sites=set());u.emu_start(cs*16+0x88e,cs*16+0x100,count=4000000);label=f'{load:x}/{category}/{ax:x}/{bp:x}/{bx:x}/{budget}/{same}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'Original nearRET/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),C.byref(incoming),budget,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.words==active['words'],'Native wordcount/status '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-2:ss*16+sp]=expected[ss*16+sp-2:ss*16+sp];require(actual==expected,'Full nonlocalbus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp==bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearframeguard '+label)
            if not active['prefix']:require(r.registers.ax==ax and r.registers.si==0xd5c and r.registers.cx==0 and r.registers.di==0,'Orderedfivepass endstate '+label)
            coverage[category]+=1;coverage['original_prefix' if active['prefix'] else 'original_normal_near_return']+=1;coverage['words']+=out.words;coverage['same_DS_SS_'+str(same)]+=1;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
    require(len(sites)==len(starts),'Every088Einstructionlocation');record={'schema':1,'result':'pass','function_id':'FN-EGA-000071','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_near_clamp.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete088E orderedfivemutableDSpasses/signedlowerthenupper/negativeupperbounds/capturedBX/LOOPzero65536/wordwrap/CFIFDF/nearRET compared. Widecases useSSseparatefromDS/controlframes; nozero-countnormalization. PrefixesstopbeforeoriginalnextLODSW, not originalerror/normalreturn. Actual1F71 AX2C2A/BP17 writer/callerbounds/graphics/layout/resource/IRQ/core/game/fidelity pending. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
