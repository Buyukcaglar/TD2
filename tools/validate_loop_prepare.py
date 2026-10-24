"""Compare2089 record preparation, NEG/JGE overflow and mutable output/source aliases."""
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
    _fields_=[('status',C.c_uint16),('records',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_loop_prepare;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());f=next(f for f in graph['functions'] if f['entry']=='06C9:2089');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000;group=bytes((i*37+11)&255 for i in range(65536));cases=[]
    for high,basehigh,adjust,borrow in itertools.product([0,1,24,25,26,0x7fff,0x8000,0x8001,0xffe7,0xffe8,0xffff],[0,1,0x7fff,0x8000,0xffff],[0,1,25,26,1000,0x7fff,0x8000,0xffff],[0,1]):cases.append(('word_arithmetic',high,basehigh,adjust,borrow,8,8,4000))
    for first,second,pattern in itertools.product([0,1,7,8,9,15,16,17,399,400,401,408],[0,1,8,9,400],range(3)):cases.append(('extent_and_output_order',[0,1,0x8000][pattern],0,[0,1000,0xffff][pattern],pattern&1,first,second,4000))
    for first in [4800,11200]:cases.append(('indexed_output_source_alias',0,0,0,0,first,16,4000))
    for budget in [0,1,2,3]:cases.append(('budget_prefix',0,0,0,0,16,16,budget))
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=group;base[0x90000:0xa0000]=bytes(i^0xff for i in group);starts={cs*16+ip for ip in f['instructions']}
        def code(cpu,address,size,_):
            require(address in starts,'2089 escaped fence')
            if address in [cs*16+0x20fc,cs*16+0x2139]:
                if active['records']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['records']+=1
            active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for category,high,basehigh,adjust,borrow,first,second,budget in cases:
            for same in [0,1]:
                ss=ds if same else 0x9000;data=bytearray(base);baselow=1 if borrow else 0;low=0;rowcount=max(128,(first+7)//8,(second+7)//8)
                for table in [0x3813,0x39a3]:
                    for i in range(rowcount):struct.pack_into('<4H',data,ds*16+table+i*8,(0x8100+i)&65535,high,low,(0xa500+i)&65535)
                fields={0x52c8:baselow,0x52ca:basehigh,0x380d:adjust,0x5354:first,0x5356:second,0x52d0:low,0x52d2:high,0x52d4:0xabcd,0x52d8:baselow^0xffff,0x52da:(high^0x8000),0x52dc:0xcdef,0x533e:[0,1,0x8000,0xffff][vectors%4],0x2f48:[0,1,0x8000,0xffff][(vectors>>1)%4],0x52cc:[0,1,2,0x7fff,0x8000,0xffff][vectors%6],0x2a1e:0x7654}
                for at,value in fields.items():struct.pack_into('<H',data,ds*16+at,value)
                data[ds*16+0x5491]=vectors&255;data[ds*16+0x3375]=(vectors*3)&255;data[ds*16+0x33b8]=(vectors*5)&255;data[ds*16+0x33b7]=(vectors*7)&255;frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp: ss*16+sp+8]=frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
                for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2089),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
                active.update(records=0,limit=budget,prefix=False,instructions=0,sites=set());u.emu_start(cs*16+0x2089,0x11210,count=500000);label=f'{load:x}/{category}/{high:x}/{basehigh:x}/{adjust:x}/{borrow}/{first}/{second}/{budget}/{same}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original normal/prefix exit '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(gb,len(gb),C.byref(incoming),budget,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.records==active['records'],'Native status/records '+label);require(bytes(u.mem_read(0,len(data)))==bytes(gb),'Complete bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(u.reg_read(UC_X86_REG_SS)==ss and bytes(u.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'Farframe untouched '+label);coverage[category]+=1;coverage['same_DS_SS_'+str(same)]+=1;coverage['original_budget_prefix' if active['prefix'] else 'original_normal_return']+=1;coverage['records']+=out.records;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
    require(len(sites)==len(starts),'All2089instructionlocations');record={'schema':1,'result':'pass','function_id':'FN-EGA-000088','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_loop_prepare.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete2089 serializedcurrentDS record/global/output effects, actualNEG/JGE SF==OF at8000, lowborrow/SBB/adjust/unsignedfilter, do-once loops, mutableindexedoutput-sourcealiases andCFIFDF/BP compared. Budget-prefix comparisons stopbeforeoriginalnextrecord, not originalerror/normalreturn equivalence.1E59 usesSS records separately; noactualcallerresourcebounds/units/graphics/state/IRQ/core/game/fidelity admission. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
