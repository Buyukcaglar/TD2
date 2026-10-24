"""Compare near-pointer shift assignment and actual RETF-immediate cleanup."""
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
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['shift_count','bus_writes']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_shift_assign;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['13A8:2FD0','13A8:2FC4'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();counts=set()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Shift assignment escaped '+hex(address))
            if ip==0x2fc4:require(bytes(u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))==struct.pack('<2H',0x2fe3,cs),'Actual shift child far frame');active['child_calls']+=1
            if ip==0x2fee and not active['allow_raw_return']:
                words=struct.unpack('<2H',u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))
                if words!=(0x100,0x1111):active['raw_pending']=True;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No interrupt/service in finite shift assignment')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(count,data32,0x2800,same,flags) for count,data32,same,flags in itertools.product(range(256),[0,1,0x80000000,0xffffffff],[0,1],[2,0x603])]
        cases +=[(count,data32,pointer,same,flags) for count,data32,pointer,same,flags in itertools.product([0,1,7,15,16,31,32,0x100,0x101,0xff00,0xffff],[0x12345678,0xffffffff],[0x2801,0xfffe,0xffff,sp-6,sp-4,sp-2,sp,sp+4],[0,1],[2,0x603])]
        for count,data32,pointer,same,flags in cases:
            data=bytearray(base);ss=ds if same else 0x9000
            struct.pack_into('<H',data,ds*16+pointer,data32&65535);struct.pack_into('<H',data,ds*16+((pointer+2)&65535),data32>>16);frame=struct.pack('<2H',0x100,0x1111);arguments=struct.pack('<2H',pointer,count);guard=b'\x5a\xa5'*4;data[ss*16+sp-16:ss*16+sp+16]=b'\xa5'*16+frame+arguments+guard
            # Restore ordinary source data afterframe seeding whenit isdisjoint;
            # stack aliases deliberately observe thecallerframe andPUSHBP writes.
            if not same or pointer<sp-16 or pointer>=sp+16:
                struct.pack_into('<H',data,ds*16+pointer,data32&65535);struct.pack_into('<H',data,ds*16+((pointer+2)&65535),data32>>16)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2fd0),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(ss=ss,raw_pending=False,allow_raw_return=False,writes=0,child_calls=0,instructions=0,sites=set());u.emu_start(cs*16+0x2fd0,0x11210,count=2000)
            if active['raw_pending']:active['allow_raw_return']=True;u.emu_start(cs*16+0x2fee,0,count=1)
            label=f'{load:x}/{count:x}/{data32:x}/{pointer:x}/{same}/{flags:x}';require((active['raw_pending'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))==(0x1111,0x100)) and u.reg_read(UC_X86_REG_SP)==sp+8 and active['child_calls']==1,'Original RETF4 cleanup '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(out));require(out.status==0 and out.current_sp==sp+8 and out.shift_count==(count&255) and out.bus_writes==active['writes'],'Native cleanup/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/SS andnearstores '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF retainedacrossRETF4 '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Actual far coordinate '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);counts.add(count&255);coverage['raw_root_returns' if active['raw_pending'] else 'far_returns']+=1;coverage['bus_write_events']+=out.bus_writes;coverage['root_returns_with_CF1']+=r.carry;coverage['stack_data_alias_profiles']+=int(same and sp-16<=pointer<sp+16);coverage['high_count_byte_nonzero']+=int(count>255)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and counts==set(range(256)) and coverage['root_returns_with_CF1']>0,'Finite shift/cleanup coverage');record={'schema':1,'result':'pass','function_ids':['FN-EGA-000347'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_shift_assign.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'distinct_CL_counts':len(counts),'fixture_coverage':dict(coverage),'limits':'Actual13A8:2FD0+2FC4, currentDSnear32bitwordpair/SSpointer-count args, all256CL counts/CHdiscard andorderedpointerreread/AX-DXstores. FullbusincludingnestedSSframes/GPR/BP/CFIFDF/actualRETF imm4 consumes4farframe+4argumentbytes ->entrySP+8 withoutchangingCF. NearwordEAwrap/odddata andstackargument/saved/returnaliases tested; rawrootRETcoordinates exposedafteractualinstruction, notfollowed. NooriginalCreturntype/signedsource32bittype inferred, nohostovershift. Actualcaller/otherflagconsumers/bounds/lifetimes/IRQ/core/resource-fedP2/P3/device/session/game/fidelity remainopen; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','distinct_CL_counts','fixture_coverage']},indent=2))

if __name__=='__main__':main()
