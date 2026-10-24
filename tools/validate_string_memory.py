"""Compare raw near string copy/compare/fill operations and full SS effects."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['operations','bus_writes']]+[('returned',StateRegisters)]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_string_memory;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[0x2916,0x2956,0x2988,0x2b40,0x2b82];selected=[f for f in g['functions'] if f['entry'] in [f'13A8:{ip:04X}' for ip in entries]];fence={ip for f in selected for ip in f['instructions']};exits={int(e['site'][5:],16) for f in selected for e in f['exits']};repeat={0x2929,0x2934,0x2949,0x294d,0x296b,0x297c,0x2980,0x299e,0x29a4,0x2ba4,0x2ba8};single={0x2945,0x2978,0x2b51,0x2ba0};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP)
            if active.get('executing_return'):return
            require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'String escaped '+hex(address))
            if ip in exits:active['return']=True;u.emu_stop();return
            if ip in single or (ip in repeat and u.reg_read(UC_X86_REG_CX)!=0):
                if active['operations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['operations']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No services in string helper')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        profiles=[(0x1200,0x1300,n,kind) for n,kind in itertools.product([0,1,2,3,17],[0,1,2,3])]+[(0x1201,0x1301,3,0),(0xfff1,0x1300,17,0),(0x1200,0xfff1,17,0),(0x1301,0x1300,17,0),(0x12ff,0x1300,17,0),(0xdff6,0x1300,17,0),(0xe000,0x1300,17,0),(0xe006,0x1300,17,0),(0x1200,0x1300,0xffff,4)]
        for entry,(pointer,source,length,kind),same,flags,limit in itertools.product(range(5),profiles,[0,1],[2,0x203,0x402,0x603],[0,1,4,40,65535]):
            data=bytearray(base);ss=ds if same else 0x9000;sp=0xe000;df=(flags>>10)&1
            def byte(o,v):data[ds*16+(o&65535)]=v
            if kind!=4:
                for k in range(length):
                    val=(0x41+k%26) if kind!=3 else (0x80+k%64);byte(source+(-k if df else k),val);byte(pointer+(-k if df else k),val if kind==0 else (val+32)&255 if kind==1 else (val+1)&255)
                byte(source+(-length if df else length),0);byte(pointer+(-length if df else length),0)
            frame=struct.pack('<2H',0x1111,0x2222);args=struct.pack('<3H',pointer,0x5a if entry==4 else source,length);guard=b'\xa5'*8;data[ss*16+sp-16:ss*16+sp+18]=b'\xa5'*16+frame+args+guard;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,df),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(operations=0,limit=limit,prefix=False,writes=0,instructions=0,sites=set(),**{'return':False});u.emu_start(cs*16+entries[entry],0,count=500000);label=f'{load:x}/{entry}/{pointer:x}/{source:x}/{length}/{kind}/{same}/{flags:x}/{limit}';require(active['prefix'] or active['return'],'Terminated '+label)
            if active['return']:
                sites.add(u.reg_read(UC_X86_REG_IP));active['instructions']+=1;active['executing_return']=True
                return_ip=u.reg_read(UC_X86_REG_IP);u.emu_start(cs*16+return_ip,0,count=1);active['executing_return']=False
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.operations==active['operations'] and out.bus_writes==active['writes'],'Status/count '+label+str((out.status,out.operations,out.bus_writes,u.reg_read(UC_X86_REG_SP),active)));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Whole bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix' if active['prefix'] else 'far_returns']+=1;coverage['raw_far_returns']+=int(active['return'] and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['operations']+=out.operations;coverage['bus_write_events']+=out.bus_writes;coverage['reverse_DF_fixtures']+=df;coverage[f'entry_{entry}']+=1
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Full instruction coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000326','FN-EGA-000327','FN-EGA-000328','FN-EGA-000337','FN-EGA-000338'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_string_memory.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual near currentDS copy/tail-copy/compare/bytecase-compare/fill algorithms, incomingDF, word EA and sequential byte/word transfers, actual SS savedBP and raw far return operation. Full bus/GPR/BP/CFIFDF. Native before-element prefix separate. Caller capacity/NUL/DF/otherFLAGS/writers/lifetime/core/resource-fedP2/P3/device/session/game/fidelity remain open; no original source C types or host string substitutions inferred.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
