"""Compare byte far-copy and two CS configuration writers, including overlaps."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['work','writes']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];dll=C.CDLL(str(library));fn=dll.td2ega_copy_config;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    entries=[0x5d01,0x7d5e,0x7918];ids=['FN-EGA-000133','FN-EGA-000206','FN-EGA-000195'];rep_sites={0x5d17,0x7d75,0x792d};graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in graph['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in entries] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[principal*16:principal*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Copy escaped '+hex(address))
            if ip in rep_sites and u.reg_read(UC_X86_REG_CX)!=0:
                if active['work']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['work']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No interrupt in copy bodies')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(0,count,profile,same,flags,limit) for count,profile,same,flags,limit in itertools.product([0,1,2,4,17,255,256,65535],range(5),[0,1],[2,0x203,0x402,0x603],[0,1,4,65536]) if profile!=4 or count<=4]
        cases +=[(entry,13 if entry==1 else 26,profile,same,flags,limit) for entry,profile,same,flags,limit in itertools.product([1,2],range(4),[0,1],[2,0x203,0x402,0x603],[0,1,4,65536])]
        for entry,count,profile,same,flags,limit in cases:
            data=bytearray(base);ds=cs if entry==2 and profile in [1,2] else principal;ss=ds if same else 0x9000;source=0x6000;source_offset=0x1000;destination=0x7000;destination_offset=0x2000
            if entry==0:
                if profile in [1,2]:destination=source;destination_offset=source_offset+(1 if profile==1 else -1)
                if profile==3:source_offset=0xfffe;destination_offset=0xffff
                if profile==4:destination=ss;destination_offset=sp-8
            else:
                source=ds if entry==2 else cs if profile in [1,2] else 0x6000
                source_offset=0xaf39 if profile==1 else 0xaf3b if profile==2 else 0xffff if profile==3 else 0x2000;destination=cs;destination_offset=0xaf3a
            for i in range(128):data[((source<<4)+((source_offset+i)&65535))&0xfffff]=(i*37+profile*11)&255
            arguments=[source_offset,source,destination_offset,destination,count] if entry==0 else [source_offset,source] if entry==1 else [source_offset]
            frame=struct.pack('<2H',0x100,0x1111);tail=struct.pack('<'+'H'*len(arguments),*arguments)+b'\x5a\xa5'*4;data[ss*16+sp-16:ss*16+sp+len(frame)+len(tail)]=b'\xa5'*16+frame+tail;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(work=0,limit=limit,writes=0,prefix=False,instructions=0,sites=set());u.emu_start(cs*16+entries[entry],0x11210,count=100000);label=f'{load:x}/{entry}/{count}/{profile}/{same}/{flags:x}/{limit}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original return '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.work==active['work'] and out.writes==active['writes'],'Native prefix/write count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(0x1111,0x100),'Far return words '+label)
            require(bytes(u.mem_read(ss*16+sp,len(frame)+len(tail)))==frame+tail,'Args/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['prefix' if active['prefix'] else 'far_returns']+=1;coverage['copy_units']+=out.work;coverage['bus_write_events']+=out.writes
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised copy sites '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_copy_config.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Threeforwardcopybodies, five-wordbyte-farcopy/two-wordfar-source13wordCSconfig/one-wordnear-source26wordCSconfig ABIs, fullbusincludingSSsavedframes/GPR/BP/CFIFDF/farRETF4. REP0zero,65535bytecases, oddoverlaps/rawSI-DIwrap andsavedSI-DIoutputaliases tested; currentDS/SS/CS contrasts explicit. Nativeworkprefix separate. Actualproducer/argument/outputbounds, allCSconfigurationwriters/lifetime/IRQexclusion, complete state/core/device/resource-fedP2/P3/game/fidelity remainopen. Nooriginalconfiguration/media payloadembedded; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
