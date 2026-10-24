"""Compare raw member-address calculation and normalized AX/DX far outputs."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32),('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_far_member;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:C701')['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Far-member escaped '+hex(address))
            if ip==0xc75f:active['return']=True;u.emu_stop();return
            if ip==0xc740 and u.reg_read(UC_X86_REG_BX)==0xfffe:active['wrapped_table_high_reads']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform instruction in member-address helper')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        offsets=[0,1,0xfffb,0xfffc,0xffff,0xdff8];segments=[0,0x40,0x1000,ds,0x5000,0x9000];counts=[0,1,2,0x1fff,0x2000,0x3fff,0x4000,0x7fff,0x8000,0xffff];indices=[0,1,0x3ffe,0x3fff,0x4000,0x7fff,0xffff];displacements=[0,1,7,8,9,10,15,16,0xffff,0x10000,0x7fffffff,0xffffffff];cases=[]
        for ni,ii,di,sc,same,flags in itertools.product(range(len(counts)),range(len(indices)),range(len(displacements)),range(len(segments)),[0,1],[2,0x203,0x402,0x603]):
            offset=offsets[(ni+ii+di+sc)%len(offsets)];sp=16 if (ni+ii+di+sc)&1 else 0xe000;cases.append((counts[ni],indices[ii],displacements[di],segments[sc],offset,same,sp,flags))
        cases +=[(0,0,disp,segment,offset,same,0xe000,flags) for disp,segment,offset,same,flags in itertools.product([0,10,0xffff,0xffffffff],segments,offsets,[0,1],[2,0x203,0x402,0x603])]
        cases +=[(0,0x3ffe,disp,segment,0,same,0xe000,flags) for disp,segment,same,flags in itertools.product(displacements,segments,[0,1],[2,0x203,0x402,0x603])]
        for count,index,displacement,segment,offset,same,sp,flags in cases:
            data=bytearray(base);ss=ds if same else 0x9000;table=(4*count+4*index+6)&65535
            def putword(s,o,v):
                at=((s*16)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
            putword(segment,offset+4,count);putword(segment,table,displacement&65535);putword(segment,table+2,displacement>>16)
            if table==0xfffe:
                # One four-byte read would incorrectly take this marker as highword.
                at=segment*16+0x10000;data[at:at+2]=struct.pack('<H',0x1357)
            frame=struct.pack('<5H',0x1111,0x2222,offset,segment,index);data[ss*16+sp:ss*16+sp+10]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xc701),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(writes=0,instructions=0,wrapped_table_high_reads=0,sites=set(),executing_return=False,**{'return':False});u.emu_start(cs*16+0xc701,0,count=1000);label=f'{load:x}/{count:x}/{index:x}/{displacement:x}/{segment:x}/{offset:x}/{same}/{sp:x}/{flags:x}';require(active['return'],'Return '+label);sites.add(0xc75f);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+0xc75f,0,count=1);active['executing_return']=False;bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(out));require(out.status==0 and out.current_sp==sp+4 and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.bus_writes==active['writes']==2,'Status/SS '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))==(0x2222,0x1111),'Control '+label);require(r.registers.ax<16 and r.registers.bx==r.registers.ax and r.registers.ds==ds and r.registers.es==segment,'Normalizedfarview '+label);require(bytes(u.mem_read(ss*16+sp,10))==frame,'Callerframe/arguments unchanged '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['far_returns']+=1;coverage['bus_write_events']+=out.bus_writes;coverage['wrapped_table_high_reads']+=active['wrapped_table_high_reads'];coverage['normalized_offset_zero_nonzero_segment']+=int(r.registers.ax==0 and r.registers.dx!=0);coverage['nonzero_header_offset_fixtures']+=int(offset!=0);coverage['minimumSP16_fixtures']+=int(sp==16);coverage['ES_equals_SS_fixtures']+=int(segment==ss);coverage['carry_set_returns']+=r.carry
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['wrapped_table_high_reads']>0 and coverage['normalized_offset_zero_nonzero_segment']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000251'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_far_member.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualC701SSthreewords/headerES:SI+4/separatelywrappedES-tableword reads/wordbase truncation/raw32bitadd/4SHR-RCR normalization toAXnibble/DXsegment/CFbit3; fullbus/SSsaves/farframe/GPR/BP/CFIFDF/control. Nonzeroheaderoffset retained, tableindicesnotSI-relative. Zerooffset/nonzerosegment validrawoutput, nohostNULL substitution. SourceESranges0..9000 andflatbus only, noA20/device/realDOS qualification. Actualcaller/header-alignment/index/table/buffer/outputbounds/writers/lifetime/otherFLAGS/core/resourcefedP2/P3/session/game/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
