"""Compare signed field clamp, overflow-aware byte ratio and raw label padding."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['iterations','bus_writes']]+[('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_small_algorithms;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[(0x6c9,0x8cb),(0x6c9,0x52fd),(0x432,0x61)];names={f'{s:04X}:{ip:04X}' for s,ip in entries};selected=[f for f in g['functions'] if f['entry'] in names];fence={(int(f['entry'][:4],16),ip) for f in selected for ip in f['instructions']};unreachable={(0x6c9,0x5303)};exits={(int(f['entry'][:4],16),int(e['site'][5:],16)) for f in selected for e in f['exits']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence and pair not in unreachable,'Smallalgorithm escaped '+str(pair))
            if pair in exits:active['return']=True;u.emu_stop();return
            if pair in {(0x432,0x72),(0x432,0x90),(0x432,0x9b)}:
                if active['iterations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['iterations']+=1
            if pair==(0x6c9,0x5327):active['byte_divisions']+=1
            active['instructions']+=1;active['sites'].add(pair)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform service; byteDIVguard mustpreventfault')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(0,ax,si,mask,profile,same,flags,0) for ax,si,mask,profile,same,flags in itertools.product([0,1,319,320,321,0x7fff,0x8000,0xfffe,0xffff],[0,1,319,320,0x7fff,0x8000,0xffff],[0,8,0x40,0x48,0x80,0x88,0xc0,0xff],range(6),[0,1],[2,0x603])]
        cases +=[(1,ax,bx,cx,dx,same,flags,0) for ax,bx,cx,dx,same,flags in itertools.product([0,1,0xff,0x100,0x7fff,0x8000,0xfffa,0xfffb,0xfffe,0xffff],[0,1,4,0x7fff,0x8000,0xfffa,0xfffe,0xffff],[0,1,2,3,4,7,59,60,61,0x7fff,0x8000,0xffff],[0,1,2,3,0x7fff,0x8000,0xfffd,0xffff],[0,1],[2,0x603])]
        cases +=[(1,max(0,(cx>>1)-4),0,cx,0,same,flags,0) for cx,same,flags in itertools.product(range(3,61),[0,1],[2,0x203,0x402,0x603])]
        cases +=[(2,length,pointer,pattern,0,same,flags,limit) for length,pointer,pattern,same,flags,limit in itertools.product([0,1,17,18,19,255,None],[0x1200,0xfff0,0xdffa,0xdffc,0xdffe,0xe000,0xe004],[0,1],[0,1],[2,0x203,0x402,0x603],[0,1,4,20,512])]
        cases +=[(2,length,0x1200,pattern,0,same,flags,limit) for length,pattern,same,flags,limit in itertools.product([32767,32768,65535,None],[0,1],[0,1],[2,0x603],[65536,100000])]
        for entry,param,a1,a2,a3,same,flags,limit in cases:
            data=bytearray(base);ss=ds if same else 0x9000;sp=0xe000;segment,ip=entries[entry];cs=load+segment;ax,bx,cx,dx,si=0xa55a,0xb123,0xc456,0xd789,0x3456
            def putword(o,v):struct.pack_into('<H',data,ds*16+o,v&65535)
            if entry==0:
                ax,si=param,a1;data[ds*16+0x133c]=a2;fieldsets=[(0,0,0,0),(320,320,320,320),(0x7fff,0x8000,0x8000,0x7fff),(0x8000,0x7fff,0x7fff,0x8000),(0xffff,0xffff,0xffff,0xffff),(1,0xffff,0,321)]
                for o,v in zip([0x12d0,0x1310,0x130e,0x130a],fieldsets[a3]):putword(o,v)
            elif entry==1:ax,bx,cx,dx=param,a1,a2,a3
            else:
                length,pointer,pattern=param,a1,a2
                if length is not None:
                    for k in range(length):data[ds*16+((pointer+k)&65535)]=0x5f if pattern and k%2==0 else 0x41
                    data[ds*16+((pointer+length)&65535)]=0
            frame=struct.pack('<3H',0x1111,0x2222,a1) if entry==2 else struct.pack('<H',0x1111);data[ss*16+sp:ss*16+sp+len(frame)]=frame;incoming=StateRegisters(Registers(ax,bx,cx,dx,si,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(limit=limit,iterations=0,writes=0,instructions=0,byte_divisions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+ip,0,count=2000000);label=f'{load:x}/{entry}/{param}/{a1:x}/{a2:x}/{a3:x}/{same}/{flags:x}/{limit}';require(active['prefix'] or active['return'],'Outcome '+label)
            if active['return']:
                pair=(segment,u.reg_read(UC_X86_REG_IP));sites.add(pair);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+pair[1],0,count=1);active['executing_return']=False
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.iterations==active['iterations'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['budget_prefix' if active['prefix'] else 'return_operations']+=1;coverage['byte_DIV_instructions']+=active['byte_divisions'];coverage['iterations']+=out.iterations;coverage['bus_write_events']+=out.bus_writes;coverage['raw_label_returns']+=int(entry==2 and active['return'] and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['signed_counter_wrap_label_returns']+=int(entry==2 and param in [32768,65535] and not same and out.status==0)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence-unreachable and coverage['byte_DIV_instructions']>0 and coverage['signed_counter_wrap_label_returns']>0,'Coverage '+str(fence-unreachable-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000072','FN-EGA-000392','FN-EGA-000032'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_small_algorithms.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'unreachable_under_entry_guards':['06C9:5303'],'fixture_coverage':dict(coverage),'limits':'Actual08CBsignedfieldclamp/52FDoverflow-awareSUB-JLE/JG/guardedbyteDIV/0432:0061underscoreandminimum18pad withactualSSwordcounter rereadsafterstores. Fullbus/SSsaves/near-farframes/GPR/BP/CFIFDF/control, wordwrap/signedcounternegativepadding andaliases retained. 5303unreachablefrom52FD becauseadjacentJLE/JGcomplementarywithoutflagsetter, notglobaldead. Nativebeforelabelscan/store budget separate. Actualcaller/fieldunits/bounds/writers/lifetime/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
