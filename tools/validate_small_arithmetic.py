"""Compare raw record selection, signed counter division and pair/square helpers."""
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_small_arithmetic;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[(0x6c9,0x5c30),(0x143,0x19e),(0x6c9,0x5a25),(0x6c9,0x5c5a)];names={f'{s:04X}:{ip:04X}' for s,ip in entries};selected=[f for f in g['functions'] if f['entry'] in names];fence={(int(f['entry'][:4],16),ip) for f in selected for ip in f['instructions']};exits={(int(f['entry'][:4],16),int(e['site'][5:],16)) for f in selected for e in f['exits']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;active={}
        cases=[(0,count,pattern,si,0,same,0xe000,flags,limit) for count,pattern,si,same,flags,limit in itertools.product([0,1,7,8,16,0xffff],[0,1,2],[0x1200,0xfff8],[0,1],[2,0x603],[0,1,4,64])]
        cases +=[(0,count,pattern,0xfff8,0,1,0xe000,flags,65536) for count,pattern,flags in itertools.product([0,7,8,16],[0,2],[2,0x603])]
        cases +=[(1,counter,divisor,tally,cap,same,sp,flags,0) for counter,divisor,tally,cap,same,sp,flags in itertools.product([0,199,200,0x7fff,0x8000,0xffff],[0,1,0xffff,20,0xffec,0x7fff,0x8000],[0,0x7fff,0xffff],[0,1,0x8000],[0,1],[0xe000,0x2de],[2,0x603])]
        cases +=[(2,pattern,bx,dx,alias,same,0xe000,flags,0) for pattern,bx,dx,alias,same,flags in itertools.product(range(8),[0,1,0x8000,0xffff],[0,179,180,359,0x7fff,0x8000,0xffff],[0,1,2,3],[0,1],[2,0x603])]
        cases +=[(3,si,di,bx,field,same,sp,flags,0) for si,di,bx,field,same,sp,flags in itertools.product([0,1,255,256,0x7fff,0x8000,0xffff],[0,1,2,3,0xffff],[0,0x3b41,0x3b42,0xffff],[0,1,0xffff,0x8000],[0,1],[0xe000,0x3344],[2,0x603])]
        for entry,param,a1,a2,a3,same,sp,flags,limit in cases:
            # Fresh machine also avoids any prior divide-fault execution state.
            u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);data=bytearray(base);ss=ds if same else 0x9000;segment,ip=entries[entry];cs=load+segment;ax,bx,cx,dx,si,di=0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567
            def word(o,v):
                at=ds*16+(o&65535);data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
            if entry==0:
                cx,si,ax,dx=param,a2,0x7fff,0x8000
                # Repeating raw records, with borrow/overflow and unsigned tie cases.
                block=struct.pack('<4H',0,0x7fff if a1==0 else 0x8000 if a1==1 else 0,0xffff if a1==0 else 0,0);data[ds*16:ds*16+65536]=block*8192;word(0x380d,[0,0x7fff,0xffff][a1])
            elif entry==1:
                word(0x2de,param);word(0x2e0,a2);word(0x83c8,param);word(0x83ca,a1);word(0x83cc,a2);word(0x83ce,a3)
            elif entry==2:
                si,di=0x1200,[0x1300,0x1200,0x1202,0xfffe][a3];bx,dx=a1,a2
                tuples=[(0,1,0,1,2,0),(0xffff,1,0,0,2,0),(0,0xffff,0,1,1,0),(1,0x8000,0,0,0x7fff,0),(1,0,0,1,2,0),(1,1,0,1,0,0),(1,1,0,2,2,0x8000),(0,1,0,0xffff,1,0x7fff)];fields=tuples[param]
                for o,v in zip([si,si+2,si+4,di,di+2,di+4],fields):word(o,v)
            else:si,di,bx=param,a1,a2;word(0x380f,a3);word(0x3344,0xbeef)
            frame=struct.pack('<2H',0x1111,0x2222) if entry==1 else struct.pack('<H',0x1111);data[ss*16+sp-16:ss*16+sp+len(frame)+8]=b'\xa5'*16+frame+b'\xa5'*8;incoming=StateRegisters(Registers(ax,bx,cx,dx,si,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(writes=0,instructions=0,iterations=0,sites=set(),executing_return=False,prefix=False,fault=False,**{'return':False})
            def code(cpu,address,size,unused):
                if active['executing_return']:return
                pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence,'Arithmetic escaped '+str(pair))
                if pair in exits:active['return']=True;u.emu_stop();return
                if pair==(0x6c9,0x5c3a):
                    if active['iterations']==limit:active['prefix']=True;u.emu_stop();return
                    active['iterations']+=1
                if pair in {(0x143,0x1c9),(0x6c9,0x5c79)}:
                    active['division_prefix']={'flags':u.reg_read(UC_X86_REG_EFLAGS),'registers':[u.reg_read(reg) for reg in regs],'bp':u.reg_read(UC_X86_REG_BP),'sp':u.reg_read(UC_X86_REG_SP)}
                active['instructions']+=1;active['sites'].add(pair)
            def written(cpu,access,address,size,value,unused):active['writes']+=1
            def interrupt(cpu,number,unused):
                require(number==0,'Only divide fault');prefix=active['division_prefix'];require(prefix['registers']==[u.reg_read(reg) for reg in regs] and prefix['bp']==u.reg_read(UC_X86_REG_BP) and prefix['sp']==u.reg_read(UC_X86_REG_SP),'Fault operand/register preservation')
                # The native diagnostic is the pre-instruction fault prefix;
                # Unicorn exception delivery FLAGS are outside that contract.
                active['fault_delivery_flags_changed']=u.reg_read(UC_X86_REG_EFLAGS)!=prefix['flags'];u.reg_write(UC_X86_REG_EFLAGS,prefix['flags']);active['fault']=True;u.emu_stop()
            u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt);u.emu_start(cs*16+ip,0,count=2000000);label=f'{load:x}/{entry}/{param:x}/{a1:x}/{a2:x}/{a3:x}/{same}/{sp:x}/{flags:x}/{limit}';require(active['return'] or active['prefix'] or active['fault'],'Outcome '+label)
            if active['return']:
                pair=(segment,u.reg_read(UC_X86_REG_IP));sites.add(pair);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+pair[1],0,count=1);active['executing_return']=False
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(5 if active['fault'] else 3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.bus_writes==active['writes'] and out.iterations==active['iterations'],'Status/count '+label+str((out.status,out.iterations,out.bus_writes,active)));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['bus_write_events']+=out.bus_writes;coverage['fault_prefix' if active['fault'] else 'budget_prefix' if active['prefix'] else 'returns']+=1;coverage['iterations']+=out.iterations;coverage['LOOP_zero_full_runs']+=int(entry==0 and param<8 and out.iterations==65536);coverage['raw_returns']+=int(active['return'] and (out.next_segment,out.next_ip)!=((0x2222 if entry==1 else cs),0x1111))
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['fault_prefix']>0 and coverage['LOOP_zero_full_runs']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000129','FN-EGA-000363','FN-EGA-000400','FN-EGA-000402'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_small_arithmetic.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual record selector/raw counter IDIV/conditional pair update/square DIV helpers, currentDS/actualSS, word arithmetic/signed guards/SBB/LOOPzero/read-after-write aliases and near/farreturns. Fullbus/GPR/BP/CFIFDF/actualcontrol. Divide fault prefix separate, undefined DIVflags unadmitted; following defined operations determine returnedCF. Before-selector-iteration budget diagnostic separate. Actualcaller/otherFLAGS/bounds/tableunits/writers/lifetime/core/resource-fedP2/P3/device/session/game/fidelity remainopen.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
