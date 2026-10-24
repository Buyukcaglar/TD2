"""Compare bytecase/signextension and three raw signed/indexed state helpers."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32),('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];reference='docs/recovery/evidence/td2ega-sign-extension-context-v1.json';require(json.loads((ROOT/reference).read_text())['result']=='pass','Operand-width proof');fn=C.CDLL(str(library)).td2ega_scalar_state;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[(0x16aa,2),(0x13a8,0x2a18),(0x13a8,0x190e),(0x432,0x1d25)];names={f'{s:04X}:{ip:04X}' for s,ip in entries};fence={(int(f['entry'][:4],16),ip) for f in g['functions'] if f['entry'] in names for ip in f['instructions']};exit_sites={(int(f['entry'][:4],16),int(e['site'][5:],16)) for f in g['functions'] if f['entry'] in names for e in f['exits'] if e['kind']=='retf'};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();chars=set()
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence,'Scalar helpers escaped '+str(pair))
            if pair in exit_sites and not active['allow_raw_return']:
                words=struct.unpack('<2H',u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))
                if words!=(0x100,0x1111):active['raw_pending']=pair;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(pair)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No OS/device service in finite scalar bodies')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(0,char,high,0,same,0xe000,flags) for char,high,same,flags in itertools.product(range(256),[0,0x12,0x80,0xff],[0,1],[2,0x203,0x402,0x603])]
        cases +=[(1,index,limit,flag,same,sp,flags) for index,limit,flag,same,sp,flags in itertools.product([0,1,2,0x7fff,0x8000,0xffff],[0,1,2,0x7fff,0x8000,0xffff],[0,0x40,0x41,0xff],[0,1],[0xe000,0x6da4],[2,0x203,0x402,0x603])]
        cases +=[(2,flag,count,0,same,sp,flags) for flag,count,same,sp,flags in itertools.product([0,1,0xffff],[0,1,2,0x7fff,0x8000,0xffff],[0,1],[0xe000,0x83da],[2,0x203,0x402,0x603])]
        cases +=[(3,index,value,0,same,sp,flags) for index,value,same,sp,flags in itertools.product([0,1,0x7fff,0x8000,0xffff,0x462f,0xc62f,0x44f1,0x4526,0x44ee,0x6fe0],[0,1,0x8000,0xffff],[0,1],[0xe000,0x8a22,0x8c9e],[2,0x203,0x402,0x603])]
        for entry,a,b,extra,same,sp,flags in cases:
            data=bytearray(base);ss=ds if same else 0x9000;segment,ip=entries[entry];cs=load+segment
            def put(offset,value):struct.pack_into('<H',data,ds*16+offset,value&65535)
            if entry==1:put(0x6da2,b);data[ds*16+((a+0x6da4)&65535)]=extra
            if entry==2:put(0x83e4,a);put(0x83da,b)
            if entry==3:
                for offset,value in [(0x8a22,a),(0x8a8c,0xdead),(0x8a1c,0xbeef),(0x8c9e,b)]:put(offset,value)
            arguments=struct.pack('<H',(b<<8)|a) if entry==0 else struct.pack('<H',a) if entry==1 else b'';frame=struct.pack('<2H',0x100,0x1111);guard=b'\x5a\xa5'*4;data[ss*16+sp-16:ss*16+sp+len(frame)+len(arguments)+len(guard)]=b'\xa5'*16+frame+arguments+guard;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));upper_eax=0x81230000 if b&0x80 else 0xa5a50000;u.reg_write(UC_X86_REG_EAX,upper_eax|incoming.registers.ax)
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(ss=ss,raw_pending=None,allow_raw_return=False,writes=0,instructions=0,sites=set());u.emu_start(cs*16+ip,0x11210,count=1000)
            if active['raw_pending']:active['allow_raw_return']=True;u.emu_start((load+active['raw_pending'][0])*16+active['raw_pending'][1],0,count=1)
            label=f'{load:x}/{entry}/{a:x}/{b:x}/{extra:x}/{same}/{sp:x}/{flags:x}';require((active['raw_pending'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))==(0x1111,0x100)) and u.reg_read(UC_X86_REG_SP)==sp+4,'Original far result '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),C.byref(out));require(out.status==0 and out.current_sp==sp+4 and out.bus_writes==active['writes'],'Native scalar return/writes '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/SS/rawfields '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Actual far coordinate '+label)
            if entry==0:require(u.reg_read(UC_X86_REG_EAX)&0xffff0000==upper_eax,'Original98upperEAXpreserved '+label);chars.add(a);coverage['original_upper_EAX_checks']+=1;coverage['ASCII_argument_high_byte_preserved']+=int(bus[ss*16+sp+5]==b)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['raw_root_returns' if active['raw_pending'] else 'far_returns']+=1;coverage['bus_write_events']+=out.bus_writes;coverage['returned_CF1']+=r.carry
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and chars==set(range(256)),'Scalar/ASCII coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000421','FN-EGA-000333','FN-EGA-000295','FN-EGA-000052'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_scalar_state.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py',reference]],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'distinct_input_bytes':len(chars),'fixture_coverage':dict(coverage),'limits':'Four finitebodies/fullbusincludingSS/GPR/BP/CFIFDF/plainfarreturns. FN421all256signedbytecases/argumenthighbyte preservation/ASCIIlowercase lowbyteSUB andunprefixed98AXsignextension; originalupperEAXpreservation checkedseparatelyfrom16bitnativeAPI, primaryISA+60microfixtures pinwidth. Signedindex/limit+bit40, rawflag/signedpositivecounter andindexedresetpostwritealiases/SHLcarry retained. ControlledSS/global/rootreturnaliases exposeactualfarcoordinateafterRETF, no targetfollowed. NooriginalCreturntype/tableformat/globalunits inferred. Actualcaller/otherFLAGS/bounds/writers/lifetime/IRQ/fullstate/core/resource-fedP2/P3/device/session/game/fidelity remainopen; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','distinct_input_bytes','fixture_coverage']},indent=2))

if __name__=='__main__':main()
