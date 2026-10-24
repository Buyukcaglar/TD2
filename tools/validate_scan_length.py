"""Compare bounded REPNE scan, incoming DF and near-pointer wrap contracts."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['scans','bus_writes']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_scan_length;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='13A8:29B4')['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Near scan escaped '+hex(address))
            if ip==0x29c5 and u.reg_read(UC_X86_REG_CX)!=0:
                if active['scans']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['scans']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform service in near scan body')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=itertools.product([0x1111,0xfff1],[0,1,17,255,65534,65535,None],[0,1],[2,0x203,0x402,0x603],[0,1,4,65535])
        for pointer,length,same,flags,limit in cases:
            data=bytearray(base);ss=ds if same else 0x9000;df=(flags>>10)&1
            if length is not None:data[ds*16+((pointer+(-length if df else length))&65535)]=0
            frame=struct.pack('<2H',0x1111,0x2222);arguments=struct.pack('<H',pointer);guard=b'\xa5'*8;data[ss*16+sp-16:ss*16+sp+14]=b'\xa5'*16+frame+arguments+guard;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,df),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x29b4),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(scans=0,limit=limit,prefix=False,writes=0,instructions=0,sites=set());u.emu_start(cs*16+0x29b4,0x23331,count=100000);label=f'{load:x}/{pointer:x}/{length}/{same}/{flags:x}/{limit}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x2222,0x1111,sp+4),'Original scan result '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.scans==active['scans'] and out.bus_writes==active['writes'],'Native scan/prefix '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full near/SSbus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:
                require((out.next_segment,out.next_ip)==(0x2222,0x1111),'Far return coordinate '+label)
                if length in [65535,None]:require(out.scans==65535 and r.registers.ax==65534 and r.carry==1,'No terminator count/CF '+label);coverage['full_no_match_scans']+=1
                if length==65534:require(out.scans==65535 and r.registers.ax==65534 and r.carry==0,'Last eligible NUL/CF '+label);coverage['last_eligible_match_scans']+=1
            require(bytes(u.mem_read(ss*16+sp,14))==frame+arguments+guard,'Caller frame/argument/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix' if active['prefix'] else 'far_returns']+=1;coverage['scan_iterations']+=out.scans;coverage['reverse_DF_fixtures']+=df;coverage['bus_write_events']+=out.bus_writes
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['full_no_match_scans']>0 and coverage['last_eligible_match_scans']>0,'Scan instruction/boundary coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000329'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_scan_length.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual13A8:29B4 nearcurrentDS scan, ES=DS/AL0/CXFFFF REPNE SCASB with incomingDF retained, wordDIwrap, NOTCX/DECCX/XCHG ->AXcount/CX0 andDIrestoredviaDX. FullbusincludingSSBPsave/GPR/BP/CFIFDF/plainfarreturn. No-matchFFFFscans andlast-eligible-NUL bothAXFFFE distinguishedbyCF; noerror orstandardhoststrlen substitution. Nativebefore-scanprefix separate. Callerbounds/NUL/DF/otherFLAGS/lifetime/IRQ/core/resource-fedP2/P3/device/session/game/fidelity remainopen; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
