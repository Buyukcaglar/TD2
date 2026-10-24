"""Compare raw error mapping, CS lookup, signed byte table and field selectors."""
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_table_scalar;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[(0x13a8,0x94a),(0x13a8,0x2d57),(0x13a3,0x12),(0x6c9,0x5334),(0x6c9,0x535b)];names={f'{s:04X}:{ip:04X}' for s,ip in entries};selected=[f for f in g['functions'] if f['entry'] in names];fence={(int(f['entry'][:4],16),ip) for f in selected for ip in f['instructions']};exits={(int(f['entry'][:4],16),int(e['site'][5:],16)) for f in selected for e in f['exits']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence,'Table/scalar escaped '+str(pair))
            if pair in exits:active['return']=True;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(pair)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform service in table/scalar functions')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(0,al,version,pattern,same,0xe000,flags) for al,version,pattern,same,flags in itertools.product(range(256),[0,2,3,255],[0,1],[0,1],[2,0x603])]
        cases +=[(0,(ah<<8)|al,version,0,same,sp,flags) for ah,al,version,same,sp,flags in itertools.product([1,0x80,0xff],[0,0x13,0x20,0x21,0x22,0xff],[0,3],[0,1],[0xe000,0x6da0,0x6d95],[2,0x203,0x402,0x603])]
        cases +=[(1,al,0,pattern,same,0xe000,flags) for al,pattern,same,flags in itertools.product(range(256),[0,1],[0,1],[2,0x603])]
        cases +=[(2,(high<<8)|al,0,pattern,same,sp,flags) for al,high,pattern,same,sp,flags in itertools.product(range(256),[0,0xff],[0,1],[0,1],[0xe000,0x54aa],[2,0x603])]
        cases +=[(3,ax,bx,pattern,same,sp,flags) for ax,bx,pattern,same,sp,flags in itertools.product([0,1,0x7fff,0x8000,0xffff],[0xfe6f,0xfe70,0xffff,0,399,400,800,801],[0,1,2],[0,1],[0xe000,0x333e],[2,0x603])]
        cases +=[(4,ax,0,pattern,same,0xe000,flags) for ax,pattern,same,flags in itertools.product([0x8000,0xffd7,0xffd8,0xffff,0,40,41,359,360,440,441,0x7fff],[0,1,2,3],[0,1],[2,0x203,0x402,0x603])]
        for entry,ax,param,pattern,same,sp,flags in cases:
            data=bytearray(base);ss=ds if same else 0x9000;segment,ip=entries[entry];cs=load+segment
            def word(o,v):struct.pack_into('<H',data,ds*16+o,v&65535)
            data[ds*16+0x6d9d]=param if entry==0 else 3
            for k in range(256):data[ds*16+0x6dda+k]=(k*(7 if pattern else 1)+(0x80 if pattern else 0))&255
            for k in range(129):word(0x54aa+2*k,[k,0x8000+k][pattern&1])
            fields=[[0,1,2],[0x7fff,0x8000,0xffff],[0xffff,0x7fff,0x8000],[400,200,600]][pattern]
            for o,v in zip([0x333e,0x3340,0x3342],fields):word(o,v)
            data[ds*16+0x33be]=0x80 if pattern&1 else 0
            if entry==1 and pattern:data[(load+0x13a8)*16+0x2cae:(load+0x13a8)*16+0x2cb4]=bytes([0,1,0x80,0x41,0xff,0x7f])
            frame=struct.pack('<2H',0x1111,0x2222) if entry in [1,2] else struct.pack('<H',0x1111);data[ss*16+sp-16:ss*16+sp+len(frame)+8]=b'\xa5'*16+frame+b'\xa5'*8;incoming=StateRegisters(Registers(ax,param if entry==3 else 0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.update(writes=0,instructions=0,sites=set(),executing_return=False,**{'return':False});u.emu_start(cs*16+ip,0,count=1000);label=f'{load:x}/{entry}/{ax:x}/{param:x}/{pattern}/{same}/{sp:x}/{flags:x}';require(active['return'],'Return '+label);pair=(segment,u.reg_read(UC_X86_REG_IP));sites.add(pair);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+pair[1],0,count=1);active['executing_return']=False;bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),C.byref(out));require(out.status==0 and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.bus_writes==active['writes'],'Status/writes '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Actual return '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['bus_write_events']+=out.bus_writes;coverage['carry_set_returns']+=r.carry;coverage['raw_returns']+=int((out.next_segment,out.next_ip)!=((0x2222 if entry in [1,2] else cs),0x1111))
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000272','FN-EGA-000340','FN-EGA-000420','FN-EGA-000393','FN-EGA-000394'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_table_scalar.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual error byte/currentDS XLAT/word signextension, six currentCS byte lookup, signedAL/externalword table and raw signed threshold/selection helpers; original near/far returns and actualSSsavedframes. Fullbus/GPR/BP/CFIFDF/actualcontrol coordinates, overwrittenreturns exposed notfollowed. Externaltables private fixture/original views, no bundledtablepayload or sourceCtype/fieldunits inferred. Caller/tablebounds/otherFLAGS/writers/lifetime/core/resource-fedP2/P3/device/session/game/fidelity remainopen; nativeinvalid checks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
