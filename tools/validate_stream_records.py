"""Compare special-record setup, raw byte membership and eight-byte scan/reset."""
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_stream_records;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[0xf16,0x2170,0x219a];selected=[f for f in g['functions'] if f['entry'] in [f'13A8:{ip:04X}' for ip in entries]];fence={ip for f in selected for ip in f['instructions']};exits={int(e['site'][5:],16) for f in selected for e in f['exits']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Stream records escaped '+hex(address))
            if ip in exits:active['return']=True;u.emu_stop();return
            if ip in [0x2181,0x21a8]:
                if active['iterations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['iterations']+=1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform instruction in these record bodies')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        # Tuple: selector, pointer/key/end, index/position, flags/freeflag,
        # sideflag/higharg, guard/pattern, DS=SS, SP, FLAGS, budget.
        cases=[(0,pointer,index,recordflags,side,0,same,0xe000,flags,0) for pointer,index,recordflags,side,same,flags in itertools.product([0x6dfc,0x6e04,0x6e14],range(256),[0,2],[0,1],[0,1],[2,0x603])]
        cases +=[(0,pointer,index,recordflags,side,guard,same,sp,flags,0) for pointer,index,recordflags,side,guard,same,sp,flags in itertools.product([0x6dfc,0x6e04,0x6e14,0x6e24],[0,1,0x22,0x7f,0x80,0xff],[0,2,4,8,0x80,0xff],[0,1],[0,1],[0,1],[0x6dee,0x6df8,0x6e00,0x6e08],[2,0x603])]
        cases +=[(1,key,position,0,high,0,same,sp,flags,limit) for key,position,high,same,sp,flags,limit in itertools.product([0,1,0x41,0x80,0xff],[0,1,17,255,None],[0,0xa5],[0,1],[0xe000,0x6f20],[2,0x203,0x402,0x603],[0,1,4,256])]
        cases +=[(1,0xff,None,0,0,0,0,0xe000,flags,65536) for flags in [2,0x603]]
        cases +=[(2,end,free,freeflag,0,0,same,sp,flags,limit) for end,free,freeflag,same,sp,flags,limit in itertools.product([0,1,2,17,8191,None],[0,1,17,None],[0,0xa4,0x7c],[0,1],[0xe000,0x6df8,0x6f0c],[2,0x603],[0,1,4,64])]
        cases +=[(2,8191,None,0,0,0,0,0xe000,flags,8192) for flags in [2,0x603]]
        cases +=[(2,end,free,freeflag,0,0,1,sp,flags,limit,0x4444) for end,free,freeflag,sp,flags,limit in itertools.product([0,1,2],[0,1],[0,0xa4,0x7c],[0x6df8,0x6f0c],[2,0x603],[0,1,4,64])]
        for case in cases:
            entry,param,index,recordflags,side,guard,same,sp,flags,limit=case[:10];return_cs=case[10] if len(case)==11 else 0x2222
            data=bytearray(base);ss=ds if same else 0x9000
            def putword(o,v):
                at=ds*16+(o&65535);data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
            if entry==0:
                pointer=param;putword(0x6df2,0xffff if index&0x80 else 0x7fff);data[ds*16+pointer+6]=recordflags;data[ds*16+pointer+7]=index;di=((index if index<128 else index-256)*6)&65535;data[ds*16+((di+0x6e94)&65535)]=side;putword(0x6e00,0x8440 if guard else 0x1234);argument=pointer
            elif entry==1:
                argument=(side<<8)|param;data[ds*16+0x6f1e:ds*16+0x6f1e+300]=b'\x55'*300
                if index is not None:data[ds*16+0x6f1e+index]=param;data[ds*16+0x6f1e+index+1]=0
            else:
                argument=0x1234;end=0 if param is None else (0x6df4+8*param)&65535;putword(0x6f0c,end)
                if index is not None:data[ds*16+((0x6df4+8*index+6)&65535)]=recordflags
            frame=struct.pack('<3H',0x1111,return_cs,argument);data[ss*16+sp:ss*16+sp+6]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(limit=limit,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+entries[entry],0,count=1000000);label=f'{load:x}/{entry}/{param}/{index}/{recordflags:x}/{side}/{guard}/{same}/{sp:x}/{flags:x}/{limit}';require(active['prefix'] or active['return'],'Outcome '+label)
            if active['return']:
                ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.iterations==active['iterations'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['budget_prefix' if active['prefix'] else 'root_far_return']+=1;coverage['iterations']+=out.iterations;coverage['bus_write_events']+=out.bus_writes;coverage['raw_root_returns']+=int(active['return'] and (out.next_segment,out.next_ip)!=(return_cs,0x1111));coverage['controlled_return_alias_fixture_cases']+=int(len(case)==11);coverage['negative_index_byte_fixtures']+=int(entry==0 and index>=128);coverage['member_full_cycle_prefix']+=int(entry==1 and out.iterations==65536);coverage['record_full_cycle_end']+=int(entry==2 and out.status==0 and out.iterations==8192)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence and coverage['raw_root_returns']>0 and coverage['member_full_cycle_prefix']>0 and coverage['record_full_cycle_end']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000284','FN-EGA-000307','FN-EGA-000308'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_stream_records.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual0F16specialrecord/signedbyte*6/sideflag orderedsetup,2170rawbyte membership/CHpreservation/INCSI,219Araw8byte scan/old-SI-inclusiveend/resetstores. Fullbus/actualSSsaves/farframes/GPR/BP/CFIFDF/control, all256indexbytes/negative/wrap/SSglobalaliases. Nativebefore-scanbudget separate; rawmissingNUL/nonalignedend maycycle. SourceCtypes/recordunits/actualcaller bounds/writers/lifetime/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
