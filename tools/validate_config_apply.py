"""Compare actual3EFC+7D5E with complete nested SS frames and raw returns."""
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
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['work','writes','calls']]+[('returned',StateRegisters)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_config_apply;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in graph['functions'] if f['entry'] in ['06C9:3EFC','06C9:7D5E'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Config caller escaped '+hex(address))
            if ip==0x7d5e:
                current=u.reg_read(UC_X86_REG_SP);words=struct.unpack('<4H',u.mem_read(active['ss']*16+current,8));require(words[:2]==(0x3f09,cs),'Actual child far frame');active['far_boundary']=list(words)
            if ip==0x7d75 and u.reg_read(UC_X86_REG_CX)!=0:
                if active['work']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['work']+=1
            if ip==0x7d7b and not active['allow_raw_return']:
                words=struct.unpack('<2H',u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))
                if words!=(0x3f09,cs):active['raw_pending']=True;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform service in actual config chain')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(profile,same,sp,flags,limit,False) for profile,same,sp,flags,limit in itertools.product(range(4),[0,1],[0xe000,0x9b2,0x9b4,0x9b6],[2,0x203,0x402,0x603],[0,1,12,13,16])]
        cases +=[(0,0,0xaf40,flags,13,True) for flags in [2,0x203,0x402,0x603]]
        for profile,same,sp,flags,limit,raw in cases:
            data=bytearray(base);ss=cs if raw else ds if same else 0x9000;source=cs if profile in [1,2] else 0x6000;offset=0xaf39 if profile==1 else 0xaf3b if profile==2 else 0xffff if profile==3 else 0x2000
            for i in range(64):data[((source<<4)+((offset+i)&65535))&0xfffff]=(i*37+profile*11)&255
            if raw:struct.pack_into('<H',data,source*16+offset,0x7777)
            struct.pack_into('<2H',data,ds*16+0x9b2,offset,source);frame=struct.pack('<2H',0x100,0x1111);guard=b'\x5a\xa5'*4;data[ss*16+sp-32:ss*16+sp+12]=b'\xa5'*32+frame+guard
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x3efc),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(ss=ss,limit=limit,work=0,prefix=False,raw_pending=False,allow_raw_return=False,writes=0,instructions=0,sites=set(),far_boundary=None);u.emu_start(cs*16+0x3efc,0x11210,count=1000)
            if active['raw_pending']:
                active['allow_raw_return']=True;u.emu_start(cs*16+0x7d7b,0,count=1)
            label=f'{load:x}/{profile}/{same}/{sp:x}/{flags:x}/{limit}/{raw}';require(active['prefix'] or active['raw_pending'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original root return '+label);require(active['raw_pending']==raw,'Raw alias fixture '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.work==active['work'] and out.writes==active['writes'] and out.calls==1,'Actual native child/result '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full nested frame bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Far/raw transfer coordinate '+label)
            if not raw:require(bytes(u.mem_read(ss*16+sp,12))==frame+guard,'Root return/guard '+label)
            require(active['far_boundary'] is not None,'Far boundary exercised');vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix' if active['prefix'] else 'raw_child_returns' if raw else 'root_far_returns']+=1;coverage['copy_words']+=out.work;coverage['bus_write_events']+=out.writes;coverage['far_boundaries']+=1;coverage['DS_SS_argument_alias_profiles']+=int(same and sp!=0xe000)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised root/child sites '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000122'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_config_apply.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual3EFC+7D5E Cbodies, twoSSwordpool/nestedfarframes/savedregisters/fullbus/GPR/BP/CFIFDF/ADDSP4/rootfarRETF4 matched, noABIleafmocks orSSscratch exclusions. DS=SS argument-global/stack aliases tested, nativewordprefixes distinct. EightintentionalCS-output/childreturnCS aliases stopafteractualchildRETF andreturnrawtarget; no normalrootreturn/errorinvented. Actualsourceproducer/capacity/allwriters/lifetimes/IRQexclusion/fullstate/core/resource-fedP2/P3/device/game/fidelity remainopen; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
