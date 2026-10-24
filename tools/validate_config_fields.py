"""Compare ordered CS bound stores and the 52-byte near-output snapshot."""
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
from validate_copy_config import Registers,StateRegisters,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();library=args.library.resolve();output=args.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_config_fields;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in graph['functions'] if f['entry'] in ['06C9:5DFB','06C9:78F8'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[principal*16:principal*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def code(cpu,address,size,unused):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Config fields escaped '+hex(address))
            if ip==0x7911 and u.reg_read(UC_X86_REG_CX)!=0:
                if active['work']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['work']+=1
            if ip in [0x5e1b,0x7917] and not active['allow_raw_return']:
                words=struct.unpack('<2H',u.mem_read(active['ss']*16+u.reg_read(UC_X86_REG_SP),4))
                if words!=(0x100,0x1111):active['raw_pending']=ip;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(*unused):raise RuntimeError('No platform service in field/snapshot bodies')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=[(0,seed,profile,0,flags,0) for seed,profile,flags in itertools.product([0,1,0x7fff,0x8000,0xffff],range(3),[2,0x203,0x402,0x603])]
        cases +=[(1,0,profile,same,flags,limit) for profile,same,flags,limit in itertools.product(range(5),[0,1],[2,0x203,0x402,0x603],[0,1,25,26,27]) if profile!=4 or same]
        for entry,seed,profile,same,flags,limit in cases:
            data=bytearray(base);ds=cs if entry==1 and profile in [1,2] else principal;ss=cs if entry==0 and profile==2 else ds if entry==0 and profile==1 or entry==1 and same else 0x9000;sp=0xaf40 if entry==0 and profile==2 else 0xe000;raw=entry==1 and profile==4;destination=0xaf39 if profile==1 else 0xaf3b if profile==2 else 0xfffe if profile==3 else sp-8 if raw else 0x2800
            for i in range(26):struct.pack_into('<H',data,cs*16+0xaf3a+2*i,(0xa500+i*37)&65535)
            if raw:struct.pack_into('<2H',data,cs*16+0xaf3a+8,0x1234,0x7777)
            arguments=[seed,seed^0x1234,(seed+1)&65535,seed^0xffff] if entry==0 else [destination];frame=struct.pack('<2H',0x100,0x1111);tail=struct.pack('<'+'H'*len(arguments),*arguments)+b'\x5a\xa5'*4;data[ss*16+sp-16:ss*16+sp+len(frame)+len(tail)]=b'\xa5'*16+frame+tail;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x5dfb if entry==0 else 0x78f8),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(ss=ss,work=0,limit=limit,prefix=False,raw_pending=0,allow_raw_return=False,writes=0,instructions=0,sites=set());u.emu_start(cs*16+(0x5dfb if entry==0 else 0x78f8),0x11210,count=1000)
            if active['raw_pending']:active['allow_raw_return']=True;u.emu_start(cs*16+active['raw_pending'],0,count=1)
            label=f'{load:x}/{entry}/{seed:x}/{profile}/{same}/{flags:x}/{limit}';require(active['prefix'] or active['raw_pending'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original far return '+label);require(bool(active['raw_pending'])==(raw and not active['prefix']),'Return alias profile '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.work==active['work'] and out.writes==active['writes'],'Native result/prefix '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Actual far coordinate '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['setter' if entry==0 else 'snapshot']+=1;coverage['prefix' if active['prefix'] else 'raw_root_returns' if raw else 'far_returns']+=1;coverage['copy_words']+=out.work;coverage['bus_write_events']+=out.writes;coverage['setter_argument_CS_output_aliases']+=int(entry==0 and profile==2)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised field/snapshot sites '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000140','FN-EGA-000194'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_config_fields.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_copy_config.py','tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'FourorderedSSwordreread->CSboundstores withDFpreserved, and26wordCSsnapshot->currentDSnearoffset withCLD; fullbusincludingSSsaved/controlframes/GPR/BP/CFIFDF/farRETF4. SetterSS=CS argument/outputaliases, oddCSsource-destinationoverlaps/wrap andsnapshotoutputoverSSsaved/returnframes tested. Nativeprefixseparate; intentionalrootreturnaliases stopafteractualRETF andexposeactualCS:IP/SP, notfollowed. Native0meansoriginalfarreturnoperation, notsupportedcaller/gamecompletion. Actualbounds/producers/allwriters/lifetime/IRQexclusion/fullstate/core/device/resource-fedP2/P3/game/fidelity remainopen; nooriginalconfiguration/media payloadembedded; nativeinvalidchecks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
