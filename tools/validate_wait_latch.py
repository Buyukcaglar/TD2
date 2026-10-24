"""Compare global raw-deadline publication/wait, actual79C8 and argument aliases."""
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
from validate_wait_control import Registers,StateRegisters,Request,Service,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_wait_latch;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:7A10','06C9:7A27','06C9:79C8']];require(len(fenced)==3,'Three latch/snapshot fences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();coverage=Counter();bounds=[0,1,0xffff,0x10000,0x7fffffff,0x80000000,0xfffffff0,0xffffffff]
    cases=[(0,start,distance,0,same,0) for start,distance,same in itertools.product(bounds,[0,1,0xffff,0x10000,0x7fffffff,0x80000000,0xffffffff],[0,1])]
    cases += [(1,0,deadline,profile,same,0) for deadline,profile,same in itertools.product(bounds,range(4),[0,1])]
    cases += [(0,start,0x12345678,0,1,alias) for start,alias in itertools.product(bounds,[1,2])]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for f in fenced for ip in f['instructions']}
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            require(address in starts,'Latch escaped fence')
            if address==cs*16+0x79c8 and not active['resume']:
                current=u.reg_read(UC_X86_REG_SP);ret=0x7a18 if active['entry']==0 else 0x7a2c;require(current==active['sp']-(6 if active['entry']==0 else 4) and bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Snapshot farframe');active['pending']=Request(0,0x7a13 if active['entry']==0 else 0x7a27,cs,0x79c8,read_regs());u.emu_stop();return
            active['resume']=False;active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,start,distance,profile,same,alias in cases:
            for flags in [2,3,0x202,0x203,0x402,0x403,0x602,0x603]:
                ss=ds if same else 0x9000;sp={0:0xe000,1:0x5e88,2:0x6812}[alias];data=bytearray(base);struct.pack_into('<I',data,ds*16+0x6818,distance);frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-32:ss*16+sp+12]=b'\xa5'*32+frame+struct.pack('<I',distance)+b'\xa5'*4;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
                for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x7a10 if entry==0 else 0x7a27),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
                def service(events,write,q):
                    index=len(events);event=[q.kind,q.site,q.segment,q.offset,values(q.incoming.registers),q.incoming.bp,q.incoming.carry];events.append(event)
                    if entry==0:counter=start
                    elif profile==0:counter=[max(distance-1,0),distance][min(index,1)]
                    elif profile==1:counter=[(distance+1)&0xffffffff,distance][min(index,1)]
                    elif profile==2:counter=[0,1,0xffffffff][min(index,2)]
                    else:
                        counter=0
                        if index==1:write(ds*16+0x6818,struct.pack('<I',0))
                    write(ds*16+0x5e8c,struct.pack('<I',counter))
                active.update(ss=ss,sp=sp,entry=entry,pending=None,resume=False,instructions=0,sites=set(),events=[]);u.emu_start(cs*16+(0x7a10 if entry==0 else 0x7a27),0x11210,count=256)
                while active['pending']:
                    require(len(active['events'])<16,'Finite counter fixture');q=active['pending'];active['pending']=None;service(active['events'],lambda at,b:u.mem_write(at,b),q);active['resume']=True;u.emu_start(cs*16+0x79c8,0x11210,count=256)
                label=f'{load:x}/{entry}/{start:x}/{distance:x}/{profile}/{same}/{alias}/{flags:x}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original RETF '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
                def callback(ctx,bus,q,r):
                    try:service(events,lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q.contents);r.contents.registers.ds=0;r.contents.bp=0;r.contents.carry=2;return 1
                    except Exception as e:errors.append(str(e));return 0
                cb=Service(callback);out=Result();fn(gb,len(gb),load,ss,sp,entry,C.byref(incoming),cb,None,16,C.byref(out));require(not errors and out.status==0 and out.events==len(events) and events==active['events'],'Native counter streams '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp==incoming.bp,'Registers/BP '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,4))==frame and bytes(u.mem_read(ss*16+sp+8,4))==bytes(gb[ss*16+sp+8:ss*16+sp+12]),'Frame/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['set' if entry==0 else 'wait']+=1;coverage['events']+=out.events;coverage['argument_alias_'+str(alias)]+=1;coverage['mutable_global_deadline']+=int(entry==1 and profile==3)
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(r['id'] for r in registry if r['entries'][0].get('segment')==0x6c9 and r['entries'][0].get('segment_offset')==ip) for ip in [0x7a10,0x7a27]];require(len(sites)==len(starts),'All latch/snapshot sites');record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_wait_latch.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_wait_control.py','sha256':hashlib.sha256((ROOT/'tools/validate_wait_control.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete7A10/7A27+actual79C8 instructions/nativecounter composition, SSargument reads aftersnapshot, ADDADC32/CF, orderedDS6818/A publication, mutableglobaldeadline unsignedcompare andIF1/DF/BP retained. Counterboundarybusupdates only, noIRQ/clockrate/history/physical086Cmeaning/device/core/game/fidelity. Argument-dataaliases checked; native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','function_ids','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
