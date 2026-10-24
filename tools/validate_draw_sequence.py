"""Compare26D8/284F/28F9 orchestration, ordered arguments and wrap loops."""
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
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['kind','site','segment','offset','argument_count','live_argument_count','stack_segment','stack_sp']]+[('arguments',C.c_uint16*16),('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','return_bytes']]+[('calls',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_draw_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=[0x26d8,0x284f,0x28f9];fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{x:04X}' for x in entries]];require(len(fenced)==3,'Three caller fences');regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
    cases=[(0,flag,other,profile,0,256) for flag,other,profile in itertools.product(range(256),range(3),range(4))]
    cases += [(1,start,flags,profile,mode,budget) for start,flags,profile,mode in itertools.product([0,1,8,16,17,0xffff,0x8000],[0,4,0x20,0x24],range(4),range(3)) for budget in [256 if start in [0,1,8,16,0x8000] else 12]]
    cases += [(2,start,bound,profile,mode,budget) for start,bound,profile,mode in itertools.product([0,1,8,16,17,0x7fff,0x8000,0xffff],[0,1,8,16,17,0x7fff,0x8000,0xffff],range(4),range(3)) for budget in [256]]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={cs*16+int(c['site'][5:],16):(int(c['kind']=='lcall'),int(c['site'][5:],16),int(c['target'][5:],16),int(c['site'][5:],16)+c['size']) for f in fenced for c in f['calls']};active={}
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            if active.get('expected') and address==cs*16+active['expected'][2]:
                kind,site,target,ret=active['expected'];current=u.reg_read(UC_X86_REG_SP);framebytes=4 if kind else 2;frame=struct.pack('<2H',ret,cs) if kind else struct.pack('<H',ret);require(bytes(u.mem_read(active['ss']*16+current,framebytes))==frame,'Near/far frame');live=(sp-current-framebytes)//2 if kind else 0;argc=5 if target==0x89a2 else 4 if target==0x916c else 0;require(0<=live<=16,'Virtual pool bounds');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+framebytes,live*2))) if live else [];q=Request(kind,site,cs,target,argc,live,active['ss'],current,(C.c_uint16*16)(*(args+[0]*(16-live))),read_regs());active['expected']=None;active['pending']=(q,ret,framebytes);u.emu_stop();return
            require(address in starts,'Draw sequence escaped fence '+hex(address))
            if address in calls:
                if len(active['events'])==active['budget']:active['prefix']=True;u.emu_stop();return
                active['expected']=calls[address]
            active['instructions']+=1;active['sites'].add(address-cs*16)
        def interrupt(*_):raise RuntimeError('Unexpected original interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,start,other,profile,mode,budget in cases:
            ss=ds if vectors&1 else 0x9000;data=bytearray(base)
            for page in [ds,0x5000]:
                def put(at,v):struct.pack_into('<H',data,page*16+(at&65535),v&65535)
                for i in range(0x400):put(0x9c4+2*i,(i*13+profile*7)&127)
                for i in range(40):put(0xd5c+2*i,other if entry==1 else 0)
                fields={0x2c2a:start if entry else [0,17,0x8000,0xffff][profile],0x2c30:other if entry==2 else 17,0x2c78:start if entry==2 else 8,0x2c82:37,0x2c32:63,0x2c2c:[80,0,0x7fff,0x8000][profile],0x2c66:[0,80,0xffff,0x7fff][profile],0x2c34:[1,80,0xffff,0x8000][profile],0x2c84:[79,0,0x7fff,0xffff][profile],0x2c7a:8,0x2c7c:12,0x2c7e:10,0x2c86:[0,80,0x8000,0xffff][profile],0x2c88:[0,80,0x8000,0xffff][3-profile],0x2c2e:[0,80,0x8000,0xffff][profile],0x2c68:[80,0,0x7fff,0x8000][profile],0x2a26:0x6000,0x2a28:0xb000,0x5344:[0,511,0x8000,0xffff][profile],0x2f48:[0,127,0x8000,0xffff][profile],0x2b56:17}
                for at,v in fields.items():put(at,v)
                for i in range(5):put(0x534a+i*2,(profile*7+i)&15)
                for i in range(6):put(0x27de+2*i,0x1234+i*0x1111)
                data[page*16+0x2c98]=start if entry==0 else 0;data[page*16+0x2c97]=128 if profile&1 else 0;data[page*16+0x37f7]=1 if (entry==0 and other==1) or (entry==2 and profile&1) else 0;data[page*16+0x37f8]=1 if entry==0 and other==2 else 0
            frame=struct.pack('<H',0x100);data[ss*16+sp-64:ss*16+sp+6]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def service(model,write,q):
                index=len(model)+1;model.append([q.kind,q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),values(q.incoming.registers),q.incoming.bp,q.incoming.carry]);r=StateRegisters(Registers(*values(q.incoming.registers)),0x8000+index,index&1);rr=r.registers;rr.ax=0xa000+index;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.di=(rr.di+3)&65535;rr.es=0x6000;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if mode==1 and index==1:rr.ds=0x5000
                if mode==2 and entry==2 and index==1:write(rr.ds*16+0x2c30,struct.pack('<H',33))
                if profile==3 and entry==0 and index==1:write(rr.ds*16+0x27e0,b'\0\0')
                write(0x80000+2*index,struct.pack('<H',q.site));return r
            active.update(expected=None,pending=None,ss=ss,budget=budget,prefix=False,events=[],instructions=0,sites=set());u.emu_start(cs*16+entries[entry],cs*16+0x100,count=20000)
            while active['pending']:
                q,ret,framebytes=active['pending'];active['pending']=None;returned=service(active['events'],lambda at,b:u.mem_write(at,b),q);rr=returned.registers
                for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+framebytes),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,cs*16+0x100,count=20000)
            label=f'{load:x}/{entry}/{start:x}/{other:x}/{profile}/{mode}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x100,sp+2),'Original normal/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,m,q,r):
                try:returned=service(events,lambda at,b:C.memmove(C.byref(bus,at),b,len(b)),q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 0) and out.calls==len(events) and events==active['events'] and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.return_bytes==2,'Native frames/arguments/prefix '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Nonframe bus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Rootnearframeguard '+label);coverage[f'{entries[entry]:04X}']+=1;coverage['prefix' if active['prefix'] else 'normal']+=1;coverage['far_calls']+=sum(e[0]==1 for e in events);coverage['near_calls']+=sum(e[0]==0 for e in events);coverage['sixteen_live_words']+=sum(e[5]==16 for e in events);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
    missing=sorted(address-cs*16 for address in starts if address-cs*16 not in sites);require(not missing,'All orchestration instruction locations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000093','FN-EGA-000094','FN-EGA-000095'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_draw_sequence.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete26D8/284F/28F9 orchestration with nearC17/D01 andfar89A2/916C ABI mocks, caller-clean retained5+5 and4x4wordpools, currentDS/CSlookup/ES andreturnedstate, rawSI!=34 wraploop andsignedtemporaryboundshift/aliases, normalRET2 versusnativecallbudgetprefix. No actualdrawingleaf/producer/tablecapacity/resourceformat/SS-DS/IRQ/renderer/core/game/fidelity. Native diagnostics separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
