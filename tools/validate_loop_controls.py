"""Compare three root-loop controls, near/far frames and paired drawing arguments."""
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
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['kind','site','segment','offset','argument_count','live_argument_count','stack_segment','stack_sp']]+[('arguments',C.c_uint16*10),('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','return_bytes']]+[('calls',C.c_uint32),('returned',StateRegisters)]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_loop_control;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=[0x1f60,0x1f71,0x1f99];fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{x:04X}' for x in entries]];require(len(fenced)==3,'Three loopcontrol fences');md=Cs(CS_ARCH_X86,CS_MODE_16);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;sites=set();coverage=Counter();sp=0xe000
    specs={0x1f68:(2,2),0x1faa:(2,2),0x201a:(4,4),0x2060:(5,10),0x2068:(5,5),0x207d:(2,2)}
    cases=[(2,mode,count,mask,profile,same) for mode,count,mask,profile,same in itertools.product([0,1,3,4,5,255],[0,1,7,8,127,128,0x7fff,0x8000,0xffff],[0,128,255],range(4),[0,1])]
    cases += [(entry,mode,count,128,profile,same) for entry,mode,count,profile,same in itertools.product([0,1],[0,255],[0,0xffff],range(4),[0,1])]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            for c in f['calls']:
                ip=int(c['site'][5:],16);kind=int(c['kind']=='lcall');target=int(c['target'][5:],16);size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc,live=specs.get(ip,(0,0));calls[cs*16+ip]=(kind,ip,target,ip+size,argc,live)
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            if active.get('expected') and address==cs*16+active['expected'][2]:
                kind,site,target,ret,argc,live=active['expected'];current=u.reg_read(UC_X86_REG_SP);framebytes=4 if kind else 2;frame=struct.pack('<2H',ret,cs) if kind else struct.pack('<H',ret);require(bytes(u.mem_read(active['ss']*16+current,framebytes))==frame,'Loopcontrol near/far frame');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+framebytes,live*2))) if live else [];q=Request(kind,site,cs,target,argc,live,active['ss'],current,(C.c_uint16*10)(*(args+[0]*(10-live))),read_regs());active['expected']=None;active['pending']=(q,ret,framebytes);u.emu_stop();return
            require(address in starts,'Loopcontrol escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,mode,count,mask,profile,same in cases:
            ss=ds if same else 0x9000;data=bytearray(base)
            for page in [ds,0x5000]:
                data[page*16+0x33d4]=mode if page==ds else (4 if mode==0 else 0);data[page*16+0x2c98]=mask;struct.pack_into('<H',data,page*16+0x33ce,count)
                for at in [0x2a20,0x2a22,0x2a24,0x2a26,0x2c2a,0x5350]:struct.pack_into('<H',data,page*16+at,(at+page+count)&65535)
            for i in range(4):struct.pack_into('<H',data,cs*16+0xaf3c+2*i,(i*0x1111+count)&65535)
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+8]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def service(model,write,q):
                index=len(model)+1;event=[q.kind,q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),values(q.incoming.registers),q.incoming.bp,q.incoming.carry];model.append(event);r=StateRegisters(Registers(*values(q.incoming.registers)),0x8000+index,index&1);rr=r.registers;rr.ax=0xa000+index;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.si=0xe000+index;rr.di=[0,1,17,18,0xffff][count%5];rr.es=0x6000;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if profile==1 and q.site in [0x1faa,0x1f7a,0x1f68]:rr.ds=0x5000
                if profile==2 and q.site==0x1fdf:write(rr.ds*16+0x33d4,b'\x04');write(rr.ds*16+0x33ce,struct.pack('<H',0xffff))
                if profile==3 and q.site==0x1fdc:write(rr.ds*16+0x33d4,b'\0')
                if q.site==0x1faa:
                    for i in range(4):write(cs*16+0xaf3c+2*i,struct.pack('<H',(count+i*0x1234)&65535))
                write(0x80000+2*index,struct.pack('<H',q.site));return r
            active.update(expected=None,pending=None,ss=ss,instructions=0,sites=set(),events=[]);u.emu_start(cs*16+entries[entry],0x11210,count=512)
            while active['pending']:
                q,ret,framebytes=active['pending'];active['pending']=None;require(len(active['events'])<32,'Finite ABIfixture');returned=service(active['events'],lambda at,b:u.mem_write(at,b),q);rr=returned.registers
                for reg,val in list(zip(regs,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+framebytes),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,0x11210,count=512)
            label=f'{load:x}/{entry}/{mode}/{count}/{mask}/{profile}/{same}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original rootRETF '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,m,q,r):
                try:returned=service(events,lambda at,b:C.memmove(C.byref(bus,at),b,len(b)),q.contents);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,32,C.byref(out));require(not errors and out.status==0 and events==active['events'] and out.calls==len(events) and out.current_sp==sp+4 and out.return_bytes==4,'Native near/far/args '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers/restores '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'Rootframeguard '+label);coverage[f'{entries[entry]:04X}']+=1;coverage['near_calls']+=sum(e[0]==0 for e in events);coverage['far_calls']+=sum(e[0]==1 for e in events);coverage['paired10livewords']+=sum(e[5]==10 for e in events);coverage['same_DS_SS_'+str(same)]+=1;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
    require(len(sites)==len(starts),'Everyloopcontrol instructionlocation');record={'schema':1,'result':'pass','function_ids':['FN-EGA-000085','FN-EGA-000086','FN-EGA-000087'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_loop_controls.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete1F60/1F71/1F99 orchestration, nearRET2/farRETF4 leaf ABI frames, CSfieldreads/currentDS/returnedDS andsavedSI-DS-BP, mutablegateprofiles, shiftedrawextent, paired5+5livewords andCFIFDF compared. Allleafbodies ABImocks; no actualgraphics/resources/statewriters/device/IRQ/core/game/fidelity. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
