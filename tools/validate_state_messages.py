"""Compare eleven state-message/shared-helper bodies and their far interfaces."""
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
from validate_state_loop import Registers,StateRegisters,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['site','segment','offset','argument_count','live_argument_count','stack_segment','stack_sp']]+[('arguments',C.c_uint16*10),('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','return_bytes']]+[('calls',C.c_uint32),('returned',StateRegisters)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_state_message;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    entries=[0x36e0,0x3713,0x371f,0x372b,0x3737,0x3743,0x374f,0x375f,0x3788,0x3f0d,0x5c98];ids=['FN-EGA-'+f'{i:06}' for i in [100,101,102,103,104,105,106,107,108,123,130]];cases=list(itertools.product(range(11),[0,1,2,0x7fff,0x8000,0xffff],[0,1,0xffff],[0,1,0xffff],[0,1],[0,1,3]));cases += [(0,count,0,activity,2,1) for count,activity in itertools.product([0,1,0xffff],[0,1])]
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{ip:04X}' for ip in entries]];require(len(fenced)==11,'Eleven message/helper fences');md=Cs(CS_ARCH_X86,CS_MODE_16);regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;coverage=Counter();sites=set();active={};sp=0xe000
    specs={0x5c9d:(2,2),0x3794:(2,2),0x37ad:(5,5),0x37c6:(5,10),0x36eb:(2,2),0x36f8:(2,4),0x3708:(2,2),0x3775:(3,3),0x3635:(2,2),0x3f0d:(0,0),0x3f1c:(2,2),0x3f2b:(0,0),0x3f37:(2,2)}
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            for call in f['calls']:
                ip=int(call['site'].split(':')[1],16);segment,target=[int(v,16) for v in call['target'].split(':')]
                if segment==0x6c9 and target in [0x3788,0x3f0d,0x5c98]:continue
                size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc,live=specs[ip];calls[cs*16+ip]=(ip,load+segment,target,ip+size,argc,live)
        def read_registers():
            flags=uc.reg_read(UC_X86_REG_EFLAGS);r=Registers(*[uc.reg_read(reg) for reg in regids],(flags>>9)&1,(flags>>10)&1);return StateRegisters(r,uc.reg_read(UC_X86_REG_BP),flags&1)
        def fetch(u,address,size,_):
            if active.get('expected') and address==active['expected'][1]*16+active['expected'][2]:
                site,segment,target,ret,argc,live=active['expected'];current_sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current_sp,4))==struct.pack('<2H',ret,cs),'Messagefarcallee frame');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current_sp+4,live*2))) if live else [];q=Request(site,segment,target,argc,live,active['ss'],current_sp,(C.c_uint16*10)(*(args+[0]*(10-live))),read_registers());active['expected']=None;active['pending']=(q,current_sp,ret);u.emu_stop();return
            require(address in starts,'Message escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for entry,count,gate,activity,profile,drain in cases:
            ss=ds if vectors&1 else 0x9000;data=bytearray(base)
            for page in [ds,0x5000]:
                alternate=page!=ds
                for at,v in [(0x8424,count^(0x8000 if alternate else 0)),(0x9410,gate),(0x8a9a,(0 if activity else 1) if alternate else activity),(0x8658,count),(0x536c,count)]:struct.pack_into('<H',data,page*16+at,v)
            near=entry==8;frame=struct.pack('<H',0x100) if near else struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+len(frame)+4]=b'\xa5'*64+frame+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10)|((vectors>>2)&1);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regids,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            def model():return {'events':[],'inputs':0}
            def service(model,read,write,q):
                index=len(model['events'])+1;r=q.incoming.registers;fields=[struct.unpack('<H',read(r.ds*16+at,2))[0] for at in [0x8424,0x9410,0x8a9a,0x8658,0x536c]];event=[q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),*values(r),q.incoming.bp,q.incoming.carry,fields];returned=StateRegisters(Registers(*values(r)),q.incoming.bp,q.incoming.carry);rr=returned.registers
                rr.ax=0xa000+index;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.si=0xe000+index;rr.di=0xf000+index;rr.es=0x6000;returned.bp=0x8000+index;returned.carry=(index+q.site)&1;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if (profile==1 and q.site==0x3794) or (profile==2 and q.site==0x36eb):rr.ds=0x5000
                if q.offset==0x69fe:
                    rr.ax=0x1b if model['inputs']<drain else 0;model['inputs']+=1
                if q.site==0x3775:write(r.ds*16+0x2f20,b'12\0')
                write(0x80000+2*index,struct.pack('<H',q.site));return event,returned
            active.update(expected=None,pending=None,instructions=0,sites=set(),ss=ss,model=model());end=cs*16+0x100 if near else 0x11210;uc.emu_start(cs*16+entries[entry],end,count=4096)
            while active['pending']:
                require(len(active['model']['events'])<64,'Finite messagefixture');q,current_sp,ret=active['pending'];active['pending']=None;event,returned=service(active['model'],lambda at,n:bytes(uc.mem_read(at,n)),lambda at,b:uc.mem_write(at,b),q);active['model']['events'].append(event);rr=returned.registers
                for reg,val in list(zip(regids,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current_sp+4),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:uc.reg_write(reg,val)
                uc.emu_start(cs*16+ret,end,count=4096)
            label=f'{load:x}/{entry}/{count}/{gate}/{activity}/{profile}/{drain}/{ss:x}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(cs if near else 0x1111,0x100,sp+len(frame)),'Originalnear/farreturn '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);native_model=model();errors=[]
            def callback(ctx,m,qptr,rptr):
                try:event,returned=service(native_model,lambda at,n:bytes(gb[at:at+n]),lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),qptr.contents);native_model['events'].append(event);C.memmove(rptr,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);result=Result();fn(gb,len(gb),load,ss,sp,entry,C.byref(incoming),cb,None,64,C.byref(result));require(not errors and result.status==0 and native_model==active['model'],'Nativefarinterfaces/stackargs '+label+str(errors));require(result.calls==len(native_model['events']) and result.current_sp==uc.reg_read(UC_X86_REG_SP) and result.return_bytes==len(frame),'Virtualstack/calls '+label);actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonstack bus '+label);r=result.returned;rr=r.registers;require([uc.reg_read(reg) for reg in regids]==values(rr)[:8] and uc.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);require((uc.reg_read(UC_X86_REG_EFLAGS)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,rr.interrupts_enabled,rr.direction),'CFIFDF '+label);require(uc.reg_read(UC_X86_REG_SS)==ss and bytes(uc.mem_read(ss*16+sp,len(frame)+4))==frame+b'\xa5'*4,'Rootframe/guard '+label);coverage[f'{entries[entry]:04X}']+=1;coverage['same_DS_SS_'+str(ss==ds)]+=1;coverage['leaf_calls']+=result.calls;instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
    record={'schema':1,'function_ids':ids,'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_state_messages.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'limits':'Elevenentry/sharedcontrol bodies, near3788RET2/otherRETF4, paired10liveargumentwords/20bytecleanup,3wordformatter,CSAF54farptr, counters/optionalbranch/inputloop/activitygate/CFIFDF/returnedsegments andvirtualstack compared. Graphics/text/formatter/wait/input leafbodies arefarABImocks, no actualrendering/textdecode/clock/IRQ/inputsession/resource/core/game/fidelity. Nativeframe/budget/adapterdiagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
