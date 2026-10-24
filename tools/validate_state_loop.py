"""Compare1B2C orchestration, mutable tail and caller-clean far interfaces.

Most callees are ABI mocks. Selected cases execute actual1E59+780E and their
recovered native C; this remains isolated control/caller evidence.
"""
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
from validate_music_tick import Registers,require
from validate_mutable_control import State
from validate_prepare_records import Result as PrepareResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class StateRegisters(C.Structure):
    _fields_=[('registers',Registers),('bp',C.c_uint16),('carry',C.c_uint16)]


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['site','segment','offset','argument_count','live_argument_count']]+[('arguments',C.c_uint16*4),('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[('status',C.c_uint16),('dispatch_target',C.c_uint16),('calls',C.c_uint32),('returned',StateRegisters)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--prepare-library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,prepare_library,output=a.library.resolve(),a.prepare_library.resolve(),a.output.resolve();require(all(p.is_relative_to(ROOT/'analysis') for p in [library,prepare_library]) and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private libraries/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_state_loop;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(State),C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;prepare=C.CDLL(str(prepare_library)).td2ega_prepare_records;prepare.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(Registers),C.c_uint16,C.c_uint32,C.POINTER(PrepareResult)];prepare.restype=None
    cases=[]
    for state,count,post,wait in itertools.product(list(range(1,10))+[0x80,0xff],[0,1,2,0x8000,0xffff],[4,9,2],[0,1]):cases.append(('state_counter_loop_paths',{'state':state,'count':count,'post':post,'wait':wait}))
    for redirect,profile,count in itertools.product([0,1,2,9,0xff],range(4),[1,2]):cases.append(('late_state_and_segment_changes',{'state':2,'count':count,'redirect':redirect,'profile':profile}))
    bounds=[0,1,10,11,0x3b50,0x3b51,0xffff]
    for first,second,limit in itertools.product(bounds,bounds,bounds):cases.append(('unsigned_wrapped_exit_limits',{'state':0xff,'first':first,'second':second,'limit':limit}))
    targets=[0x1bac,0x1c51,0x1c02,0x1c23,0x1c2a,0x1c35,0x1c3c,0x1c43,0x1c4a,0x1c59]
    for target in targets:cases.append(('known_target_permutation',{'state':2,'count':1,'target':target}))
    for state,count,profile in itertools.product([1,2,4,9,0xff],[1,2],range(3)):cases.append(('actual_record_caller_composition',{'state':state,'count':count,'profile':profile,'prepare':True}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());root=next(f for f in graph['functions'] if f['entry']=='06C9:1B2C');prep=[f for f in graph['functions'] if f['entry'] in ['06C9:1E59','06C9:780E']];md=Cs(CS_ARCH_X86,CS_MODE_16);regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];coverage=Counter();vectors=instructions=0;sites=set();active={};sp=0xe000
    for load in [0x1000,0x2345]:
        cs,ds,ss=load+0x6c9,load+0x178f,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);cpus={tail:Uc(UC_ARCH_X86,UC_MODE_16) for tail in [0,1]};starts={cs*16+ip for f in [root]+prep for ip in f['instructions']};calls={}
        for call in root['calls']:
            ip=int(call['site'].split(':')[1],16);target=int(call['target'].split(':')[1],16);size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc=2 if ip in [0x1b4e,0x1c6d,0x1c7a] else 0;live=4 if ip==0x1c7a else argc;calls[cs*16+ip]=(ip,target,ip+size,argc,live)
        def word(group,offset):return struct.unpack('<H',uc.mem_read(group*16+(offset&65535),2))[0]
        def read_registers():
            flags=uc.reg_read(UC_X86_REG_EFLAGS);r=Registers(*[uc.reg_read(reg) for reg in regids],(flags>>9)&1,(flags>>10)&1);return StateRegisters(r,uc.reg_read(UC_X86_REG_BP),flags&1)
        def fetch(u,address,size,_):
            if active.get('expected') and address==cs*16+active['expected'][1]:
                site,target,ret,argc,live=active['expected'];current_sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(ss*16+current_sp,4))==struct.pack('<2H',ret,cs),'Statecallee farframe');args=list(struct.unpack('<'+'H'*live,u.mem_read(ss*16+current_sp+4,live*2))) if live else [];q=Request(site,cs,target,argc,live,(C.c_uint16*4)(*(args+[0]*(4-live))),read_registers());active['expected']=None
                if c.get('prepare') and site==0x1b30:
                    event,_=service(active['model'],lambda at,n:bytes(u.mem_read(at,n)),lambda at,b:u.mem_write(at,b),q,True);active['model']['events'].append(event);active['actual_prepare']+=1
                else:active['pending']=(q,current_sp,ret);u.emu_stop();return
            require(address in starts,'Stateorchestration escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
            if address==cs*16+0x1ba8:active['dispatch_target']=word(u.reg_read(UC_X86_REG_DS),u.reg_read(UC_X86_REG_BX)+0x2302)
            if address==cs*16+0x780e:active['prep_samples']+=1
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        for tail,cpu in cpus.items():cpu.mem_map(0,0x100000);cpu.hook_add(UC_HOOK_CODE,fetch);cpu.hook_add(UC_HOOK_INTR,interrupt)
        for category,c in cases:
            for tail in [0,1]:
                uc=cpus[tail];data=bytearray(base)
                for page in [ds,0x5000]:
                    for at,v in [(0x8424,c.get('count',2)),(0x8658,0xffff),(0x52ca,c.get('first',0x3b50)),(0x52d2,c.get('second',0xffff)),(0x380f,c.get('limit',11)),(0x331e,0xabcd),(0x2282,0x1111 if page==ds else 0xaaaa),(0x2284,0x2222 if page==ds else 0xbbbb),(0x2286,0x3333 if page==ds else 0xcccc),(0x2288,0x4444 if page==ds else 0xdddd)]:struct.pack_into('<H',data,page*16+at,v)
                    data[page*16+0x336b]=0xff;struct.pack_into('<11H',data,page*16+0x2300,0x1bac,*targets)
                    if 'target' in c:struct.pack_into('<H',data,page*16+0x2306,c['target'])
                if c.get('prepare'):
                    struct.pack_into('<H',data,ds*16+0x380d,1000)
                    for table in [0x3813,0x39a3]:
                        for i in range(4):data[ss*16+table+8*i]=1;struct.pack_into('<H',data,ss*16+table+8*i+2,i*17+1)
                struct.pack_into('<H',data,0x86,0xa55a);frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-32:ss*16+sp+8]=b'\xa5'*32+frame+b'\xa5'*4;uc.mem_write(0,bytes(data));uc.mem_write(cs*16+0x1bf7,bytes([0xcb if tail else 0xf8]));flags=2|((vectors&1)<<9)|(((vectors>>1)&1)<<10)|((vectors>>2)&1);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
                for reg,val in list(zip(regids,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x1b2c),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
                def model():return {'events':[],'loop':0,'continued':False,'prepare_samples':0}
                def service(model,read,write,q,actual_prepare=False):
                    model_count=len(model['events'])+1;r=q.incoming.registers;event=[q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,list(q.arguments),*values(r),q.incoming.bp,q.incoming.carry];returned=StateRegisters(Registers(*values(r)),q.incoming.bp,q.incoming.carry);rr=returned.registers
                    if actual_prepare:return event,returned
                    rr.ax=(0xa000+model_count)&65535;rr.bx=(0xb000+model_count)&65535;rr.cx=(0xc000+model_count)&65535;rr.dx=(0xd000+model_count)&65535;rr.si=(0xe000+model_count)&65535;rr.di=(0xf000+model_count)&65535;rr.es=0x6000;returned.bp=(0x8000+model_count*31)&65535;returned.carry=(model_count+q.site)&1;rr.interrupts_enabled=(model_count>>1)&1;rr.direction=(model_count>>2)&1
                    profile=c.get('profile',0)
                    if (profile==1 and q.site==0x1b3a) or (profile==2 and q.site==0x1bd7) or (profile==3 and q.site==0x1c6d):rr.ds=0x5000
                    if q.site==0x1b88:
                        model['loop']+=1;wait=c.get('wait',0);state=0 if model['loop']<=wait else c.get('state',2) if model['loop']==wait+1 else 0xff;write(rr.ds*16+0x5490,bytes([state]))
                    if q.site==0x1b9b and 'redirect' in c:write(rr.ds*16+0x5490,bytes([c['redirect']]))
                    if q.site==0x1c0d:write(rr.ds*16+0x5490,bytes([c.get('post',9)]))
                    write(0x80000+2*model_count,struct.pack('<H',q.site));return event,returned
                active.update(expected=None,pending=None,instructions=0,sites=set(),dispatch_target=0,prep_samples=0,actual_prepare=0,model=model());uc.emu_start(cs*16+0x1b2c,0x11210,count=4096)
                while active['pending']:
                    require(len(active['model']['events'])<512,'Finitecallee fixture');q,current_sp,ret=active['pending'];active['pending']=None;event,returned=service(active['model'],lambda at,n:bytes(uc.mem_read(at,n)),lambda at,b:uc.mem_write(at,b),q);active['model']['events'].append(event);rr=returned.registers
                    for reg,val in list(zip(regids,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current_sp+4),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:uc.reg_write(reg,val)
                    uc.emu_start(cs*16+ret,0x11210,count=4096)
                label=f'{load:x}/{tail}/{category}/{c}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Originalstatefarreturn '+label)
                gb=(C.c_uint8*len(data)).from_buffer_copy(data);gb[cs*16+0x1bf7]=0xcb if tail else 0xf8;native_model=model();errors=[]
                def callback(ctx,m,qptr,rptr):
                    try:
                        q=qptr.contents
                        if c.get('prepare') and q.site==0x1b30:
                            event,_=service(native_model,lambda at,n:bytes(gb[at:at+n]),lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q,True);pr=PrepareResult();prepare(gb,len(gb),ss,C.byref(q.incoming.registers),q.incoming.bp,1000,C.byref(pr));require(pr.status==0,'Actualnativeprepare normalprofile');returned=StateRegisters(pr.registers,pr.bp,0);native_model['prepare_samples']+=pr.samples
                        else:event,returned=service(native_model,lambda at,n:bytes(gb[at:at+n]),lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q)
                        native_model['events'].append(event);C.memmove(rptr,C.byref(returned),C.sizeof(returned));return 1
                    except Exception as e:errors.append(str(e));return 0
                cb=Service(callback);code=State();code.returns_state=tail;result=Result();fn(gb,len(gb),load,C.byref(code),C.byref(incoming),cb,None,512,C.byref(result));require(not errors and result.status==0,'Nativecalls '+label+str(errors));require(native_model['events']==active['model']['events'],'Orderedcall/argument/register/CF interfaces '+label);require(result.calls==len(native_model['events']) and result.dispatch_target==active['dispatch_target'],'Call/dispatchcounts '+label)
                actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Full nonstack bus '+label);r=result.returned;rr=r.registers;require([uc.reg_read(reg) for reg in regids]==values(rr)[:8] and uc.reg_read(UC_X86_REG_BP)==r.bp,'Registers/restore '+label);require((uc.reg_read(UC_X86_REG_EFLAGS)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,rr.interrupts_enabled,rr.direction),'CF/IF/DF '+label);require(uc.reg_read(UC_X86_REG_SS)==ss and bytes(uc.mem_read(ss*16+sp-6,6))==struct.pack('<3H',incoming.registers.si,incoming.registers.ds,incoming.bp) and bytes(uc.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'SavedSI/DS/BP/frame '+label)
                if c.get('prepare'):require(active['actual_prepare']==1 and active['prep_samples']==native_model['prepare_samples']==2,'Actualrecordcaller consumption '+label)
                coverage[category]+=1;coverage['returns_state_'+str(tail)]+=1;instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
    deps=['tools/validate_prepare_records.py','tools/validate_music_tick.py','tools/validate_mutable_control.py'];record={'schema':1,'function_id':'FN-EGA-000080','result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_state_loop.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'native_libraries':[{'path':prepare_library.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(prepare_library.read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'limits':'Complete1B2C orchestration inknown-target/nonwrappingfarABI profile, mutableCLC/RETFtail/physical0086, wait/state/counter/reset/unsignedlimits andCF/IF/DF/register restores. Mostcallees areABImocks;120cases executeactual1E59+780E andnativeprepare C with2samples each. No fullcallee/statewriter/domain/resource/IRQ/core/game/fidelity acceptance. Late-state/segment/tablepermutation areconditional syntheticprofiles. Nativeunknown-target/budget/adapterdiagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
