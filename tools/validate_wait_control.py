"""Compare79C8/7A55/6A6A raw counter/deadline/input effects without IRQ delivery."""
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
    _fields_=[(n,C.c_uint16) for n in ['kind','site','segment','offset']]+[('incoming',StateRegisters)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','deadline_low','deadline_high']]+[('events',C.c_uint32),('returned',StateRegisters)]


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));snapshot=dll.td2ega_counter_snapshot;snapshot.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(StateRegisters),C.POINTER(Result)];snapshot.restype=None;wait=dll.td2ega_wait_control;wait.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_int,C.c_uint32,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];wait.restype=None
    cases=[];bounds=[0,1,0xffff,0x10000,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
    for value,flags in itertools.product(bounds,[2|carry|(enabled<<9)|(direction<<10) for carry,enabled,direction in itertools.product([0,1],repeat=3)]):cases.append(('snapshot','paired_counter_IF_CF',{'base':value,'flags':flags}))
    for base,distance,mode in itertools.product(bounds,bounds,[0,1]):
        for profile in ([0,1] if mode else [0]):cases.append(('wait','absolute_unsigned_deadlines',{'base':base,'distance':distance,'mode':mode,'profile':profile}))
    for base,distance,key,delay,profile in itertools.product(bounds,[0,1,32,0xffff,0xffffffff],[1,0x1b,0x100,0x8400,0xffff],[0,1,2],[0,1]):cases.append(('wait','input_before_or_after_deadline',{'base':base,'distance':distance,'mode':1,'profile':profile,'key':key,'delay':delay}))
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:79C8','06C9:7A55','06C9:6A6A']];require(len(fenced)==3,'Three wait/counter fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;coverage=Counter();sites=set();active={};sp=0xe000;md=Cs(CS_ARCH_X86,CS_MODE_16)
    for load in [0x1000,0x2345]:
        cs,ds,ss=load+0x6c9,load+0x178f,0x9000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base_image=bytearray(0x100000);base_image[load*16:load*16+len(relocated)]=relocated;starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            for call in f['calls']:
                ip=int(call['site'].split(':')[1],16);target=int(call['target'].split(':')[1],16);size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;calls[cs*16+ip]=(0 if target==0x79c8 else 1,ip,target,ip+size)
        def read_registers():
            flags=uc.reg_read(UC_X86_REG_EFLAGS);r=Registers(*[uc.reg_read(reg) for reg in regids],(flags>>9)&1,(flags>>10)&1);return StateRegisters(r,uc.reg_read(UC_X86_REG_BP),flags&1)
        def fetch(u,address,size,_):
            if active.get('expected') and address==cs*16+active['expected'][2]:
                eventkind,site,target,ret=active['expected'];current_sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(ss*16+current_sp,4))==struct.pack('<2H',ret,cs),'Waitfarcallee frame');q=Request(eventkind,site,cs,target,read_registers());active['expected']=None
                if eventkind==0:
                    event,_=service(active['model'],lambda at,b:u.mem_write(at,b),q);active['model']['events'].append(event)
                else:active['pending']=(q,current_sp,ret);u.emu_stop();return
            require(address in starts,'Wait escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for kind,category,c in cases:
            data=bytearray(base_image);initial=c['base'];distance=c.get('distance',0);deadline=(initial+distance)&0xffffffff;mode=c.get('mode',0);struct.pack_into('<I',data,ds*16+0x5e8c,initial);struct.pack_into('<I',data,0x50000+0x5e8c,initial);args=struct.pack('<I',distance) if kind=='wait' else b'';frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-16:ss*16+sp+len(args)+8]=b'\xa5'*16+frame+args+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=c.get('flags',2|((vectors&1)<<9)|(((vectors>>1)&1)<<10)|((vectors>>2)&1));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);entry=0x79c8 if kind=='snapshot' else 0x7a55 if mode==0 else 0x6a6a
            for reg,val in list(zip(regids,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
            def model():return {'events':[],'reads':0,'inputs':0}
            def service(model,write,q):
                r=q.incoming.registers;event=[q.kind,q.site,q.segment,q.offset,*values(r),q.incoming.bp,q.incoming.carry];returned=StateRegisters(Registers(*values(r)),q.incoming.bp,q.incoming.carry)
                if q.kind==0:
                    stream=[initial,initial,initial,deadline];value=stream[min(model['reads'],len(stream)-1)];model['reads']+=1;write(r.ds*16+0x5e8c,struct.pack('<I',value))
                else:
                    index=model['inputs'];model['inputs']+=1;rr=returned.registers;rr.ax=c.get('key',0) if index>=c.get('delay',0) else 0;rr.bx=0xb000+index;rr.cx=0xc000+index;rr.dx=0xd000+index;rr.si=0xe000+index;rr.di=0xf000+index;rr.es=0x6000;rr.ds=0x5000 if c.get('profile') else r.ds;rr.interrupts_enabled=(index>>1)&1;rr.direction=index&1;returned.carry=index&1;write(0x80000+2*index,struct.pack('<H',rr.ax))
                return event,returned
            active.update(expected=None,pending=None,instructions=0,sites=set(),model=model());uc.emu_start(cs*16+entry,0x11210,count=512)
            while active['pending']:
                require(active['model']['inputs']<32,'Finite inputfixture');q,current_sp,ret=active['pending'];active['pending']=None;event,returned=service(active['model'],lambda at,b:uc.mem_write(at,b),q);active['model']['events'].append(event);rr=returned.registers
                for reg,val in list(zip(regids,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current_sp+4),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:uc.reg_write(reg,val)
                uc.emu_start(cs*16+ret,0x11210,count=512)
            label=f'{load:x}/{kind}/{category}/{c}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Originalwait/counterfarreturn '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);native_model=model();errors=[];result=Result()
            def callback(ctx,m,qptr,rptr):
                try:event,returned=service(native_model,lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),qptr.contents);native_model['events'].append(event);C.memmove(rptr,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback)
            if kind=='snapshot':snapshot(gb,len(gb),C.byref(incoming),C.byref(result))
            else:wait(gb,len(gb),load,sp,mode,distance,C.byref(incoming),cb,None,64,C.byref(result))
            require(not errors and result.status==0 and native_model==active['model'],'Nativecounter/input boundaries '+label+str(errors));require(result.events==len(native_model['events']),'Eventcount '+label);actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-16:ss*16+sp]=expected[ss*16+sp-16:ss*16+sp];require(actual==expected,'Full nonstack bus '+label);r=result.returned;rr=r.registers;require([uc.reg_read(reg) for reg in regids]==values(rr)[:8] and uc.reg_read(UC_X86_REG_BP)==r.bp,'Registers/BP '+label);require((uc.reg_read(UC_X86_REG_EFLAGS)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,rr.interrupts_enabled,rr.direction),'CF/IF/DF '+label);require(uc.reg_read(UC_X86_REG_SS)==ss and bytes(uc.mem_read(ss*16+sp,len(args)+8))==frame+args+b'\xa5'*4,'Frame/arguments '+label)
            if kind=='wait':require((result.deadline_low|(result.deadline_high<<16))==deadline and bytes(uc.mem_read(ss*16+sp-6,4))==struct.pack('<I',deadline) and bytes(uc.mem_read(ss*16+sp-2,2))==struct.pack('<H',incoming.bp),'Deadline/locals/savedBP '+label)
            else:require(bytes(uc.mem_read(ss*16+sp-16,16))==b'\xa5'*16,'Snapshotlowerguard '+label)
            coverage[category]+=1;coverage['counter_reads']+=native_model['reads'];coverage['input_calls']+=native_model['inputs'];coverage['deadline_wrap']+=int(kind=='wait' and initial+distance>0xffffffff);instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
    deps=['tools/validate_state_loop.py'];record={'schema':1,'function_ids':['FN-EGA-000167','FN-EGA-000199','FN-EGA-000203'],'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_wait_control.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'limits':'Complete79C8/7A55/6A6A serializedsyntheticbus/counterstream/69FEABI profile. Actual79C8bodyexecutes, CLI/STI IF1 and32bitmoddeadline/absoluteunsignedcompare/wrap retained, inputexit/timeout/DSchange/CFIFDF/frameBP/args compared. Counterevents are data-boundary fixtures, notIRQ delivery orclockrate. No physical086C meaning, actualcallback/IRQ/BIOS/inputsession/resource/core/game/fidelity acceptance. Nativebudget/adapter diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
