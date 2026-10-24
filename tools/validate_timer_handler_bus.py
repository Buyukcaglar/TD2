"""FullSS61BF/6230 original instructions with explicit retired service profiles."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_input_poll_bus import Registers,StateRegisters,require,values
from validate_music_tick import Port,Port as PortService
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['kind','segment','offset','ss','current_sp','flags_word','flags_mask','reserved']]+[('registers',StateRegisters)]
class Response(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip','flags_word','flags_mask']]+[('bus_writes',C.c_uint32),('returned',StateRegisters)]
Call=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Request),C.POINTER(Response))
class Services(C.Structure):
    _fields_=[('port',PortService),('call',Call),('context',C.c_void_p),('undefined_af',C.c_uint16)]
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['steps','calls','ports']]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','ports','callbacks','old_interrupts','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','stage','reserved']]+[('returned',StateRegisters)]
def clone(v):return type(v).from_buffer_copy(bytes(v))
def physical(s,o):return ((s<<4)+(o&65535))&0xfffff
def rw(memory,s,o):
    p=physical(s,o);return memory[p]|(memory[(p+1)&0xfffff]<<8)
def ww(memory,s,o,v):
    p=physical(s,o);memory[p]=v&255;memory[(p+1)&0xfffff]=(v>>8)&255

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve()
    require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
    require(C.sizeof(Request)==C.sizeof(Response)==40 and C.sizeof(Result)==64 and C.sizeof(Limits)==12,'Layouts')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in graph['functions'] if f['entry'] in ['06C9:61BF','06C9:6230'] for ip in f['instructions']};require(len(fence)==71,'71source sites')
    md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    fn=C.CDLL(str(lib)).td2ega_timer_handler_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=0,countdown=1,enabled=1,delay=2,guard=0,callbacks=2,index=0,low=65535,same=False,ss=None,sp=0xe000,flags=2,irqflags=0x643,af=0,callback_flags=0x247,change=0,mutate=0,cycle=0,raw=0,root_patch=0,limits=(12,12,8),tag='base');c.update(kw);return c
    boundary=[0,1,2,3,0x7fff,0x8000,0x8001,0xfffe,0xffff]
    cases=[case(countdown=d,enabled=e,delay=v,guard=g,callbacks=k,tag='counters') for d,e,v,g,k in itertools.product(boundary,[0,1],boundary,[0,1],[0,1,2,5,6])]
    cases += [case(entry=1,delay=d,enabled=e,change=k,af=af,tag='bridge') for d,e,k,af in itertools.product(boundary,[0,1,255],[0,1],[0,1])]
    cases += [case(index=i,low=v,tag='indexed') for i,v in itertools.product([0,1,2,3,0x60,0x76,0x7fff,0x8000,0xa161,0xfffc,0xffff],boundary)]
    cases += [case(change=ch,mutate=mu,cycle=cy,raw=ra,af=af,callback_flags=f,tag='service') for ch,mu,cy,ra,af,f in itertools.product([0,1],[0,1],[0,1],range(3),[0,1],[2,0x247,0x643,0xed7])]
    cases += [case(same=same,sp=sp,af=af,flags=f,tag='SS_alias') for same,sp,af,f in itertools.product([False,True],[68,0xe000,0xffe0,0x5e9c,0x5ea0,0x5eac,0x5f18,0x5f28],[0,1],[2,0x643])]
    cases += [case(entry=1,ss=0,sp=sp,af=af,tag='IVT_frame_alias') for sp,af in itertools.product([6,0x22,0x24,0x26,0x28,0xfffa],[0,1])]
    cases += [case(limits=(st,ca,po),tag='budget') for st,ca,po in itertools.product(range(5),range(5),range(4))]
    cases += [case(irqflags=f,guard=g,callbacks=0,tag='IRET_qualification') for f,g in itertools.product([0,0x100,0x1000,0x4000,0xffff],[0,1])]
    cases += [case(root_patch=patch,same=same,af=af,callback_flags=f,tag='root_saved_frame_mutation') for patch,same,af,f in itertools.product([1,2],[False,True],[0,1],[2,0x247,0x643,0xed7])]
    vectors=instructions=synthetic=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[0x70000:0x70002]=b'\xcb\xcf'
        u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def registers():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def flags():
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535
            return (f if active['af_valid'] else (f&~16)|(active['case']['af']<<4)),0xffff if active['af_valid'] else 0xffef
        def stop(status,ip):active['prefix']=status;active['stop']=True;u.emu_stop()
        def budget(name,cap,ip):
            active['stage']=ip
            if active[name]==cap:stop(3,ip);return False
            active[name]+=1;return True
        def fetch(cpu,address,size,_):
            if active.get('synthetic'):
                active['synthetic_count']+=1;return
            if active.get('expected')==address:
                active['expected']=None;active['external']=0;u.emu_stop();return
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Handlerfence')
            if active.get('stepping_return'):
                active['instructions']+=1;active['sites'].add(ip);return
            if ip in [0x61bf,0x6230,0x620e] and not budget('steps',active['caps'].steps,ip):return
            if ip in [0x61f0,0x6217,0x6259] and not budget('calls',active['caps'].calls,ip):return
            if ip in [0x61cb,0x6220,0x6224] and not budget('ports',active['caps'].ports,ip):return
            if ip in [0x622f,0x6268]:active['ret_site']=ip;u.emu_stop();return
            active['instructions']+=1;active['sites'].add(ip)
            if decoded[ip].mnemonic in ['xor','or','and']:active['af_valid']=False
            elif decoded[ip].mnemonic in ['cmp','add','inc','dec']:active['af_valid']=True
            if ip==0x6217:
                group=u.reg_read(UC_X86_REG_DS);di=u.reg_read(UC_X86_REG_DI)
                active['target']=(rw(backing,group,di+0x5f14),rw(backing,group,di+0x5f12));active['expected']=((active['target'][0]<<4)+active['target'][1]);active['callbacks']+=1
        def memory_write(cpu,access,address,size,value,_):active['writes']+=1
        def interrupt(cpu,number,_):
            require(number==8 and u.reg_read(UC_X86_REG_IP)==0x625b,'INT08site');sp=u.reg_read(UC_X86_REG_SP);f,_=flags()
            for off,v in [(sp-2,f),(sp-4,cs),(sp-6,0x625b)]:ww(backing,active['ss'],off,v)
            active['writes']+=3;active['INT_writes']+=3;u.reg_write(UC_X86_REG_SP,(sp-6)&65535);u.reg_write(UC_X86_REG_EFLAGS,f&~0x300)
            # Explicit real-address profile: vector loads follow frame writes.
            active['target']=(rw(backing,0,0x22),rw(backing,0,0x20));active['external']=1;active['old_interrupts']+=1;u.emu_stop()
        def port_effect(events,operation,number,value,enabled):
            events.append(['port',operation,number,value,enabled]);return 0xa7
        def port_in(cpu,number,width,_):
            require(width==1 and number==0x61,'INprofile');return port_effect(active['events'],0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(cpu,number,width,value,_):
            require(width==1 and number in [0x20,0x61],'OUTprofile');port_effect(active['events'],1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,memory_write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for c in cases:
            ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];data=bytearray(base)
            for at,v in [(0x5e88,0x1234),(0x5e8a,0x5678),(0x5e8c,c['low']),(0x5e8e,0x7fff),(0x5e90,c['low']),(0x5e92,0x8000),(0x5e96,c['delay']),(0x5e98,0xa55a),(0x5e9a,c['countdown']),(0x5e9c,c['index']),(0x5e9e,65535)]:ww(data,ds,at,v)
            data[physical(ds,0x5e94)]=1;data[physical(ds,0x5e95)]=c['enabled'];data[physical(ds,0x5efe)]=c['guard']
            for i in range(8):ww(data,ds,0x5f12+4*i,0x100+16*i);ww(data,ds,0x5f14+4*i,0x7000 if i<c['callbacks'] else 0)
            ww(data,ss,sp,0x1111)
            if c['entry']==0:ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,c['irqflags'])
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds if c['entry'] else 0x5000,0x8000,(c['flags']>>9)&1,(c['flags']>>10)&1),0x5678,c['flags']&1);caps=Limits(*c['limits'])
            u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6230 if c['entry'] else 0x61bf),(UC_X86_REG_EFLAGS,c['flags'])]:u.reg_write(reg,value)
            active.clear();active.update(case=c,caps=caps,ss=ss,events=[],instructions=0,sites=set(),writes=0,INT_writes=0,steps=0,calls=0,ports=0,callbacks=0,old_interrupts=0,stage=0,af_valid=True,stop=False,prefix=0,external=None,ret_site=None,synthetic_count=0,root=False,raw=False)
            def effect(memory,events,q):
                events.append(['call',q.kind,q.segment,q.offset,q.ss,q.current_sp,q.flags_word,q.flags_mask,*values(q.registers.registers),q.registers.bp,q.registers.carry]);r=clone(q.registers);writes=0
                count=sum(v[0]=='call' for v in events);r.registers.ax=0xa000+q.kind;r.registers.bx=0xb000+count;r.registers.cx=0xc000+count;r.registers.dx=0xd000+count;r.registers.si=0xe000+count;r.bp=0xabcd
                if c['change']:r.registers.ds=0x5000;r.registers.es=0x6000
                if not q.kind and c['cycle']:r.registers.di=(r.registers.di-4)&65535
                if not q.kind and c['root_patch']:
                    for i in range(9):ww(memory,ss,sp-2*(i+1),0x5100+17*i);writes+=1
                    for off,value in [(sp,0x3333),(sp+2,0x4444),(sp+4,0x643 if c['root_patch']==1 else 0x100)]:ww(memory,ss,off,value);writes+=1
                if c['mutate']:ww(memory,ds,0x5f18,0);writes+=1
                if c['raw']==1:ww(memory,ss,q.current_sp,0x4321);writes+=1
                if c['raw']==2:ww(memory,ss,(q.current_sp+2)&65535,0x4567);writes+=1
                f=c['callback_flags']
                if q.kind:f=rw(memory,ss,q.current_sp+4)
                r.carry=f&1;r.registers.interrupts_enabled=(f>>9)&1;r.registers.direction=(f>>10)&1
                return r,f,writes
            while not active['stop']:
                u.emu_start((u.reg_read(UC_X86_REG_CS)<<4)+u.reg_read(UC_X86_REG_IP),0,count=20000)
                if active['external'] is not None:
                    kind=active['external'];active['external']=None;seg,off=active['target'];f,mask=flags();q=Request(kind,seg,off,ss,u.reg_read(UC_X86_REG_SP),f,mask,0,registers());r,f,writes=effect(backing,active['events'],q);active['writes']+=writes
                    for reg,value in list(zip(REGS,values(r.registers)[:8]))+[(UC_X86_REG_BP,r.bp),(UC_X86_REG_EFLAGS,f),(UC_X86_REG_CS,0x7000),(UC_X86_REG_IP,kind)]:u.reg_write(reg,value)
                    active['synthetic']=True;u.emu_start(0x70000+kind,0,count=1);active['synthetic']=False;active['af_valid']=True
                    resume=0x625b if kind else 0x621b
                    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))!=(cs,resume):active['raw']=True;active['stop']=True
                    continue
                if active['ret_site'] is not None:
                    ip=active['ret_site'];active['ret_site']=None;cur=u.reg_read(UC_X86_REG_SP)
                    if ip==0x622f:
                        f=rw(backing,ss,cur+4)
                        if f&~0x0ed7 or not f&2:stop(5,ip);active['stage']=ip;continue
                    active['stepping_return']=True;u.emu_start((cs<<4)+ip,0,count=1);active['stepping_return']=False
                    if ip==0x622f or c['entry']==1:active['root']=True;active['stop']=True
                    elif (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP))!=(cs,0x61f3):active['raw']=True;active['stop']=True
                    if ip==0x622f:active['af_valid']=True
                    continue
                require(active['stop'],'Original instruction count exhausted')
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def native_port(ctx,qptr,value):
                try:q=qptr.contents;value.contents.value=port_effect(events,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as error:errors.append(str(error));return 0
            def native_call(ctx,memory,count,qptr,rptr):
                try:
                    q=qptr.contents;r,f,writes=effect(bus,events,q);response=rptr.contents;response.returned=r;response.flags_word=f;response.flags_mask=65535;response.bus_writes=writes;response.next_ip=rw(bus,ss,q.current_sp);response.next_segment=rw(bus,ss,q.current_sp+2);response.current_sp=(q.current_sp+(6 if q.kind else 4))&65535;return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);call=Call(native_call);services=Services(port,call,None,c['af']);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],c['flags'],65535,C.byref(incoming),C.byref(caps),C.byref(services),C.byref(r));label=f'{load:x}/{c}'
            require(not errors,'Nativeservices '+label+str(errors));require(events==active['events'],'Ordered services '+label+str((events,active['events'])))
            status=0 if active['root'] else 1 if active['raw'] else active['prefix'];expected=(status,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['calls'],active['ports'],active['callbacks'],active['old_interrupts'],active['writes'],active['stage'])
            observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.calls,r.ports,r.callbacks,r.old_interrupts,r.bus_writes,r.stage)
            require(observed==expected,'Handlercontrol/counts '+label+str((observed,expected)))
            require(bytes(bus)==bytes(backing),'Whole1MiBRAM/actualSS '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'WholeGPR-BP '+label)
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(f&1,(f>>9)&1,(f>>10)&1),'CFIFDF '+label);require((r.flags_word&r.flags_mask)==(f&r.flags_mask),'DefinedFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(f))))
            vectors+=1;instructions+=active['instructions'];synthetic+=active['synthetic_count'];sites.update(active['sites']);coverage['root_'+str(c['entry'])]+=1;coverage['status_'+str(status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['modeled_INT_frame_writes']+=active['INT_writes'];coverage['CPU_and_service_writes']+=r.bus_writes;coverage['far_callbacks']+=r.callbacks;coverage['old_INT08']+=r.old_interrupts;coverage['SS_equals_DS']+=int(ss==ds)
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%1024==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==fence,'Handler71site coverage '+str(sorted(fence-sites)))
    deps=['tools/validate_input_poll_bus.py','tools/validate_music_tick.py','tools/validation/twenty_bit_bus.py','analysis/history/timer-handler-bus-build-setup-v3.json','docs/recovery/evidence/intel-int-real-mode-reference-v1.json','analysis/history/timer-handler-bus-validation-refinement-v2.json','analysis/history/timer-handler-bus-validation-refinement-v3.json','analysis/history/validate_timer_handler_bus_attempt_v2.py','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000360','FN-EGA-000361'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_handler_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':71,'instruction_sites_exercised':len(sites),'synthetic_return_operations':synthetic,'fixture_coverage':dict(coverage),'limits':'FullSS61BF/6230 original71sites/fullRAM-GPR-BP-CFIFDF/definedFLAGS/actualsavedwords/farframes/modeledINT08-IRET-explicitAFstorage/IVTalias-order/rawreturns. External oldIRQ/farcallbacks remain ABI profiles with generic RETF/IRET, not actual body proof. Named real-address ISA profile/historicalCPU-IRQdelivery/callback403Bcomposition/allwriters-lifetime-core/P1-GATE remain open. Physical086Cunassigned/CGAbehindEGAclosure/noDOSgame-session-renderer-audio-complete-state-machine-gameplay-fidelity.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
