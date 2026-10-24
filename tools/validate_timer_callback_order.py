"""Actual registration producer and61BF->6269->403B early/paused body composition."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,Request,Response,PortService,Call,Services,Limits,Result,ww,rw,require,values
from validation.validate_state_tick_bus_diagnostics import SimLimits,Limits as TickLimits,Result as TickResult
from validate_input_poll_bus import Limits as InputLimits,Services as InputServices
from validate_mutable_control import State
from validate_effect_tick_bus import Result as EffectResult
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def clone(v):return type(v).from_buffer_copy(bytes(v))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();out=a.output.resolve();require(out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshmetadataoutput')
    hp='analysis/build/timer-handler-bus-repro-v3/td2ega_timer_handler_bus.dll';tp='analysis/build/state-tick-bus-repro/td2ega_state_tick_bus.dll';ep='analysis/build/effect-tick-bus-repro-v2/td2ega_effect_tick_bus.dll'
    handler=C.CDLL(str((ROOT/hp).resolve())).td2ega_timer_handler_bus;handler.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];handler.restype=None
    tick=C.CDLL(str((ROOT/tp).resolve())).td2ega_state_tick_bus;tick.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(State),C.POINTER(TickLimits),C.POINTER(InputServices),C.POINTER(TickResult)];tick.restype=None
    effect=C.CDLL(str((ROOT/ep).resolve())).td2ega_effect_tick_bus;effect.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),PortService,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(EffectResult)];effect.restype=None
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());by={f['entry']:f for f in g['functions']};names={'06C9:61BF','06C9:403B','06C9:412C','06C9:420A','06C9:5A6F','06C9:69B7','06C9:6269'};todo=list(names)
    while todo:
        name=todo.pop()
        for call in by[name]['calls']:
            if call['target'] not in names:names.add(call['target']);todo.append(call['target'])
    fence={(int(f['entry'][:4],16),ip) for name in names for f in [by[name]] for ip in f['instructions']}
    cases=[dict(counter=v,paused=1,activity=0,secondary=2,active=0,word=0,tag='all_counter_bytes') for v in range(256)]
    cases += [dict(counter=1,paused=paused,activity=activity,secondary=secondary,active=active,word=word,tag='paused_controls') for paused,activity,secondary,active,word in itertools.product([1,2,4],[0,1,2],[1,2],[0,1],[0,0x7fff,0x8000,0xffff])]
    audio=[dict(mode=0),dict(mode=1,remaining=2,threshold=1),dict(mode=1,remaining=1,threshold=9),dict(mode=1,remaining=2,threshold=2),dict(note=0),dict(note=65),dict(note=65,shift=0),dict(note=65,shift=31),dict(absent=1),dict(absent=1,queued=1),dict(note=0xff,queued=1)]
    audio += [dict(note=note,loop_count=count,count=count) for note,count in itertools.product(range(0xf5,0x100),[0,0x7fff,0x8000,0xffff])]
    for profile in audio:cases.append(dict(counter=1,paused=1,activity=0,secondary=2,active=1,word=0,tag='ordered_audio_body',effect=profile))
    vectors=instructions=producer_instructions=productions=0;sites=set();producer_sites=set();coverage=Counter()
    for load,same,sp,df in itertools.product([0x1000,0x2345],[False,True],[68,0xa3ce,0xe000,0xffe0],[0,1]):
        cs,ds=load+0x6c9,load+0x178f;ss=ds if same else 0x9000;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        producer=Uc(UC_ARCH_X86,UC_MODE_16);producer_backing=map_twenty_bit_ram(producer);producer.mem_write(0,bytes(base));prod={'halt':False,'stepping':False,'instructions':0,'sites':set()}
        producer_fence={ip for name in ['06C9:601C','06C9:614C'] for ip in by[name]['instructions']}|{0x3fd9,0x3fde,0x3fe1,0x3fe2,0x3fe3,0x3fe8,0x3feb,0x3fee,0x3fef,0x3ff0,0x3ff5,0x3ff8}
        def producer_fetch(cpu,address,size,_):
            ip=producer.reg_read(UC_X86_REG_IP);require(producer.reg_read(UC_X86_REG_CS)==cs and ip in producer_fence,'Registrationproducerfence')
            if ip==0x3ff8 and not prod['stepping']:prod['halt']=True;producer.emu_stop();return
            prod['instructions']+=1;prod['sites'].add(ip)
        def producer_in(cpu,number,width,_):require(width==1 and number in [0x21,0x61],'ProducerIN');return 0xa5 if number==0x21 else 0xa7
        def producer_out(cpu,number,width,value,_):require(width==1 and number in [0x21,0x61,0x43,0x40],'ProducerOUT')
        producer.hook_add(UC_HOOK_CODE,producer_fetch);producer.hook_add(UC_HOOK_INSN,producer_in,None,1,0,UC_X86_INS_IN);producer.hook_add(UC_HOOK_INSN,producer_out,None,1,0,UC_X86_INS_OUT)
        ww(producer_backing,0,0x20,0x1234);ww(producer_backing,0,0x22,0x5678);ww(producer_backing,ss,sp,0x1111);ww(producer_backing,ss,sp+2,0x2222)
        for reg,value in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x3fd9),(UC_X86_REG_DS,ds),(UC_X86_REG_ES,0x8000),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x5678),(UC_X86_REG_EFLAGS,2|0x200|(df<<10))]:producer.reg_write(reg,value)
        producer.emu_start(cs*16+0x3fd9,0,count=10000);require(prod['halt'],'Producerboundedreturn');prod['stepping']=True;producer.emu_start(cs*16+0x3ff8,0,count=1)
        require((producer.reg_read(UC_X86_REG_CS),producer.reg_read(UC_X86_REG_IP),producer.reg_read(UC_X86_REG_SP))==(0x2222,0x1111,sp+4),'ActualproducertailfarRET')
        require([rw(producer_backing,ds,off) for off in [0x5f12,0x5f14,0x5f16,0x5f18,0x5f1c]]==[0x6269,cs,0x403b,cs,0],'Actual6269-403Bpublicationorder')
        base=bytearray(producer_backing);productions+=1;producer_instructions+=prod['instructions'];producer_sites.update(prod['sites']);active={}

        def state():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);seg=(u.reg_read(UC_X86_REG_CS)-load)&65535;site=(seg,ip);require(site in fence,'Callerprefixfence '+str(site))
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(site);return
            if site==(0x6c9,0x6269):
                active['order'].append(0x6269);active['body']='effect';active['effect_entry']=state();active['effect_entry_flags']=u.reg_read(UC_X86_REG_EFLAGS)&65535;active['effect_write_start']=active['writes']
            if site==(0x6c9,0x403b):
                require(not active['entered'],'Exactlyone403Bcallback');active['entered']=True;active['order'].append(0x403b);active['body']='tick';active['entry_state']=state();active['entry_sp']=u.reg_read(UC_X86_REG_SP);active['entry_flags']=u.reg_read(UC_X86_REG_EFLAGS)&65535;active['body_writes_start']=active['writes']
            if site in [(0x6c9,v) for v in [0x6287,0x62a2,0x62fc,0x6323,0x412b,0x622f]]:active['return_site']=site;u.emu_stop();return
            if site==(0x6c9,0x621b):
                if active['body']=='effect':active['effect_retired']=state();active['effect_retired_sp']=u.reg_read(UC_X86_REG_SP);active['effect_writes']=active['writes']-active['effect_write_start']
                else:active['retired_state']=state();active['retired_sp']=u.reg_read(UC_X86_REG_SP);active['body_writes']=active['writes']-active['body_writes_start']
            active['instructions']+=1;active['sites'].add(site)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        def port_out(cpu,number,width,value,_):
            require(number in [0x20,0x61,0x42] and width==1,'Handler-effectOUTprofile');active['ports'].append((1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1))
        def port_in(cpu,number,width,_):
            require(number==0x61 and width==1,'EffectINprofile');active['ports'].append((0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1));return 0xa7
        def interrupt(cpu,number,_):
            require(number==0x16 and u.reg_read(UC_X86_REG_IP)==0x6605,'Paused6601actualINT16only')
            current=u.reg_read(UC_X86_REG_SP);f=u.reg_read(UC_X86_REG_EFLAGS)&65535
            # The preceding420A CMP defines AF before MOVAH1/INT; no unknown AF storage.
            for off,value in [(current-2,f),(current-4,cs),(current-6,0x6605)]:ww(backing,ss,off,value)
            active['writes']+=3;active['modeled_INT_writes']+=3;u.reg_write(UC_X86_REG_SP,(current-6)&65535);u.reg_write(UC_X86_REG_CS,cs);u.reg_write(UC_X86_REG_IP,0x69b7);u.reg_write(UC_X86_REG_EFLAGS,f&~0x300)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN)
        for c in cases:
            data=bytearray(base)
            # Synthetic raw state only. No resource codec or historical-state claim.
            for begin,end in [(0x3300,0x3400),(0x52c0,0x5400)]:data[(ds<<4)+begin:(ds<<4)+end]=bytes(end-begin)
            data[(ds<<4)+0x3368]=c['counter'];data[(ds<<4)+0x3369]=c['secondary'];data[(ds<<4)+0x33d4]=c['paused'];data[(ds<<4)+0x336b]=c['active'];data[(ds<<4)+0x5490]=c['activity']
            for at,v in [(0x33ce,c['word']),(0x33d0,c['word']),(0x33d2,2),(0x942e,0),(0x5e9a,2),(0x5e9c,0),(0x5e8c,0xffff),(0x5e8e,0x7fff),(0x62b6,0)]:ww(data,ds,at,v)
            profile=c.get('effect',dict(mode=0));note=profile.get('note',65);segment=0x6000;event=0x1000
            for at,value in [(0x5eee,0 if profile.get('absent') else segment),(0x5ef0,event),(0x5ef2,0x7000),(0x5ef4,0x2000),(0x5ef6,profile.get('remaining',0)),(0x5ef8,profile.get('threshold',0)),(0x5f00,profile.get('loop_count',0)),(0x5f02,profile.get('loop_count',0)),(0x5f04,profile.get('loop_count',0)),(0x5f06,0x2000),(0x5f08,0x2000),(0x5f0a,0x2000),(0x5f0c,0x2000),(0x5f0e,0x2000),(0x5f10,0x2000)]:ww(data,ds,at,value)
            for i in range(128):ww(data,ds,0x5f2e+2*i,317*i+11)
            for at,value in [(0x5efb,profile.get('mode',1)),(0x5efc,1),(0x5efd,profile.get('queued',0)),(0x5efa,profile.get('shift',1))]:data[(ds<<4)+at]=value
            if 0xfb<=note<=0xfd:stream=bytes([note])+struct.pack('<H',profile.get('count',0))+bytes([65,2,0])
            elif note==0xfe:stream=bytes([note,profile.get('shift',5),65,2,0])
            elif 0xf5<=note<=0xfa:stream=bytes([note,65,2,0])
            else:stream=bytes([note])+struct.pack('<H',profile.get('duration',2))
            data[(segment<<4)+event:(segment<<4)+event+len(stream)]=stream
            for source_segment in [segment,0x7000]:data[(source_segment<<4)+0x2000:(source_segment<<4)+0x2003]=bytes([65,2,0])
            require([rw(data,ds,off) for off in [0x5f12,0x5f14,0x5f16,0x5f18,0x5f1c]]==[0x6269,cs,0x403b,cs,0],'Fixturepreservesactualpublishedrows')
            data[(ds<<4)+0x5e95]=0;data[(ds<<4)+0x5efe]=0;ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,0x643)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x5000,0x8000,0,df),0x5678,0);ef=2|(df<<10);u.mem_write(0,bytes(data))
            for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x61bf),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,v)
            active.clear();active.update(instructions=0,sites=set(),writes=0,modeled_INT_writes=0,ports=[],entered=False,order=[],body=None,return_site=None)
            root=False
            for _ in range(4):
                u.emu_start((u.reg_read(UC_X86_REG_CS)<<4)+u.reg_read(UC_X86_REG_IP),0,count=5000)
                site=active['return_site'];require(site is not None,'Callerprefixinstructionbudget');active['return_site']=None;active['stepping']=True;u.emu_start((load+site[0])*16+site[1],0,count=1);active['stepping']=False
                if site[1]==0x622f:root=True;break
                require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x621b,sp-18),'Actual403Bfarretiredcallerframe')
            require(root and active['entered'] and active['order']==[0x6269,0x403b],'Actualpublishedorder-and-IRET');bus=(C.c_uint8*len(data)).from_buffer_copy(data);ports=[];errors=[];child_results=[]
            def native_port(ctx,qptr,value):
                q=qptr.contents;ports.append((q.operation,q.port,q.value,q.interrupts_enabled));value.contents.value=0xa7;return 1
            def native_call(ctx,memory,count,qptr,rptr):
                try:
                    q=qptr.contents
                    if q.offset==0x6269:
                        require((q.kind,q.segment,q.current_sp)==(0,cs,sp-22) and bytes(q.registers)==bytes(active['effect_entry']),'Actual6269entry')
                        require((q.flags_word&0xffef)==(active['effect_entry_flags']&0xffef),'EffectcallerORdefinedFLAGS')
                        child=EffectResult();effect(memory,count,load,ss,q.current_sp,q.flags_word,q.flags_mask,C.byref(q.registers),port,None,128,8,C.byref(child));require(child.status==0 and bytes(child.returned)==bytes(active['effect_retired']) and child.current_sp==active['effect_retired_sp'] and child.bus_writes==active['effect_writes'],'Actual6269retiredstate-and-writes')
                        response=rptr.contents;response.current_sp=child.current_sp;response.next_segment=child.next_segment;response.next_ip=child.next_ip;response.bus_writes=child.bus_writes;response.returned=child.returned;response.flags_word=child.flags_word;response.flags_mask=child.flags_mask;child_results.append(('effect',bytes(child)));return 1
                    require((q.kind,q.segment,q.offset,q.current_sp)==(0,cs,0x403b,sp-22),'Nativeactual403Bcall');require(bytes(q.registers)==bytes(active['entry_state']),'ActualentryGPR-BP-CFIFDF');require((q.flags_word&0xffef)==(active['entry_flags']&0xffef),'DefinedcallerORflags')
                    caps=TickLimits(11,8,4,32,128,8,16,128,128,128,3,SimLimits(8,16,1800,32,16,64,32,16),InputLimits(16,2,1,5000));code=State();code.branch_42ad=1;services=InputServices();child=TickResult()
                    tick(memory,count,load,ss,q.current_sp,C.byref(q.registers),C.byref(code),C.byref(caps),C.byref(services),C.byref(child));require(child.status==0,'Onlyretirednormal403Bpathsadmitted');require(bytes(child.returned)==bytes(active['retired_state']) and child.current_sp==active['retired_sp'] and child.bus_writes==active['body_writes'],'Actualretired403Bstate-and-writes')
                    response=rptr.contents;response.current_sp=child.current_sp;response.next_segment=child.next_segment;response.next_ip=child.next_ip;response.bus_writes=child.bus_writes;response.returned=child.returned
                    # Unexposed child arithmetic bits are dead at immediate ADDDI4.
                    response.flags_word=(q.flags_word&~0x601)|child.returned.carry|(child.returned.registers.interrupts_enabled<<9)|(child.returned.registers.direction<<10);response.flags_mask=0xffef;child_results.append(('tick',bytes(child)));return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);call=Call(native_call);services=Services(port,call,None,0);caps=Limits(4,2,2);r=Result();handler(bus,len(bus),load,ss,sp,0,ef,65535,C.byref(incoming),C.byref(caps),C.byref(services),C.byref(r));label=str((load,same,sp,df,c))
            require(not errors and [v[0] for v in child_results]==['effect','tick'],'ActualCcallback '+label+str(errors));require(r.callbacks==2 and r.status==0 and (r.current_sp,r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'HandlerIRET '+label);require(bytes(bus)==bytes(backing),'Wholecaller-callee1MiBRAM '+label);require(r.bus_writes==active['writes'],'Allcaller-calleewrites '+label);require(ports==active['ports'],'EOIprofile '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'ActualsavedwordsGPR-BP '+label);require(r.flags_word==(u.reg_read(UC_X86_REG_EFLAGS)&65535),'ActualrootIRETFLAGS '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['tag_'+c['tag']]+=1;coverage['actual403B_callbacks']+=1;coverage['actual6269_callbacks']+=1;coverage['modeled_INT16_frame_writes']+=active['modeled_INT_writes'];coverage['SS_equals_principalDS']+=int(same);coverage['source_DF_'+str(df)]+=1;coverage['source_SP_'+hex(sp)]+=1
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites)}),flush=True)
    require({(0x6c9,ip) for ip in by['06C9:6269']['instructions']}.issubset(sites),'All140actual6269caller-sites')
    deps=['tools/validate_effect_tick_bus.py','docs/recovery/evidence/td2ega-effect-tick-bus-validation-v2.json','docs/recovery/evidence/td2ega-timer-callback-lifetime-v1.json','analysis/history/timer-callback-order-preparation-v1.json','analysis/history/timer-callback-order-refinement-v2.json','analysis/history/validate_timer_callback_order_attempt_v1.py','tools/validate_timer_state_tick_prefix.py','docs/recovery/evidence/td2ega-timer-state-tick-prefix-v2.json','tools/validate_timer_handler_bus.py','tools/validate_input_poll_bus.py','tools/validation/validate_state_tick_bus_diagnostics.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-state-tick-bus-validation-v5.json','docs/recovery/evidence/td2ega-timer-handler-bus-validation-v3.json','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json','analysis/history/timer-state-tick-prefix-refinement-v2.json','analysis/history/validate_timer_state_tick_prefix_attempt_v1.py']
    record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':sha,'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_libraries':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in [hp,tp,ep]],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'source_registration_productions':productions,'source_registration_instructions':producer_instructions,'source_registration_sites_exercised':len(producer_sites),'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual original3FD9 registration slice produces6269-then403B rows andsentinel; its instructions/counts recordedseparately andnotnative-startup acceptance. Common resulting raw inputstate feeds original61BF->actual6269->actual403B-412C-paused420A-69B7-5A6F->actualfarRETs->actualIRET andnativeC counterparts. Whole1MiBRAM-GPR-BP-CFIFDF-definedcallerORFLAGS/actualSSwords/independentCPUwrites/orderedports/twoloads/SScontrast/SP68-A3CE-E000-FFE0/DF0-1/all140effectsites. A3CEstaticcandidate/notobservedruntime. Full403Bsimulation-mode-record-nonlocal/FN3sourceconsumption under61BF, oldIRQdelivery/nesting/allwriters-reset-storage-lifetime-exclusion/core/P1-GATE remainopen. NoC-valuemock/genericRETforcallbackbodies. Supplementaryvectors excludedfromhelper totals; noDOSsession-realdevices-renderer-audio-fullresources-complete-state-machine-gameplay-fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
