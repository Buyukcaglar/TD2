"""Actual61BF-to403B boundary and paused/early paths, not fullcallback admission."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,Request,Response,PortService,Call,Services,Limits,Result,ww,rw,require,values
from validation.validate_state_tick_bus_diagnostics import SimLimits,Limits as TickLimits,Result as TickResult
from validate_input_poll_bus import Limits as InputLimits,Services as InputServices
from validate_mutable_control import State
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def clone(v):return type(v).from_buffer_copy(bytes(v))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();out=a.output.resolve();require(out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshmetadataoutput')
    hp='analysis/build/timer-handler-bus-repro-v3/td2ega_timer_handler_bus.dll';tp='analysis/build/state-tick-bus-repro/td2ega_state_tick_bus.dll'
    handler=C.CDLL(str((ROOT/hp).resolve())).td2ega_timer_handler_bus;handler.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];handler.restype=None
    tick=C.CDLL(str((ROOT/tp).resolve())).td2ega_state_tick_bus;tick.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(State),C.POINTER(TickLimits),C.POINTER(InputServices),C.POINTER(TickResult)];tick.restype=None
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());by={f['entry']:f for f in g['functions']};names={'06C9:61BF','06C9:403B','06C9:412C','06C9:420A','06C9:5A6F','06C9:69B7'};todo=list(names)
    while todo:
        name=todo.pop()
        for call in by[name]['calls']:
            if call['target'] not in names:names.add(call['target']);todo.append(call['target'])
    fence={(int(f['entry'][:4],16),ip) for name in names for f in [by[name]] for ip in f['instructions']}
    cases=[dict(counter=v,paused=1,activity=0,secondary=2,active=0,word=0,tag='all_counter_bytes') for v in range(256)]
    cases += [dict(counter=1,paused=paused,activity=activity,secondary=secondary,active=active,word=word,tag='paused_controls') for paused,activity,secondary,active,word in itertools.product([1,2,4],[0,1,2],[1,2],[0,1],[0,0x7fff,0x8000,0xffff])]
    vectors=instructions=0;sites=set();coverage=Counter()
    for load,same,sp,df in itertools.product([0x1000,0x2345],[False,True],[68,0xa3ce,0xe000,0xffe0],[0,1]):
        cs,ds=load+0x6c9,load+0x178f;ss=ds if same else 0x9000;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;active={}
        def state():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);seg=(u.reg_read(UC_X86_REG_CS)-load)&65535;site=(seg,ip);require(site in fence,'Callerprefixfence '+str(site))
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(site);return
            if site==(0x6c9,0x403b):
                require(not active['entered'],'Exactlyone403Bcallback');active['entered']=True;active['entry_state']=state();active['entry_sp']=u.reg_read(UC_X86_REG_SP);active['entry_flags']=u.reg_read(UC_X86_REG_EFLAGS)&65535;active['body_writes_start']=active['writes']
            if site in [(0x6c9,0x412b),(0x6c9,0x622f)]:active['return_site']=site;u.emu_stop();return
            if site==(0x6c9,0x621b):active['retired_state']=state();active['retired_sp']=u.reg_read(UC_X86_REG_SP);active['body_writes']=active['writes']-active['body_writes_start']
            active['instructions']+=1;active['sites'].add(site)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        def port_out(cpu,number,width,value,_):
            require(number==0x20 and width==1,'OnlyhandlerEOIprofile');active['ports'].append((number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1))
        def interrupt(cpu,number,_):
            require(number==0x16 and u.reg_read(UC_X86_REG_IP)==0x6605,'Paused6601actualINT16only')
            current=u.reg_read(UC_X86_REG_SP);f=u.reg_read(UC_X86_REG_EFLAGS)&65535
            # The preceding420A CMP defines AF before MOVAH1/INT; no unknown AF storage.
            for off,value in [(current-2,f),(current-4,cs),(current-6,0x6605)]:ww(backing,ss,off,value)
            active['writes']+=3;active['modeled_INT_writes']+=3;u.reg_write(UC_X86_REG_SP,(current-6)&65535);u.reg_write(UC_X86_REG_CS,cs);u.reg_write(UC_X86_REG_IP,0x69b7);u.reg_write(UC_X86_REG_EFLAGS,f&~0x300)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for c in cases:
            data=bytearray(base)
            # Synthetic raw state only. No resource codec or historical-state claim.
            for begin,end in [(0x3300,0x3400),(0x52c0,0x5400)]:data[(ds<<4)+begin:(ds<<4)+end]=bytes(end-begin)
            data[(ds<<4)+0x3368]=c['counter'];data[(ds<<4)+0x3369]=c['secondary'];data[(ds<<4)+0x33d4]=c['paused'];data[(ds<<4)+0x336b]=c['active'];data[(ds<<4)+0x5490]=c['activity']
            for at,v in [(0x33ce,c['word']),(0x33d0,c['word']),(0x33d2,2),(0x942e,0),(0x5e9a,2),(0x5e9c,0),(0x5e8c,0xffff),(0x5e8e,0x7fff),(0x5f12,0x403b),(0x5f14,cs),(0x5f18,0),(0x62b6,0)]:ww(data,ds,at,v)
            data[(ds<<4)+0x5e95]=0;data[(ds<<4)+0x5efe]=0;ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,0x643)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,0x5000,0x8000,0,df),0x5678,0);ef=2|(df<<10);u.mem_write(0,bytes(data))
            for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x61bf),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,v)
            active.clear();active.update(instructions=0,sites=set(),writes=0,modeled_INT_writes=0,ports=[],entered=False,return_site=None)
            root=False
            for _ in range(3):
                u.emu_start((u.reg_read(UC_X86_REG_CS)<<4)+u.reg_read(UC_X86_REG_IP),0,count=5000)
                site=active['return_site'];require(site is not None,'Callerprefixinstructionbudget');active['return_site']=None;active['stepping']=True;u.emu_start((load+site[0])*16+site[1],0,count=1);active['stepping']=False
                if site[1]==0x622f:root=True;break
                require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(cs,0x621b,sp-18),'Actual403Bfarretiredcallerframe')
            require(root and active['entered'],'ActualcallerandIRET');bus=(C.c_uint8*len(data)).from_buffer_copy(data);ports=[];errors=[];child_results=[]
            def native_port(ctx,qptr,value):
                q=qptr.contents;ports.append((q.port,q.value,q.interrupts_enabled));return 1
            def native_call(ctx,memory,count,qptr,rptr):
                try:
                    q=qptr.contents;require((q.kind,q.segment,q.offset,q.current_sp)==(0,cs,0x403b,sp-22),'Nativeactual403Bcall');require(bytes(q.registers)==bytes(active['entry_state']),'ActualentryGPR-BP-CFIFDF');require((q.flags_word&0xffef)==(active['entry_flags']&0xffef),'DefinedcallerORflags')
                    caps=TickLimits(11,8,4,32,128,8,16,128,128,128,3,SimLimits(8,16,1800,32,16,64,32,16),InputLimits(16,2,1,5000));code=State();code.branch_42ad=1;services=InputServices();child=TickResult()
                    tick(memory,count,load,ss,q.current_sp,C.byref(q.registers),C.byref(code),C.byref(caps),C.byref(services),C.byref(child));require(child.status==0,'Onlyretirednormal403Bpathsadmitted');require(bytes(child.returned)==bytes(active['retired_state']) and child.current_sp==active['retired_sp'] and child.bus_writes==active['body_writes'],'Actualretired403Bstate-and-writes')
                    response=rptr.contents;response.current_sp=child.current_sp;response.next_segment=child.next_segment;response.next_ip=child.next_ip;response.bus_writes=child.bus_writes;response.returned=child.returned
                    # Unexposed child arithmetic bits are dead at immediate ADDDI4.
                    response.flags_word=(q.flags_word&~0x601)|child.returned.carry|(child.returned.registers.interrupts_enabled<<9)|(child.returned.registers.direction<<10);response.flags_mask=0xffef;child_results.append(bytes(child));return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);call=Call(native_call);services=Services(port,call,None,0);caps=Limits(4,2,2);r=Result();handler(bus,len(bus),load,ss,sp,0,ef,65535,C.byref(incoming),C.byref(caps),C.byref(services),C.byref(r));label=str((load,same,sp,df,c))
            require(not errors and len(child_results)==1,'ActualCcallback '+label+str(errors));require(r.status==0 and (r.current_sp,r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'HandlerIRET '+label);require(bytes(bus)==bytes(backing),'Wholecaller-callee1MiBRAM '+label);require(r.bus_writes==active['writes'],'Allcaller-calleewrites '+label);require(ports==active['ports'],'EOIprofile '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'ActualsavedwordsGPR-BP '+label);require(r.flags_word==(u.reg_read(UC_X86_REG_EFLAGS)&65535),'ActualrootIRETFLAGS '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['tag_'+c['tag']]+=1;coverage['actual403B_callbacks']+=1;coverage['modeled_INT16_frame_writes']+=active['modeled_INT_writes'];coverage['SS_equals_principalDS']+=int(same);coverage['source_DF_'+str(df)]+=1;coverage['source_SP_'+hex(sp)]+=1
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites)}),flush=True)
    deps=['tools/validate_timer_handler_bus.py','tools/validate_input_poll_bus.py','tools/validation/validate_state_tick_bus_diagnostics.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-state-tick-bus-validation-v5.json','docs/recovery/evidence/td2ega-timer-handler-bus-validation-v3.json','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json','analysis/history/timer-state-tick-prefix-refinement-v2.json','analysis/history/validate_timer_state_tick_prefix_attempt_v1.py']
    record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':sha,'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_libraries':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in [hp,tp]],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Additionalactual61BF->403B->412C/paused420A->actual69B7->5A6F/actualcontrolhelpers->farRET->actualhandlerIRET composition. All2563368bytes/paused1-2-4/DS-SScontrast/SP68-A3CE-E000-FFE0/DF0-1/twoloads/fullRAM-GPR-BP-CFIFDF/definedcallerORFLAGS/actualsavedwords/wholeCPUwrites. A3CE is a static startup candidate, not observed runtime. Onlynormalearly-paused403B paths admitted here; full420A-4674-mode-record-nonlocal/FN3consumption and actual6269-first-registrationorder/oldIRQ/nesting/writers-reset-lifetime-exclusion/core remainopen. Callback-row403B-onlyfixture is not historicalregistration-lifetimeproof. Childunexposedarithbits proven dead at621BADDDI4, not fabricated outputFLAGS acceptance. No genericcallbackRET for403B and noC-valuemock in originalbody. Supplementaryvectors excludedfromhelper totals. NoDOSsession/realIRQ-devices/renderer-audio-complete-state-machine-gameplay-fidelity; physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
