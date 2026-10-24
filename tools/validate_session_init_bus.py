"""ActualSS whole session-initialization roots with original callee bodies."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,PortService,ww,rw,require,values
from validate_timer_startup_tail_bus import Limits as TailLimits,ROOT_SITES as TAIL_SITES
from validate_timer_control_bus import PORTS
from validate_timer_callback_bus import STEPS as CALLBACK_STEPS
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_MEM
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[0x3f40,0x3ff9,0x38f2,0x1e31,0x5427];INIT_CALLS={0x1e31:(1,0x1e36,True),0x4037:(2,0x403a,False),0x1e53:(3,0x1e58,True)};TAIL_CALLS={0x3fd9:(101,0x3fde),0x3fe3:(102,0x3fe8),0x3ff0:(103,0x3ff5)};RETURNS={0x6109,0x617f,0x3ff8,0x403a,0x391e,0x1e58,0x5438};ARITH=0x8d5
class Limits(C.Structure):_fields_=[('steps',C.c_uint32),('init_calls',C.c_uint32),('tail',TailLimits)]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','init_calls','tail_calls','ports','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','stage','halt_site','call_segment','call_offset']]+[('returned',StateRegisters)]
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--probe',type=int,default=0);a=ap.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths');require(C.sizeof(Result)==64 and C.sizeof(Limits)==24,'Layouts')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());init_names=['06C9:'+f'{ip:04X}' for ip in ENTRIES];names=init_names+['06C9:601C','06C9:614C'];fence={ip for f in g['functions'] if f['entry'] in names for ip in f['instructions']};require(len(fence)==188,'188sites');admitted=fence-{0x6164};md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True;decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence};init_sites={ip for f in g['functions'] if f['entry'] in init_names for ip in f['instructions']};prefix_steps=set(ENTRIES)|{0x3f4d,0x3fbf,0x3fd3}|{ip for ip in init_sites if decoded[ip].mnemonic=='mov' and decoded[ip].operands[0].type==X86_OP_MEM}
    fn=C.CDLL(str(lib)).td2ega_session_init_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),PortService,C.c_void_p,C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=0,same=False,ds=None,ss=None,sp=0xe000,flags=2,mask=65535,pattern=0xa5,conditional=0,source=0x7f,token=0,table_seed=0x5a,word3811=0x1234,bound0=0x1234,bound1=0x5678,pic=0xa5,speaker=0xa7,caps=(120,3,3,41,9,16),mutation=0,occupied=0,tag='base');c.update(kw);return c
    cases=[case(entry=e,same=same,flags=f,conditional=cond,pattern=pattern) for e,same,f,cond,pattern in itertools.product(range(5),[False,True],[2,0x247,0x643,0xed7],[0,1],[0,0xa5,0xff])]
    cases +=[case(token=v,conditional=v,source=v,table_seed=v^0xa5,word3811=0xffff if v&1 else 0,same=same,flags=0x643,tag='all_masked_tokens') for v,same in itertools.product(range(256),[False,True])]
    alias_sp=sorted(set([10,68,0xa3ce,0xe000,0xffe0]+list(range(0x2f44,0x2f60))+list(range(0x33b2,0x33d8))+list(range(0x52c8,0x52e2))+list(range(0x5e88,0x5ea3))+list(range(0x5f0a,0x5f31))+list(range(0x66e0,0x66f1))+[0x672a,0x672b,0x67e6,0x67e8]))
    cases +=[case(entry=e,same=True,sp=sp,flags=f,conditional=1,tag='live_SS_alias') for e,sp,f in itertools.product(range(5),alias_sp,[2,0x643])]
    # Additional live SS frames may overlap source bounds, REP destinations,
    # fold stream/lookup bytes, repeated3811 and the BSS942E root write.
    extra_aliases=sorted(set(list(range(0x23c2,0x23cf))+list(range(0x335a,0x3369))+list(range(0x347a,0x3489))+list(range(0x367a,0x3681))+list(range(0x380f,0x3819))+list(range(0x3b4d,0x3b60))+list(range(0x9428,0x9435)))-set(alias_sp))
    cases +=[case(entry=e,same=True,sp=sp,flags=f,conditional=255,word3811=0xfffe,tag='live_source_BSS_SS_alias') for e,sp,f in itertools.product(range(5),extra_aliases,[2,0x643])]
    caps_steps=[0,1,2,5,8,9,20,25,26,35,36,38,39,40,70,109,110,111,112,120]
    cases +=[case(entry=e,same=same,flags=0x643,caps=(steps,calls,3,41,9,16),tag='prefix_budget') for e,same,steps,calls in itertools.product(range(5),[False,True],caps_steps,range(4))]
    cases +=[case(same=same,caps=(120,3,calls,steps,ports,callbacks),flags=0x643,tag='tail_budget') for same,calls,steps,ports,callbacks in itertools.product([False,True],range(4),[0,1,40,41],[0,1,8,9],[0,1,5,6,7,16])]
    cases +=[case(entry=e,sp=sp,tag='SP_boundary') for e,sp in itertools.product(range(5),[0,1,2,3,6,9,10,0xfffc,0xfffd,0xfffe,0xffff]) if (e!=0 or 10<=sp<=0xffe0) and (e!=1 or sp>=2) and (e!=3 or sp>=6)]
    cases +=[case(entry=e,mask=mask,caps=(steps,3,3,41,9,16),tag='partial_FLAGS') for e,mask,steps in itertools.product(range(5),[0xffef,0xf72b,0xf72a],[0,1,120])]
    cases +=[case(entry=e,ds=ds,ss=ss,flags=0xed7,tag='physical_alias') for e,ds,ss in itertools.product(range(5),[0,0x5000,0xffff],[0,0x9000,0xffff])]
    cases +=[case(mutation=m,occupied=o,same=same,flags=0x643,tag='port_bus_mutation') for m,o,same in itertools.product([1,2,3,4],range(6),[False,True])]
    cases +=[case(word3811=word,conditional=cond,table_seed=0xff,tag='word_wrap') for word,cond in itertools.product([0,1,0x3b33,0x8000,0xc4cc,0xc4cd,0xfffe,0xffff],[0,255])]
    vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Sessioninitfence')
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if ip==0x3fd9:active['stage']=100
            if ip in prefix_steps and (ip!=0x3f4d or u.reg_read(UC_X86_REG_CX)):
                if active['steps']==active['c']['caps'][0]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['steps']+=1
            if ip in INIT_CALLS:
                if active['init_calls']==active['c']['caps'][1]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['init_calls']+=1;stage,ret,far=INIT_CALLS[ip];active['frames'].append((cs,ret,u.reg_read(UC_X86_REG_SP),active['stage']));active['stage']=stage
            if ip in TAIL_CALLS:
                if active['tail_calls']==active['c']['caps'][2]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['tail_calls']+=1;stage,ret=TAIL_CALLS[ip];active['frames'].append((cs,ret,u.reg_read(UC_X86_REG_SP),100));active['stage']=stage;active['timer_steps']=active['callback_steps']=0
            if active['stage']==101 and ip in [0x601c,0x60c3]:
                if active['timer_steps']==active['c']['caps'][3]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['timer_steps']+=1
            if active['stage'] in [102,103] and ip in CALLBACK_STEPS:
                if active['callback_steps']==active['c']['caps'][5]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['callback_steps']+=1
            if ip in PORTS:
                if active['ports']==active['c']['caps'][4]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['ports']+=1
            if ip==0x6164:active['status']=6;active['halt']=ip;active['call_target']=(load+0x16a7,2);u.emu_stop();return
            if ip in RETURNS:active['ret']=ip;u.emu_stop();return
            mnemonic=decoded[ip].mnemonic
            if mnemonic in ['cmp','add']:active['pending_mask']=active['mask']|ARITH
            elif mnemonic in ['inc','dec']:active['pending_mask']=active['mask']|(ARITH^1)
            elif mnemonic in ['and','or','xor','shl']:active['pending_mask']=(active['mask']|ARITH)&0xffef
            active['instructions']+=1;active['sites'].add(ip)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        def service(memory,model,events,operation,number,value,enabled):
            require(number in [0x21,0x61,0x40,0x43],'Rawports');events.append((operation,number,value,enabled));response=model.get(number,0)
            if operation:model[number]=value
            c=active['c'];ss,sp,ds=active['ss'],active['sp'],active['ds'];mutation=c['mutation']
            if len(events)==1 and mutation==1:ww(memory,ss,sp,0x3333);ww(memory,ss,sp+2,0x4444)
            if len(events)==1 and mutation==2:ww(memory,ss,sp-4,0x3333);ww(memory,ss,sp-2,0x4444)
            if len(events)==1 and mutation==3:
                for i in range(5):ww(memory,ds,0x5f14+4*i,cs)
            if len(events)==9 and mutation==4:
                for i in range(6):ww(memory,ds,0x5f14+4*i,0 if i==c['occupied'] and i<5 else cs)
            return response
        def port_in(cpu,number,width,_):require(width==1 and number in [0x21,0x61],'INwidth');return service(backing,active['model'],active['events'],0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(cpu,number,width,value,_):require(width==1,'OUTwidth');service(backing,active['model'],active['events'],1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for c in cases:
            ds=principal if c['ds'] is None else c['ds'];ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];data=bytearray(base);pattern=bytes([c['pattern']])*65536;at=(ds<<4)&0xfffff;first=min(65536,len(data)-at);data[at:at+first]=pattern[:first];data[:65536-first]=pattern[first:]
            def byte(offset,value):data[((ds<<4)+offset)&0xfffff]=value&255
            for i in range(71):byte(0x3b51+i,c['token'])
            for i in range(512):byte(0x347e+i,(i*13)^c['table_seed'])
            byte(0x90a8,c['conditional']);byte(0x843e,c['source']);ww(data,ds,0x3811,c['word3811']);ww(data,ds,0x23c6,c['bound0']);ww(data,ds,0x23c8,c['bound1']);ww(data,ds,0x66e6,0x1357)
            for i in range(256):byte(0x66e8+i,i)
            for i in range(6):ww(data,ds,0x5f12+4*i,0x100+i);ww(data,ds,0x5f14+4*i,cs)
            ww(data,0,0x20,0x1234);ww(data,0,0x22,0x5678);ww(data,ss,sp,0x1111)
            if c['entry']!=4:ww(data,ss,sp+2,0x2222)
            ring_before=bytes(data[((ds<<4)+o)&0xfffff] for o in range(0x66e6,0x67e8));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x8000,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.clear();active.update(c=c,ds=ds,ss=ss,sp=sp,steps=0,init_calls=0,tail_calls=0,ports=0,writes=0,mask=c['mask'],status=0,halt=0,stage=0,frames=[],ret=None,call_target=(0,0),instructions=0,sites=set(),model={0x21:c['pic'],0x61:c['speaker']},events=[]);root=False
            u.emu_start(cs*16+ENTRIES[c['entry']],0,count=10000)
            while active['ret'] is not None:
                ret=active['ret'];active['ret']=None;active['halt']=ret
                if u.reg_read(UC_X86_REG_SP)>(0xfffe if ret==0x5438 else 0xfffc):active['status']=5;break
                active['stepping']=True;u.emu_start(cs*16+ret,0,count=1);active['stepping']=False
                if not active['frames']:root=True;active['stage']=0;break
                expected=active['frames'].pop();now=(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))
                if now!=expected[:3]:active['status']=1;break
                active['stage']=expected[3];u.emu_start(now[0]*16+now[1],0,count=10000)
            require(root or active['status'],'Originalsessionoutcome')
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);model={0x21:c['pic'],0x61:c['speaker']};events=[];errors=[]
            def native_port(ctx,qptr,value):
                try:q=qptr.contents;value.contents.value=service(bus,model,events,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);r=Result();caps=Limits(c['caps'][0],c['caps'][1],TailLimits(*c['caps'][2:]));fn(bus,len(bus),load,ss,sp,c['entry'],flags,c['mask'],C.byref(incoming),C.byref(caps),port,None,C.byref(r));label=str((load,c));expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['init_calls'],active['tail_calls'],active['ports'],active['writes'],active['stage'],active['halt'],*active['call_target']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.init_calls,r.tail_calls,r.ports,r.bus_writes,r.stage,r.halt_site,r.call_segment,r.call_offset)
            require(not errors and events==active['events'] and model==active['model'],'Orderedinitports '+label+str(errors));require(observed==expected,'Initcontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'InitwholeRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'InitGPR-BP '+label)
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.registers.interrupts_enabled,r.returned.registers.direction)==((f>>9)&1,(f>>10)&1),'InitIFDF '+label);require(not r.flags_mask&1 or r.returned.carry==f&1,'InitdefinedCF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==f&r.flags_mask,'InitFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(f),hex(active['mask']))))
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['stage_'+str(r.stage)]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['raw_ports']+=r.ports;coverage['init_calls']+=r.init_calls;coverage['tail_calls']+=r.tail_calls;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root']+=int(root and (r.next_segment,r.next_ip)!=((cs if c['entry']==4 else 0x2222),0x1111));ring_after=bytes(bus[((ds<<4)+o)&0xfffff] for o in range(0x66e6,0x67e8));coverage['conditional_SS_ring_write_witnesses']+=int(ring_before!=ring_after);coverage['entry_'+str(c['entry'])+'_SS_ring_write_witnesses']+=int(ring_before!=ring_after);coverage['published_6269_403B_sentinel']+=int(root and c['entry']==0 and [rw(bus,ds,o) for o in [0x5f12,0x5f14,0x5f16,0x5f18,0x5f1c]]==[0x6269,cs,0x403b,cs,0])
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%2048==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==admitted,'All187admittedsites '+str(sorted(admitted-sites)));require(coverage['conditional_SS_ring_write_witnesses'] and coverage['published_6269_403B_sentinel'] and coverage['status_1'] and coverage['status_6'],'Initcaller-and-aliascoverage')
    deps=['tools/validate_timer_handler_bus.py','tools/validate_timer_startup_tail_bus.py','tools/validate_timer_control_bus.py','tools/validate_timer_callback_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/session-init-bus-build-setup-v1.json','analysis/reviews/session-init-bus-frontier-v1.json','analysis/history/session-init-bus-validation-refinement-v2.json','docs/recovery/evidence/td2ega-timer-startup-tail-bus-validation-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000124','FN-EGA-000125','FN-EGA-000111','FN-EGA-000082','FN-EGA-000126'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_session_init_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':188,'instruction_sites_admitted':187,'instruction_sites_exercised':len(sites),'preCALL_boundary_sites':['06C9:6164'],'fixture_coverage':dict(coverage),'limits':'Whole3F40-3FF9-38F2-1E31/actualnear5427/frozennative601C-614Ctail/fullSSfar-nearCALL-RET/orderedDSwrites-liveSSframes/fullGPR-BP-CFIFDF-definedFLAGS/wholeRAM-orderedports-independentCPUwrites. ConditionalSS66E6..67E7stackwrites arewitnessed, notintentionalringreset/seeding/RNGpurpose oractualcallerstackdomain proof. Budgets/rawchild/fatalpreCALL/preRET remainqualifications; no actualIRQ-allwriters-storage-lifetime-exclusion/startup-to-exit-complete-core/P1-GATE/DOSsession-renderer-audio-game-fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
