"""Actual native/source3FD9 registration tail with real nested SS frames."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,PortService,ww,rw,require,values
from validate_timer_control_bus import PORTS
from validate_timer_callback_bus import STEPS as CALLBACK_STEPS
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ROOT_SITES={0x3fd9,0x3fde,0x3fe1,0x3fe2,0x3fe3,0x3fe8,0x3feb,0x3fee,0x3fef,0x3ff0,0x3ff5,0x3ff8};CALLS={0x3fd9:(1,0x3fde),0x3fe3:(2,0x3fe8),0x3ff0:(3,0x3ff5)};ARITH=0x8d5
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['calls','timer_steps','timer_ports','callback_steps']]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','ports','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','stage','halt_site','call_segment','call_offset']]+[('returned',StateRegisters)]
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--probe',type=int,default=0);a=ap.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths');require(C.sizeof(Result)==56 and C.sizeof(Limits)==16,'Layouts')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=ROOT_SITES|{ip for f in g['functions'] if f['entry'] in ['06C9:601C','06C9:614C'] for ip in f['instructions']};require(len(fence)==81,'81sites');admitted=fence-{0x6164};md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    fn=C.CDLL(str(lib)).td2ega_timer_startup_tail_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),C.POINTER(Limits),PortService,C.c_void_p,C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(offset=0x1234,segment=0x5678,same=False,ds=None,ss=None,sp=0xe000,flags=2,mask=65535,pic=0xa5,speaker=0xa7,caps=(3,41,9,16),mutation=0,occupied=0,tag='base');c.update(kw);return c
    cases=[case(offset=o,segment=s,same=same,flags=f) for o,s,same,f in itertools.product([0,0x1234,0x61bf,65535],[0,0x5678,'own',65535],[False,True],[2,0x247,0x643,0xed7])]
    cases +=[case(sp=sp,same=same,flags=f,tag='actual_SS') for sp,same,f in itertools.product([10,68,0xa3ce,0xe000,0xffe0]+list(range(0x5e88,0x5ea5))+list(range(0x5f0a,0x5f31)),[False,True],[2,0x643])]
    cases +=[case(caps=caps,same=same,flags=0x643,tag='budget') for caps,same in itertools.product(itertools.product(range(4),[0,1,40,41],[0,1,5,8,9],[0,1,2,4,5,6,10,16]),[False,True])]
    cases +=[case(pic=v,speaker=v^0xa5,tag='all_port_bytes') for v in range(256)]
    cases +=[case(mutation=m,occupied=o,same=same,flags=f,tag='port_bus_mutation') for m,o,same,f in itertools.product([1,2,3,4],range(6),[False,True],[2,0x643])]
    cases +=[case(ds=ds,ss=ss,sp=sp,flags=0xed7,tag='physical_alias') for ds,ss,sp in itertools.product([0,0x5000,0xffff],[0,0xffff],[10,0xe000,0xffe0])]
    cases +=[case(mask=mask,caps=(cap,41,9,16),tag='partial_flags') for mask,cap in itertools.product([0xffef,0xf72b,0xf72a],range(4))]
    vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Startuptailfence')
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if ip in CALLS:
                if active['calls']==active['c']['caps'][0]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['calls']+=1;stage,ret=CALLS[ip];active['stage']=stage;active['frame']=(cs,ret,u.reg_read(UC_X86_REG_SP));active['timer_steps']=active['callback_steps']=0
            if active['stage']==1 and ip in [0x601c,0x60c3]:
                if active['timer_steps']==active['c']['caps'][1]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['timer_steps']+=1
            if active['stage'] in [2,3] and ip in CALLBACK_STEPS:
                if active['callback_steps']==active['c']['caps'][3]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['callback_steps']+=1
            if ip in PORTS:
                if active['ports']==active['c']['caps'][2]:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['ports']+=1
            if ip==0x6164:active['status']=6;active['halt']=ip;active['call_target']=(load+0x16a7,2);u.emu_stop();return
            if ip in [0x6109,0x617f,0x3ff8]:active['ret']=ip;u.emu_stop();return
            if decoded[ip].mnemonic in ['cmp','add']:active['pending_mask']=active['mask']|ARITH
            elif decoded[ip].mnemonic in ['and','or','xor']:active['pending_mask']=(active['mask']|ARITH)&0xffef
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
            ds=principal if c['ds'] is None else c['ds'];ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];data=bytearray(base)
            for i in range(6):ww(data,ds,0x5f12+4*i,0x100+i);ww(data,ds,0x5f14+4*i,cs)
            for i in range(40):ww(data,ds,0x5e9e+2*i,0xa500+i)
            ww(data,0,0x20,c['offset']);ww(data,0,0x22,cs if c['segment']=='own' else c['segment']);ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x8000,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x3fd9),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.clear();active.update(c=c,ds=ds,ss=ss,sp=sp,calls=0,ports=0,writes=0,mask=c['mask'],status=0,halt=0,stage=0,frame=None,ret=None,call_target=(0,0),instructions=0,sites=set(),model={0x21:c['pic'],0x61:c['speaker']},events=[]);root=False
            u.emu_start(cs*16+0x3fd9,0,count=5000)
            while active['ret'] is not None:
                ret=active['ret'];active['ret']=None;active['halt']=ret
                if u.reg_read(UC_X86_REG_SP)>0xfffc:active['status']=5;break
                active['stepping']=True;u.emu_start(cs*16+ret,0,count=1);active['stepping']=False
                if ret==0x3ff8:root=True;break
                now=(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))
                if now!=active['frame']:active['status']=1;break
                active['stage']=0;active['frame']=None;u.emu_start(now[0]*16+now[1],0,count=5000)
            require(root or active['status'],'Originaltailoutcome')
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);model={0x21:c['pic'],0x61:c['speaker']};events=[];errors=[]
            def native_port(ctx,qptr,value):
                try:q=qptr.contents;value.contents.value=service(bus,model,events,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);r=Result();caps=Limits(*c['caps']);fn(bus,len(bus),load,ss,sp,flags,c['mask'],C.byref(incoming),C.byref(caps),port,None,C.byref(r));label=str((load,c));expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['calls'],active['ports'],active['writes'],active['stage'],active['halt'],*active['call_target']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.ports,r.bus_writes,r.stage,r.halt_site,r.call_segment,r.call_offset)
            require(not errors and events==active['events'] and model==active['model'],'Orderedtailports '+label+str(errors));require(observed==expected,'Tailcontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'TailwholeRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'TailGPR-BP '+label)
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.registers.interrupts_enabled,r.returned.registers.direction)==((f>>9)&1,(f>>10)&1),'TailIFDF '+label);require(not r.flags_mask&1 or r.returned.carry==f&1,'TaildefinedCF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==f&r.flags_mask,'TailFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(f),hex(active['mask']))))
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['stage_'+str(r.stage)]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['raw_ports']+=r.ports;coverage['root_calls']+=r.calls;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['actual_published_6269_403B_sentinel']+=int(root and [rw(bus,ds,o) for o in [0x5f12,0x5f14,0x5f16,0x5f18,0x5f1c]]==[0x6269,cs,0x403b,cs,0])
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%2048==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==admitted,'All80admittedtailsites '+str(sorted(admitted-sites)));require(coverage['actual_published_6269_403B_sentinel'] and coverage['status_6'] and coverage['status_1'],'Sourceproduceroutcomecoverage')
    deps=['tools/validate_timer_handler_bus.py','tools/validate_timer_control_bus.py','tools/validate_timer_callback_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/timer-startup-tail-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-control-bus-validation-v1.json','docs/recovery/evidence/td2ega-timer-callback-bus-validation-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000124'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_startup_tail_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':81,'instruction_sites_admitted':80,'instruction_sites_exercised':len(sites),'root_instruction_sites_in_fence':12,'root_instruction_sites_exercised':len(ROOT_SITES&sites),'preCALL_boundary_sites':['06C9:6164'],'fixture_coverage':dict(coverage),'limits':'Actualnative/source3FD9..3FF8registrationtail withactual601C/614Ccallee bodies/farCALL-RET/callerADDS P4FLAGS/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/orderedports-independentCPUwrites. Sourceentry3FD9 is apartialtailof3F40, notcompleteinitialization. Budget/rawchild/fatalpreCALL6164 qualifications retainpartialstate; nofatalbody/actualIRQ-delivery-nesting/allwriters-reset-storage-lifetime-exclusion/core/P1-GATE/game-fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
