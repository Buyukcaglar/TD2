"""FullSS601C/6059/610A, live arguments, postIDIV flag validity and literal ports."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,PortService,ww,rw,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[0x601c,0x6059,0x610a];RETURNS={0x6109,0x6118,0x6122,0x614b};PORTS={0x60a7,0x60ab,0x60af,0x60b1,0x60b5,0x60f9,0x60fd,0x6102,0x6106,0x6123,0x6127,0x6138,0x613c,0x6141,0x6143,0x6145,0x6149};ARITH=0x8d5
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','ports','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','halt_site','initial_divisor','quotient','reserved']]+[('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require(C.sizeof(Result)==56,'Resultlayout')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:601C','06C9:6059','06C9:610A'] for ip in f['instructions']};require(len(fence)==91,'91source sites');md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    fn=C.CDLL(str(lib)).td2ega_timer_control_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),PortService,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=0,divisor=3,offset=0x1234,segment=0x5678,same=False,ss=None,ds=None,sp=0xe000,pic=0xa5,speaker=0xa7,steps=41,ports=9,mutation=0,mask=65535,tag='base');c.update(kw);return c
    cases=[case(entry=entry,offset=offset,segment=segment) for entry,offset,segment in itertools.product(range(3),[0,0x1234,0x61bf,65535],[0,0x5678,'own',65535])]
    divisors=[0,1,2,3,4,127,128,255,256,0x7fff,0x8000,0x8001,0xfffd,0xfffe,0xffff]
    cases += [case(entry=1,divisor=d,same=same,sp=sp,tag='live_divisor_SS') for d,same,sp in itertools.product(divisors,[False,True],[2,0xe000,0x5e94,0x5e96,0x5e98,0x5e9a,0x5e9c,0x5f12,0x5f30])]
    cases += [case(entry=e,pic=v,speaker=v^0xa5,segment='own' if e==2 else 0x5678,offset=0x61bf if e==2 else 0x1234,tag='all_port_bytes') for e,v in itertools.product(range(3),range(256))]
    cases += [case(entry=e,steps=steps,ports=ports,divisor=d,segment='own',offset=0x61bf,tag='budget') for e,steps,ports,d in itertools.product(range(3),[0,1,2,20,40,41],range(10),[3,0xfffe])]
    cases += [case(entry=e,same=same,sp=sp,divisor=0xfffe,segment='own',offset=0x61bf,tag='actual_SS_alias') for e,same,sp in itertools.product(range(3),[False,True],[2,0xfffc,0xfffd,0xffff,0x5e88,0x5e8a,0x5e94,0x5e96,0x5e98,0x5e9a,0x5e9e,0x5ea0,0x5f12,0x5f14,0x5f2e,0x5f30])]
    cases += [case(entry=e,ss=0,sp=sp,segment='own',offset=0x61bf,tag='IVT_frame_alias') for e,sp in itertools.product(range(3),[0x20,0x22,0x24,0x26])]
    cases += [case(entry=e,ds=ds,mutation=m,same=same,segment='own',offset=0x61bf,tag='port_bus_mutation') for e,ds,m,same in itertools.product(range(3),[None,0x5000],[1,2,3],[False,True])]
    cases += [case(entry=e,steps=s,mask=m,tag='incoming_partial') for e,s,m in itertools.product(range(3),[0,1,41],[0xffef,0xf72b,0xf72a])]
    vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Timercontrolfence')
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if ip in ENTRIES or ip==0x60c3:
                if active['steps']==active['c']['steps']:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['steps']+=1
            if ip in PORTS:
                if active['ports']==active['c']['ports']:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['ports']+=1
            if ip==0x6061:
                word=rw(backing,active['ss'],u.reg_read(UC_X86_REG_BP)+6);active['divisor']=word
                if word in [0,1,2,0xffff]:active['status']=6;active['halt']=ip;u.emu_stop();return
            if ip==0x6064:active['quotient']=u.reg_read(UC_X86_REG_AX)
            if ip in RETURNS:active['ret']=ip;u.emu_stop();return
            mnemonic=decoded[ip].mnemonic
            if mnemonic=='idiv':active['pending_mask']=active['mask']&~ARITH
            elif mnemonic in ['and','or','xor','test']:active['pending_mask']=(active['mask']|ARITH)&0xffef
            elif mnemonic in ['add','sub','cmp','neg']:active['pending_mask']=active['mask']|ARITH
            active['instructions']+=1;active['sites'].add(ip)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        def service(memory,model,events,operation,number,value,enabled):
            require(number in [0x21,0x61,0x40,0x43],'Rawportdomain');events.append((operation,number,value,enabled));response=model.get(number,0)
            if operation:model[number]=value
            if len(events)==1 and active['c']['mutation']:
                mutation=active['c']['mutation'];ss=active['ss'];sp=active['sp'];ds=active['ds']
                if mutation==1:ww(memory,ss,sp,0x3333);ww(memory,ss,sp+2,0x4444);ww(memory,ss,sp-2,0xbeef)
                elif mutation==2:ww(memory,0,0x20,0x4321);ww(memory,0,0x22,cs)
                else:ww(memory,ds,0x5e88,0x9876);ww(memory,ds,0x5e8a,0x5432)
            return response
        def port_in(cpu,number,width,_):require(width==1 and number in [0x21,0x61],'INwidth');return service(backing,active['port_values'],active['events'],0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(cpu,number,width,value,_):require(width==1,'OUTwidth');service(backing,active['port_values'],active['events'],1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for c in cases:
            ds=principal if c['ds'] is None else c['ds'];ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];data=bytearray(base)
            for at,value in [(0x5e88,0x9abc),(0x5e8a,0xdef0),(0x5e98,0x7777),(0x5e9a,0x8888),(0x5e96,0x9999),(0x5e9c,0xffff),(0x5f12,0x6269),(0x5f14,cs)]:ww(data,ds,at,value)
            for i in range(40):ww(data,ds,0x5e9e+2*i,0xa500+i)
            ww(data,0,0x20,c['offset']);ww(data,0,0x22,cs if c['segment']=='own' else c['segment']);ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,c['divisor'])
            flags=[2,0x247,0x643,0xed7][vectors%4];incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x8000,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.clear();active.update(c=c,ds=ds,ss=ss,sp=sp,steps=0,ports=0,writes=0,mask=c['mask'],status=0,halt=0,ret=None,divisor=0,quotient=0,instructions=0,sites=set(),port_values={0x21:c['pic'],0x61:c['speaker']},events=[])
            u.emu_start(cs*16+ENTRIES[c['entry']],0,count=5000);root=False
            if active['ret'] is not None:
                active['halt']=active['ret']
                if u.reg_read(UC_X86_REG_SP)>0xfffc:active['status']=5
                else:active['stepping']=True;u.emu_start(cs*16+active['ret'],0,count=1);active['stepping']=False;root=True
            require(root or active['status'],'Originalinstructionbudget')
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];model={0x21:c['pic'],0x61:c['speaker']};errors=[]
            def native_port(ctx,qptr,value):
                try:q=qptr.contents;value.contents.value=service(bus,model,events,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],flags,c['mask'],C.byref(incoming),port,None,c['steps'],c['ports'],C.byref(r));label=str((load,c))
            require(not errors and events==active['events'] and model==active['port_values'],'Orderedrawports '+label+str(errors))
            expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['ports'],active['writes'],active['halt'],active['divisor'],active['quotient']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.ports,r.bus_writes,r.halt_site,r.initial_divisor,r.quotient)
            require(observed==expected,'Timercontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'FullSS-RAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'FullGPR-BP '+label)
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.registers.interrupts_enabled,r.returned.registers.direction)==((f>>9)&1,(f>>10)&1),'IFDF '+label);require(not r.flags_mask&1 or r.returned.carry==f&1,'DefinedCF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==f&r.flags_mask,'DefinedFLAGS-mask '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(f),hex(active['mask']))))
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['raw_ports']+=r.ports;coverage['postIDIV_CF_unknown_prefix']+=int(not r.flags_mask&1);coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111))
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%1024==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==fence,'All91timer-controlsites '+str(sorted(fence-sites)))
    deps=['tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/timer-control-bus-build-setup-v1.json','analysis/reviews/timer-startup-bus-frontier-v1.json','docs/recovery/evidence/intel-idiv-reference-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000147','FN-EGA-000148','FN-EGA-000149'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_control_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':91,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'AdditionalactualSS601C-6059-610A/currentDS/fullGPR-BP-IFDF-definedCF-FLAGS/maskF72ApostIDIV/actualSSdivisor reread afterquotientpublications/literalIVTindependentoffset-segmentcomparisons/40histogramwrites/orderedbyteports/actualfarRET-aftereffects/whole1MiBRAM. Budgets/portfailure/preIDIV/preRETqualifications separatefromsourceerror-return orhistoricalexceptiondelivery. No assignedclockunits/physical086Csemantics/realIRQ-nesting/allwriters-reset-lifetime/fullnativeproducer/core/P1-GATE/DOSsession-audio-game-fidelity; CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
