"""Actual6269 fullSS, defined FLAGS, ordered ports and CPU writes."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,PortService,ww,rw,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
PORTS={0x6281,0x6285,0x629c,0x62a0,0x62ae,0x62b2,0x62f0,0x62f4,0x62f6,0x62fa,0x631d,0x6321}
RETURNS={0x6287,0x62a2,0x62fc,0x6323}
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','ports','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','halt_site','raw_target']]+[('returned',StateRegisters)]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require(C.sizeof(Result)==52,'Resultlayout')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());f=next(v for v in g['functions'] if v['entry']=='06C9:6269');fence=set(f['instructions']);require(len(fence)==140,'140source sites');md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    fn=C.CDLL(str(lib)).td2ega_effect_tick_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*5+[C.POINTER(StateRegisters),PortService,C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None
    cases=[];boundary=[0,1,2,3,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xfffe,0xffff]
    for mode,remaining,threshold in itertools.product([0,1,2,3,255],boundary,boundary):cases.append(('entry_counter_profiles',dict(mode=mode,remaining=remaining,threshold=threshold)))
    for note,count in itertools.product(range(256),[0,1,0x7fff,0x8000,0xffff]):cases.append(('all_event_bytes',dict(note=note,count=count,loop_count=count)))
    for shift,duration in itertools.product(range(256),boundary):cases.append(('all_shift_bytes',dict(shift=shift,duration=duration)))
    for note,count in itertools.product(range(0xf5,0x100),boundary):cases.append(('loop_signed_boundaries',dict(note=note,loop_count=count,count=count)))
    for event,note in itertools.product([0,1,0xfffc,0xfffd,0xfffe,0xffff],[0,65,0xff]):cases.append(('effective_offset_wrap',dict(event=event,note=note)))
    for queued,absent in itertools.product([0,1,255],[0,1]):cases.append(('queued_pointer_transfer',dict(queued=queued,absent=absent,note=0xff)))
    for event in [0x5ef6,0x5ef8,0x5efa,0x5f00,0x5f2e]:cases.append(('source_group_alias',dict(shared=True,event=event,note=0 if event==0x5ef6 else 65)))
    rng=random.Random(0x6269)
    for _ in range(2048):cases.append(('varied_finite_states',dict(mode=rng.randrange(256),remaining=rng.randrange(65536),threshold=rng.randrange(65536),shift=rng.randrange(256),note=rng.randrange(256),loop_count=rng.randrange(65536),duration=rng.randrange(65536),count=rng.randrange(65536),queued=rng.randrange(2),absent=rng.randrange(2))))
    for same,sp,note,mode in itertools.product([False,True],[0,1,0xfffc,0xfffd,0xfffe,0xffff,0x5eee,0x5ef0,0x5ef6,0x5ef8,0x5efa,0x5f00,0x5f06,0x5f0c],[0,65,0xf5,0xf8,0xfb,0xfe,0xff],[0,3]):cases.append(('actual_SS_alias',dict(same=same,sp=sp,note=note,mode=mode)))
    for steps,ports,note,queued,absent in itertools.product([0,1,2,4,32],range(5),[0,65,0xf8,0xff],[0,1],[0,1]):cases.append(('partial_budget',dict(steps=steps,ports=ports,note=note,queued=queued,absent=absent)))
    for mutation,note,same,sp in itertools.product([1,2],[0,65,0xff],[False,True],[0xe000,0x5ef6,0x5f00]):cases.append(('port_memory_mutation',dict(mutation=mutation,note=note,same=same,sp=sp)))
    for ds,note,es,event in itertools.product([0x5000,0xf000],[0,65,0xf8],[0x6000,0xffff],[0x0e,0x0f,0xfffe,0xffff]):cases.append(('currentDS_physical_wrap',dict(ds=ds,note=note,segment=es,event=event)))
    targets=[0x62fd,0x634c,0x635b,0x6370,0x6385,0x639a,0x63b4,0x63ce,0x63e8,0x63ff,0x6416]
    for slot,target in itertools.product(range(1,12),targets+[0,0x1234,0x6287,0xffff]):cases.append(('literal_command_table',dict(note=256-slot,table_patch=(slot,target))))
    for slot,sp in itertools.product(range(1,12),[0x6336,0x6340,0x6348]):cases.append(('CS_table_SS_alias',dict(note=256-slot,ss_code=True,sp=sp)))
    vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'6269fence')
            pending=active.pop('pending_af',None)
            if pending is not None:active['af_valid']=pending
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if ip in [0x6269,0x62b7]:
                if active['steps']==active['limits'][0]:active['prefix']=3;active['halt']=ip;u.emu_stop();return
                active['steps']+=1
            if ip in PORTS:
                if active['ports']==active['limits'][1]:active['prefix']=3;active['halt']=ip;u.emu_stop();return
                active['ports']+=1
            if ip==0x632f:
                target=rw(backing,cs,0x6334+u.reg_read(UC_X86_REG_BX));active['raw_target']=target
                if target not in targets:active['prefix']=6;active['halt']=ip;u.emu_stop();return
            if ip in RETURNS:active['ret']=ip;u.emu_stop();return
            mnemonic=decoded[ip].mnemonic
            if mnemonic in ['and','or','xor','test','shl','shr']:active['pending_af']=False
            elif mnemonic in ['add','sub','cmp','neg','inc','dec']:active['pending_af']=True
            active['instructions']+=1;active['sites'].add(ip)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        def service(memory,events,op,number,value,enabled):
            events.append([op,number,value,enabled]);response=[0xa5,0xfe,1,0x83][(len(events)-1)%4]
            if len(events)==1 and active['case'].get('mutation'):
                ww(memory,active['ss'],active['sp'],0x3333);ww(memory,active['ss'],active['sp']+2,0x4444)
                if active['case']['mutation']==2:ww(memory,active['ds'],0x5ef8,0x8765)
            return response
        def port_in(cpu,number,width,_):require(number==0x61 and width==1,'INprofile');return service(backing,active['events'],0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(cpu,number,width,value,_):require(number in [0x61,0x42] and width==1,'OUTprofile');service(backing,active['events'],1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for tag,c in cases:
            ds=c.get('ds',principal);ss=c.get('ss',cs if c.get('ss_code') else ds if c.get('same') else 0x9000);sp=c.get('sp',0xe000);segment=ds if c.get('shared') else c.get('segment',0x6000);event=c.get('event',0x1000);note=c.get('note',65);data=bytearray(base)
            for at,value in [(0x5eee,0 if c.get('absent') else segment),(0x5ef0,event),(0x5ef2,0x7000),(0x5ef4,0x2000),(0x5ef6,c.get('remaining',0)),(0x5ef8,c.get('threshold',0)),(0x5f00,c.get('loop_count',0)),(0x5f02,c.get('loop_count',0)),(0x5f04,c.get('loop_count',0)),(0x5f06,0x2000),(0x5f08,0x2000),(0x5f0a,0x2000),(0x5f0c,0x2000),(0x5f0e,0x2000),(0x5f10,0x2000)]:ww(data,ds,at,value)
            for i in range(128):ww(data,ds,0x5f2e+2*i,i*317+11)
            def putbyte(s,o,v):data[((s<<4)+(o&65535))&0xfffff]=v
            for at,v in [(0x5efb,c.get('mode',3)),(0x5efc,1),(0x5efd,c.get('queued',0)),(0x5efa,c.get('shift',1))]:putbyte(ds,at,v)
            if 0xfb<=note<=0xfd:stream=bytes([note])+struct.pack('<H',c.get('count',0))+bytes([65,2,0])
            elif note==0xfe:stream=bytes([note,c.get('count',0)&255,65,2,0])
            elif 0xf5<=note<=0xfa:stream=bytes([note,65,2,0])
            else:stream=bytes([note])+struct.pack('<H',c.get('duration',2))
            for i,b in enumerate(stream):putbyte(segment,event+i,b)
            for source in [segment,0x7000]:
                for i,b in enumerate([65,2,0]):putbyte(source,0x2000+i,b)
            if c.get('shared'):
                ww(data,ds,0x5eee,segment);ww(data,ds,0x5ef0,event);ww(data,ds,0x5ef6,0);putbyte(ds,0x5efb,3);putbyte(ds,0x5efd,0)
            if 'table_patch' in c:ww(data,cs,0x6334+2*c['table_patch'][0],c['table_patch'][1])
            ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);flags=[2,0x247,0x643,0xed7][vectors%4];incoming=StateRegisters(Registers(0xa55a,0xa534,0x4567,0x7654,0x3456,0x2345,ds,0x4321,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);limits=(c.get('steps',128),c.get('ports',8))
            u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6269),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.clear();active.update(case=c,ds=ds,ss=ss,sp=sp,limits=limits,steps=0,ports=0,writes=0,events=[],instructions=0,sites=set(),af_valid=True,prefix=0,ret=None,halt=0,raw_target=0)
            u.emu_start(cs*16+0x6269,0,count=30000);root=False
            if active['ret'] is not None:
                active['halt']=active['ret']
                if sp>0xfffc:active['prefix']=5
                else:active['stepping']=True;u.emu_start(cs*16+active['ret'],0,count=1);active['stepping']=False;root=True
            require(root or active['prefix'],'Originalinstructionbudget '+tag)
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def native_port(ctx,qptr,value):
                try:q=qptr.contents;value.contents.value=service(bus,events,q.operation,q.port,q.value,q.interrupts_enabled);return 1
                except Exception as error:errors.append(str(error));return 0
            port=PortService(native_port);r=Result();fn(bus,len(bus),load,ss,sp,flags,65535,C.byref(incoming),port,None,*limits,C.byref(r));label=str((load,tag,c))
            require(not errors,'Nativeservices '+label+str(errors));require(events==active['events'],'Fullorderedports '+label)
            expected=(0 if root else active['prefix'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['ports'],active['writes'],active['halt'],active['raw_target']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.ports,r.bus_writes,r.halt_site,r.raw_target)
            require(observed==expected,'Effectcontrol-counts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'WholeSS-RAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'WholeGPR-BP '+label)
            fflags=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(fflags&1,(fflags>>9)&1,(fflags>>10)&1),'CFIFDF '+label);require((r.flags_word&r.flags_mask)==(fflags&r.flags_mask),'DefinedFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(fflags))));require(bool(r.flags_mask&16)==active['af_valid'],'AFvalidity '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['tag_'+tag]+=1;coverage['status_'+str(r.status)]+=1;coverage['actual_CPU_writes']+=r.bus_writes;coverage['ordered_ports']+=r.ports;coverage['DS_equals_SS']+=int(ds==ss);coverage['retired_root_CF_'+str(r.returned.carry)]+=int(root);coverage['changed_root_coordinates']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111))
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==fence,'All140effect sites '+str(sorted(fence-sites)))
    deps=['tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/effect-tick-bus-build-setup-v2.json','analysis/history/effect-tick-bus-refinement-v2.json','analysis/history/effect-tick-bus-validation-preparation-v2.json','analysis/reviews/effect-tick-bus-frontier-v1.json','docs/recovery/evidence/td2ega-effect-tick-validation-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000403'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_effect_tick_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':140,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Additional6269fullSS/currentDS/actualfarRET-aftereffects/whole1MiBRAM-GPR-BP-CFIFDF/definedFLAGS/independentCPUwrites/orderedbyteports. LiteralcurrentCS6334words/11recognizedtargets/unknownprefix6/CS-table-SSaliases/256event-andshiftbytes/JS-afterDEC/queuedcycles/SS-state-source-framealiases/currentDScontrast/20bitwrap/portbusmutations/nativebudgets-preRETqualification. Portadapterbuswrites separatefromCPUcounts. No historicalCPU-IRQdelivery/timeunits/audio/fullresources/sourceallwriters-lifetime-exclusion/actual6269-first403B-core/P1-GATE acceptance. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
