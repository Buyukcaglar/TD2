"""Original/native actualSS callback add/remove and publication prefixes."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_timer_handler_bus import Registers,StateRegisters,ww,rw,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[0x614c,0x6180];RETURNS={0x617f,0x619e,0x61be};STEPS={0x614c,0x6180,0x6155,0x618f,0x616c,0x616e,0x6176,0x6179,0x61a6,0x61ab,0x61b3,0x61b7};ARITH=0x8d5
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','halt_site','slot','call_segment','call_offset']]+[('returned',StateRegisters)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require(C.sizeof(Result)==52,'Result52')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:614C','06C9:6180'] for ip in f['instructions']};require(len(fence)==47,'47sites');admitted=fence-{0x6164};md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence}
    fn=C.CDLL(str(lib)).td2ega_timer_callback_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=0,occupied=0,match=0,offset=0x1234,segment=0x5678,same=False,ds=None,ss=None,sp=0xe000,flags=2,mask=65535,steps=16,tag='base');c.update(kw);return c
    cases=[case(entry=e,occupied=o,match=match,flags=f,same=same) for e,o,match,f,same in itertools.product(range(2),range(6),[-1,0,1,2,3,4], [2,0x247,0x643,0xed7],[False,True])]
    cases +=[case(entry=e,occupied=o,match=match,same=True,sp=sp,flags=f,tag='live_SS_alias') for e,o,match,sp,f in itertools.product(range(2),[0,2,5],[-1,0,4],list(range(0x5f08,0x5f31))+[2,3,0xfffc,0xfffd,0xffff],[2,0x643])]
    cases +=[case(entry=e,occupied=o,match=match,same=same,steps=cap,flags=f,tag='publication_prefix') for e,o,match,same,cap,f in itertools.product(range(2),range(6),[-1,0,4],[False,True],range(17),[2,0x643])]
    cases +=[case(entry=e,offset=off,segment=sg,occupied=o,match=-1,tag='word_arguments') for e,off,sg,o in itertools.product(range(2),[0,1,0x7fff,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],range(6))]
    cases +=[case(entry=e,ds=ds,ss=ss,same=True,occupied=o,match=match,sp=sp,flags=0xed7,tag='physical_word_alias') for e,ds,ss,o,match,sp in itertools.product(range(2),[0x5000,0xffff],[0,0xffff],[0,5],[-1,0,4],[2,3,0xfffc,0xffff])]
    cases +=[case(entry=e,steps=cap,mask=mask,tag='partial_flags') for e,cap,mask in itertools.product(range(2),[0,1,5,16],[0xffef,0xf72b,0xf72a])]
    vectors=instructions=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def fetch(cpu,address,size,_):
            ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Callbackfence')
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if ip in STEPS:
                if active['steps']==active['c']['steps']:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['steps']+=1
            if ip in [0x6169,0x619f]:active['slot']=5-u.reg_read(UC_X86_REG_CX)
            if ip==0x6164:active['status']=6;active['halt']=ip;active['call']=(load+0x16a7,2);u.emu_stop();return
            if ip in RETURNS:active['ret']=ip;u.emu_stop();return
            if decoded[ip].mnemonic in ['cmp','add','dec']:active['pending_mask']=active['mask']|ARITH
            active['instructions']+=1;active['sites'].add(ip)
        def write(cpu,access,address,size,value,_):active['writes']+=1
        u.hook_add(UC_HOOK_CODE,fetch);u.hook_add(UC_HOOK_MEM_WRITE,write)
        for c in cases:
            ds=principal if c['ds'] is None else c['ds'];ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];data=bytearray(base)
            for row in range(6):ww(data,ds,0x5f12+4*row,0x100+row);ww(data,ds,0x5f14+4*row,0 if row==c['occupied'] and row<5 else cs)
            offset,segment=c['offset'],c['segment']
            if c['entry'] and c['match']>=0:
                offset=0x100+c['match'];segment=0 if c['match']==c['occupied'] and c['match']<5 else cs
            ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,offset);ww(data,ss,sp+6,segment)
            flags=c['flags'];incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x8000,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,value)
            active.clear();active.update(c=c,steps=0,writes=0,mask=c['mask'],status=0,halt=0,ret=None,slot=5,call=(0,0),instructions=0,sites=set());u.emu_start(cs*16+ENTRIES[c['entry']],0,count=1000);root=False
            if active['ret'] is not None:
                active['halt']=active['ret']
                if u.reg_read(UC_X86_REG_SP)>0xfffc:active['status']=5
                else:active['stepping']=True;u.emu_start(cs*16+active['ret'],0,count=1);active['stepping']=False;root=True
            require(root or active['status'],'Boundedoriginaloutcome')
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],flags,c['mask'],C.byref(incoming),c['steps'],C.byref(r));label=str((load,c));expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['writes'],active['halt'],active['slot'],*active['call']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.bus_writes,r.halt_site,r.slot,r.call_segment,r.call_offset)
            require(observed==expected,'Callbackcontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'CallbackwholeRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'CallbackGPR-BP '+label)
            f=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.registers.interrupts_enabled,r.returned.registers.direction)==((f>>9)&1,(f>>10)&1),'CallbackIFDF '+label);require(not r.flags_mask&1 or r.returned.carry==f&1,'CallbackdefinedCF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==f&r.flags_mask,'CallbackFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(f),hex(active['mask']))))
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['slot_'+str(r.slot)]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['published_segment_before_stale_sentinel_clear_IF1']+=int(c['entry']==0 and r.status==3 and r.halt_site==0x6179 and r.returned.registers.interrupts_enabled and rw(bus,ds,r.returned.registers.bx+6)!=0)
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    require(sites==admitted,'All46admittedsites '+str(sorted(admitted-sites)));require(coverage['published_segment_before_stale_sentinel_clear_IF1'],'Observedsourcepublicationprefix')
    deps=['tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/timer-callback-bus-build-setup-v1.json','analysis/reviews/timer-startup-bus-frontier-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000150','FN-EGA-000151'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_timer_callback_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':47,'instruction_sites_admitted':46,'instruction_sites_exercised':len(sites),'preCALL_boundary_sites':['06C9:6164'],'fixture_coverage':dict(coverage),'limits':'ActualSS614C-6180/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/actualsavedBP-farRET/orderedargumentreads-and-publicationwrites/matchedremoveCLI-STI/5rowscan/fatalpreCALL6164withactualPUSHAX/qualifiedbudget-preRET. Sourcepublicationprefixafter6176-before6179withIF1andstalerow iswitnessed, notrealIRQfeasibility orhistoricalfailure. Fatalcallee notexecuted; no nativeproducer/actualIRQ-allwriters-reset-lifetime-exclusion/core/P1-GATE/game-fidelity acceptance. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
