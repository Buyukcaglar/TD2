"""Compare five small platform wrappers with explicit synthetic INT responses."""
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
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *

class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('calls',C.c_uint32),('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();library=args.library.resolve();output=args.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));fn=dll.td2ega_small_platform
    fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    entries=[(0x6c9,0x5d4e),(0x6c9,0x5d74),(0x13a8,0x2e2e),(0x6c9,0x5d5b),(0x6c9,0x5d2e)];ids=['FN-EGA-000135','FN-EGA-000137','FN-EGA-000342','FN-EGA-000136','FN-EGA-000134'];graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());names={f'{s:04X}:{ip:04X}' for s,ip in entries};fence={(int(f['entry'][:4],16),ip) for f in graph['functions'] if f['entry'] in names for ip in f['instructions']};int_sites={0x5d50:0x21,0x5d56:0x21,0x5d74:0x11,0x2e33:0x21,0x5d67:0x21,0x5d30:0x1a};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter()
    def event(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
    for load in [0x1000,0x2345]:
        ds=load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def response(q,index,seed,profile):
            bp=(q.incoming.bp+16)&65535 if profile&1 else q.incoming.bp
            rr=StateRegisters(Registers((seed+index*0x1234)&65535,0x2222^seed,0xa5f0^seed,0x5a00^seed,0x3333^seed,0x4444^seed,[q.incoming.registers.ds,0x7000,0x7100,q.stack_segment][profile],0x7200,(seed>>1)&1,(seed>>2)&1),bp,seed&1)
            mutations=[(((rr.registers.ds<<4)+0x300+index*2)&0xfffff,struct.pack('<H',seed^0x55aa))]
            if q.site==0x2e33 and profile&1:mutations.append((((q.stack_segment<<4)+((bp+6)&65535))&0xfffff,struct.pack('<H',0x2880)))
            return rr,mutations
        def code(cpu,address,size,unused):
            segment=u.reg_read(UC_X86_REG_CS)-load;ip=u.reg_read(UC_X86_REG_IP);require((segment,ip) in fence,'Small platform escaped '+hex(address))
            if ip in int_sites:
                if len(active['events'])==active['limit']:active['prefix']=True;u.emu_stop();return
                active['pending']=Request(int_sites[ip],ip,load+segment,active['ss'],u.reg_read(UC_X86_REG_SP),read_regs())
            active['instructions']+=1;active['sites'].add((segment,ip))
        def interrupt(cpu,vector,unused):
            q=active['pending'];require(q is not None and vector==q.vector,'INT boundary');active['events'].append(event(q));rr,mutations=response(q,len(active['events'])-1,active['seed'],active['profile'])
            for at,data in mutations:u.mem_write(at,data)
            for reg,v in zip(regs,values(rr.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,rr.bp);flags=u.reg_read(UC_X86_REG_EFLAGS);u.reg_write(UC_X86_REG_EFLAGS,(flags&~0x601)|rr.carry|(rr.registers.interrupts_enabled<<9)|(rr.registers.direction<<10));active['pending']=None
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,seed,profile,same,flags,limit in itertools.product(range(5),[0,1,0x3f,0x40,0x7f,0x80,0xbf,0xc0,0xff,0xffff],range(4),[0,1],[2,0x203,0x402,0x603],[0,1,2]):
            data=bytearray(base);ss=ds if same else 0x9000;segment,ip=entries[entry];cs=load+segment;frame=struct.pack('<2H',0x100,0x1111);tail=struct.pack('<H',0x2800)+b'\x5a\xa5'*4;data[ss*16+sp-16:ss*16+sp+len(frame)+len(tail)]=b'\xa5'*16+frame+tail;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(ss=ss,limit=limit,seed=seed,profile=profile,prefix=False,pending=None,events=[],instructions=0,sites=set());u.emu_start(cs*16+ip,0x11210,count=1000);label=f'{load:x}/{entry}/{seed:x}/{profile}/{same}/{flags:x}/{limit}';require(active['prefix'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original return '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
            def callback(ctx,memory,request,returned):
                try:
                    q=request.contents;events.append(event(q));rr,mutations=response(q,len(events)-1,seed,profile)
                    for at,payload in mutations:C.memmove(C.byref(bus,at),payload,len(payload))
                    C.memmove(returned,C.byref(rr),C.sizeof(StateRegisters));return 1
                except Exception as exc:errors.append(str(exc));return 0
            service=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),service,None,limit,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.calls==len(events) and events==active['events'],'Native service boundary '+label+str(errors));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Full bus/SS frame '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label)
            if not active['prefix']:require((out.next_segment,out.next_ip)==(0x1111,0x100),'Far return coordinate '+label)
            require(bytes(u.mem_read(ss*16+sp,len(frame)+len(tail)))==frame+tail,'Root args/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['service_calls']+=out.calls;coverage['prefix' if active['prefix'] else 'far_returns']+=1
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    require(sites==fence,'Unexercised wrapper sites '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_small_platform.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Five finite wrappers, explicit syntheticINT21/11/1A requests andfullreturnedGPR/BP/CFIFDF includingmutatedDS/BP, currentSSargumentrereads/fullbus/materializedBP/farreturnframes andnativebefore-callprefixes. Modeled servicecontrol preservesSS/SP/CS; UnicornINT hook andnativeadapter omitrealinterrupt-entry/returnframes andactualOS/BIOS/IRQ/devicebehavior. RawAL-byte/DL/AH/CL/order andcurrentDS52C2/4 masks/stores retained, nofrequency/unit orphysical086C semantics assigned. Realplatform/caller/writer/lifetime/fullstate/core/gameplay/fidelity andresource-fedP2/P3 remainopen; nativeinvalid/adapterfailure checks separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()
