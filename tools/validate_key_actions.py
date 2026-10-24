"""Compare six installed key callbacks with explicit external UI ABI services."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_music_tick import Registers,Result,require
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Request(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['segment','offset','argument_count']]+[('arguments',C.c_uint16*3),('registers',Registers)]


Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(Registers))


def values(r):return [getattr(r,n) for n,_ in Registers._fields_]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));fn=dll.td2ega_key_action_apply;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_int,C.POINTER(Registers),Service,C.c_void_p,C.POINTER(Result)];fn.restype=None
    entries=[0x645a,0x646f,0x6488,0x64c7,0x6508,0x6518];graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fenced=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{ip:04X}' for ip in entries]];require(len(fenced)==6,'Six callback fences');regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];coverage=Counter();vectors=instructions=0;sites=set();active={};md=Cs(CS_ARCH_X86,CS_MODE_16)
    for load in [0x1000,0x2345]:
        cs,ds,ss,sp=load+0x6c9,load+0x178f,0x9000,0x8000;uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);base=bytearray(0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base[load*16:load*16+len(relocated)]=relocated;starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            for call in f['calls']:
                ip=int(call['site'].split(':')[1],16);segment,offset=[int(v,16) for v in call['target'].split(':')];ins=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1));calls[cs*16+ip]=((load+segment)*16+offset,ip+ins.size,3 if (segment,offset)==(0x16fc,0x220) else 0,load+segment,offset)
        def fetch(u,address,size,_):
            if active.get('expected') and address==active['expected'][0]:
                target,ret,argc,segment,offset=active['expected'];current_sp=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(ss*16+current_sp,4))==struct.pack('<2H',ret,cs),'UI far frame');args=list(struct.unpack('<'+'H'*argc,u.mem_read(ss*16+current_sp+4,2*argc))) if argc else [];fl=u.reg_read(UC_X86_REG_EFLAGS);r=Registers(*[u.reg_read(reg) for reg in regids],(fl>>9)&1,(fl>>10)&1);q=Request(segment,offset,argc,(C.c_uint16*3)(*(args+[0]*(3-argc))),r);active['pending']=(q,current_sp,ret);u.emu_stop();return
            require(address in starts,'Key action escaped instruction fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for mode in range(256):
            for action,entry in enumerate(entries):
                for profile in range(4):
                    data=bytearray(base);data[ds*16+0x5efb]=mode;data[ds*16+0x5efc]=0xff;data[ds*16+0x5efe]=[0,1,0x55,0xff][mode>>6];data[ds*16+0x6cfc]=0x80;struct.pack_into('<H',data,ds*16+0x5eee,0x5678);data[0x50000+0x5efe]=0x66;data[ss*16+sp-16:ss*16+sp+8]=b'\xa5'*16+struct.pack('<2H',0x100,0x1111)+b'\xa5'*4;uc.mem_write(0,bytes(data));flags=2|((mode&1)<<9)|(((mode>>1)&1)<<10);incoming=Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1)
                    for reg,val in list(zip(regids,values(incoming)[:8]))+[(UC_X86_REG_BP,0x5678),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry),(UC_X86_REG_EFLAGS,flags)]:uc.reg_write(reg,val)
                    def service(read,write,q):
                        segment=q.registers.ds;observed=[read(segment*16+at,1)[0] for at in [0x5efb,0x5efc,0x5efe,0x6cfc]]+[struct.unpack('<H',read(segment*16+0x5eee,2))[0]];event=[q.segment,q.offset,q.argument_count,list(q.arguments),values(q.registers),observed];r=Registers(*values(q.registers));r.ax=0xdead;r.bx=0xbeef;r.cx=0xcafe;r.dx=0xface;r.si=0xaaaa;r.di=0xbbbb;r.es=0x6000;r.ds=0x5000 if profile&1 else segment;r.interrupts_enabled=(profile>>1)&1;r.direction=profile&1;write(segment*16+0x5efe,b'\x77');write(r.ds*16+0x5efe,b'\x88');return event,r
                    active.update(expected=None,pending=None,instructions=0,sites=set());uc.emu_start(cs*16+entry,0x11210,count=128);require(active['pending'] is not None,'Missing UI ABI call');q,current_sp,ret=active['pending'];guest_event,returned=service(lambda at,n:bytes(uc.mem_read(at,n)),lambda at,b:uc.mem_write(at,b),q)
                    for reg,val in list(zip(regids,values(returned)[:8]))+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,current_sp+4),(UC_X86_REG_EFLAGS,2|(returned.interrupts_enabled<<9)|(returned.direction<<10))]:uc.reg_write(reg,val)
                    active['expected']=None;uc.emu_start(cs*16+ret,0x11210,count=128);label=f'{load:x}/{mode}/{action}/{profile}';require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original far return '+label)
                    gb=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
                    def callback(ctx,m,qptr,rptr):
                        try:event,r=service(lambda at,n:bytes(gb[at:at+n]),lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),qptr.contents);events.append(event);C.memmove(rptr,C.byref(r),C.sizeof(r));return 1
                        except Exception as e:errors.append(str(e));return 0
                    cb=Service(callback);result=Result();fn(gb,len(data),load,action,C.byref(incoming),cb,None,C.byref(result));require(not errors and result.status==0 and events==[guest_event],'Native UI ABI/event '+label+str(errors));actual=bytearray(uc.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-16:ss*16+sp]=expected[ss*16+sp-16:ss*16+sp];require(actual==expected,'Full nonstack bus '+label)
                    r=result.registers;require([uc.reg_read(reg) for reg in regids]==values(r)[:8],'Registers '+label);require(((uc.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(uc.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.interrupts_enabled,r.direction),'IF/DF '+label);require(uc.reg_read(UC_X86_REG_BP)==0x5678 and uc.reg_read(UC_X86_REG_SS)==ss,'BP/SS '+label);require(bytes(uc.mem_read(ss*16+sp,8))==struct.pack('<2H',0x100,0x1111)+b'\xa5'*4,'Frame/upperguard '+label);coverage[f'{entry:04X}']+=1;instructions+=active['instructions'];sites.update(active['sites']);vectors+=1
    record={'schema':1,'function_ids':[f'FN-EGA-{i:06}' for i in range(404,410)],'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_key_actions.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_music_tick.py','sha256':hashlib.sha256((ROOT/'tools/validate_music_tick.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':sum(len(f['instructions']) for f in fenced),'limits':'Six serializedkeycallbacks onsyntheticfullbus; allmodebytes/guardprofiles, UI3wordcaller-clean/noargumentfarframes, callbackDS/ES/SI/DI/IF/DF changes andguardclearthroughreturnedDS retained. ExternalUI bodies areABImocks; no actualdisplay/input/BIOS/IRQ/guard-exclusion/game/fidelity acceptance. Nativeinvalid/adapterdiagnostics separate; incidental arithmeticflags/SS/BP-changingadapters outsideprofile.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
