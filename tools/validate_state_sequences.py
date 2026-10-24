"""Compare3532/3643 control sequences, SS point access and actual5C98 body."""
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
from validate_state_messages import Registers,StateRegisters,Request,Service,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    fn=C.CDLL(str(library)).td2ega_state_sequence;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_int,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=[0x3532,0x3643];fenced=[f for f in g['functions'] if f['entry'] in ['06C9:'+f'{x:04X}' for x in entries+[0x5c98]]];require(len(fenced)==3,'Three sequence/helper fences');md=Cs(CS_ARCH_X86,CS_MODE_16);regids=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];active={};vectors=instructions=0;coverage=Counter();sites=set();sp=0xe000
    specs={0x3537:(2,2),0x356a:(2,2),0x3577:(2,4),0x3587:(2,2),0x35c4:(5,5),0x35e4:(1,1),0x360f:(1,1),0x3626:(2,2),0x3648:(2,2),0x5c9d:(2,2),0x366a:(2,2),0x367f:(2,2),0x368c:(2,4),0x369f:(2,2),0x36b7:(4,4)}
    cases=list(itertools.product(range(2),[0,1,2,7,128,255],range(4),range(5),[0,1]))
    cases += [(0,2,4,profile,same) for profile,same in itertools.product([0,2,3],[0,1])]
    for load in [0x1000,0x2345]:
        cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated
        for page in [ds,0x5000,0x9000]:base[page*16:page*16+65536]=bytes(65536)
        starts={cs*16+ip for f in fenced for ip in f['instructions']};calls={}
        for f in fenced:
            for c in f['calls']:
                ip=int(c['site'][5:],16);segment,target=[int(x,16) for x in c['target'].split(':')]
                if target==0x5c98 and segment==0x6c9:continue
                size=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).size;argc,live=specs.get(ip,(0,0));calls[cs*16+ip]=(ip,load+segment,target,ip+size,argc,live)
        def read_regs():
            flags=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regids],(flags>>9)&1,(flags>>10)&1),u.reg_read(UC_X86_REG_BP),flags&1)
        def code(cpu,address,size,_):
            if active.get('expected') and address==active['expected'][1]*16+active['expected'][2]:
                site,segment,target,ret,argc,live=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Sequence leaf far frame');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+4,live*2))) if live else [];q=Request(site,segment,target,argc,live,active['ss'],current,(C.c_uint16*10)(*(args+[0]*(10-live))),read_regs());active['expected']=None;active['pending']=(q,ret);u.emu_stop();return
            require(address in starts,'Sequence escaped fence');active['instructions']+=1;active['sites'].add(address-cs*16)
            if address in calls:active['expected']=calls[address]
        def interrupt(*_):raise RuntimeError('Unexpected interrupt')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,interrupt)
        for entry,count,pattern,profile,same in cases:
            ss=ds if same else 0x9000;data=bytearray(base)
            for row in range(7):
                bp=0xfff0 if pattern==4 and row==0 else 0x4000+row*0x800
                for index in range(256):
                    high1,high2=[(0x12,0x13),(0x13,0x12),(0x92,0x93),(0xff,0)][pattern%4];x=((high1<<8)|((index*17+row)&255));y=((high2<<8)|((index*37+row)&255))
                    for at,value in [((bp+4*index)&65535,x),((bp+4*index+2)&65535,y)]:struct.pack_into('<H',data,ss*16+at,value)
                struct.pack_into('<H',data,ss*16+0x2c9e+2*row,bp);data[ss*16+0x2e22+row]=count if row==0 or count in [1,2,7] else 1
            for page in [ds,0x5000]:
                for at in range(0x22da,0x2308,2):struct.pack_into('<H',data,page*16+at,(at*3+page)&65535)
                for at in [0x3008,0x300a,0x300c,0x300e,0x2fd8,0x2fda,0x536c,0x536e]:struct.pack_into('<H',data,page*16+at,(at+count+page)&65535)
                data[page*16+0x2e29]=3
            frame=struct.pack('<2H',0x100,0x1111);data[ss*16+sp-64:ss*16+sp+8]=b'\xa5'*64+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
            for reg,val in list(zip(regids,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entries[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
            def model():return {'events':[],'draws':0}
            def service(model,read,write,q):
                index=len(model['events'])+1;r=q.incoming.registers;event=[q.site,q.segment,q.offset,q.argument_count,q.live_argument_count,q.stack_segment,q.stack_sp,list(q.arguments),values(r),q.incoming.bp,q.incoming.carry,read(r.ds*16+0x2e29,1).hex()];returned=StateRegisters(Registers(*values(r)),q.incoming.bp,q.incoming.carry);rr=returned.registers
                rr.ax=(0xa000+index)&65535;rr.bx=(0xb000+index)&65535;rr.cx=(0xc000+index)&65535;rr.dx=(0xd000+index)&65535;rr.es=0x6000;returned.carry=index&1;rr.interrupts_enabled=(index>>1)&1;rr.direction=(index>>2)&1
                if q.site in [0x3537,0x3648]:rr.si=0x5555
                if profile==1 and q.site in [0x3537,0x3648]:rr.ds=0x5000
                if q.site==0x35c4:model['draws']+=1
                if profile==2 and ((q.site==0x35c4 and model['draws']==1) or q.site==0x367f):rr.ds=0x5000
                if profile==3 and q.site in [0x35c4,0x36cd]:write(rr.ds*16+0x2e29,b'\x01')
                if profile==4 and q.site in [0x35ed,0x35f2,0x35f7,0x35fc]:rr.di=0x9000+index;rr.si=0xaaaa;returned.bp=0xbbbb
                if profile==4 and q.site==0x36cd:rr.si=0xaaaa;returned.bp=0xbbbb
                write(0x80000+(index%2048)*2,struct.pack('<H',q.site));return event,returned
            active.update(expected=None,pending=None,ss=ss,instructions=0,sites=set(),model=model());u.emu_start(cs*16+entries[entry],0x11210,count=100000)
            while active['pending']:
                q,ret=active['pending'];active['pending']=None;require(len(active['model']['events'])<4096,'Finite sequence fixture');event,returned=service(active['model'],lambda at,n:bytes(u.mem_read(at,n)),lambda at,b:u.mem_write(at,b),q);active['model']['events'].append(event);rr=returned.registers
                for reg,val in list(zip(regids,values(rr)[:8]))+[(UC_X86_REG_BP,returned.bp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ret),(UC_X86_REG_SP,q.stack_sp+4),(UC_X86_REG_EFLAGS,2|returned.carry|(rr.interrupts_enabled<<9)|(rr.direction<<10))]:u.reg_write(reg,val)
                u.emu_start(cs*16+ret,0x11210,count=100000)
            label=f'{load:x}/{entry}/{count}/{pattern}/{profile}/{same}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,sp+4),'Original farreturn '+label);gb=(C.c_uint8*len(data)).from_buffer_copy(data);native_model=model();errors=[]
            def callback(ctx,m,q,r):
                try:event,returned=service(native_model,lambda at,n:bytes(gb[at:at+n]),lambda at,b:C.memmove(C.byref(gb,at),b,len(b)),q.contents);native_model['events'].append(event);C.memmove(r,C.byref(returned),C.sizeof(returned));return 1
                except Exception as e:errors.append(str(e));return 0
            cb=Service(callback);result=Result();fn(gb,len(gb),load,ss,sp,entry,C.byref(incoming),cb,None,4096,C.byref(result));require(not errors and result.status==0 and native_model==active['model'],'Sequence leaf events '+label+str(errors));require(result.current_sp==sp+4 and result.calls==len(native_model['events']),'Native stack/calls '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(gb);actual[ss*16+sp-64:ss*16+sp]=expected[ss*16+sp-64:ss*16+sp];require(actual==expected,'Full nonframebus '+label);r=result.returned;require([u.reg_read(reg) for reg in regids]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Returned registers '+label);require((u.reg_read(UC_X86_REG_EFLAGS)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1,(u.reg_read(UC_X86_REG_EFLAGS)>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,8))==frame+b'\xa5'*4,'Rootframe/guard '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'{entries[entry]:04X}']+=1;coverage['leaf_calls']+=result.calls;coverage['same_DS_SS_'+str(same)]+=1;coverage['zero_count256']+=int(entry==0 and count==0 and profile!=3);coverage['point_offset_wrap']+=int(pattern==4)
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ids=[next(r['id'] for r in registry if r['entries'][0].get('segment')==0x6c9 and r['entries'][0].get('segment_offset')==ip) for ip in entries];require(len(sites)==len(starts),'Every sequence/helper instruction location exercised')
    record={'schema':1,'result':'pass','function_ids':ids,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_state_sequences.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_messages.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_messages.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(starts),'fixture_coverage':dict(coverage),'limits':'Complete3532/3643 plusactual5C98 instruction/nativecomposition; SS count/point tables versusDSglobals, CBW onlyfirstcoordinate andretainedAHsecond, bytezero256iterations, offsetwrap, seven/ten control loops, pairedargumentlifetimes, savedDI/SI andreturnedDS/CFIFDF retained. Mostfarcallees ABI mocks; actualgraphics/text/resources/timing/input/IRQ/statewriter/core/game/fidelity pending. Native diagnostics separate.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','function_ids','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
