"""Compare composed native6D50 to actual wrapper/cache/codec/metadata code.

Only synthetic DOS services execute. No supplied resource is read. Fatal
paths stop at16A7:0002. DS=SS and all byte pools are explicit profiles.
"""
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
from validate_cache_allocate import Entry,Arena,require
import validate_file_paragraphs as M
import validate_raw_load as R
from validate_packed_loader_composition import make_inner,make_two_pass
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','stage','acquire_event','allocation_event','offset','segment','allocation_paragraphs','raw_segment','passes','last_codec','final_si','final_di','codec_status']]+[('header',M.Result),('metadata',M.Result),('raw',R.Result)]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    library,output=a.library.resolve(),a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest()
    require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    flow_path=ROOT/'analysis/flow/indirect-v7/direct-flow.json';graph=json.loads(flow_path.read_text());ips=[0x6d50,0x71b4,0x7083,0x70a3,0x6aa2,0x6b02,0x6b97,0x6c6e,0x7c16,0x7030,0x6fe8,0x7147,0x5e1c,0x5e8a]
    functions=[f for f in graph['functions'] if f['entry'] in ['06C9:'+f'{ip:04X}' for ip in ips]];require(len(functions)==len(ips),'Missing code fence')
    dll=C.CDLL(str(library));native=dll.td2ega_packed_load
    native.argtypes=[C.POINTER(Arena),C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,M.Service,R.Service,C.c_void_p,C.POINTER(C.c_uint8),C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint32,C.c_uint32,C.POINTER(Result)];native.restype=None
    cases=[]
    for length in [1,16,17,127,255]:
        for run in [False,True]:
            inner,expected=make_inner(length,run)
            for passes in [1,2]:
                raw=inner if passes==1 else make_two_pass(inner,length)
                for mode in ['empty','hit_first','hit_second','hole','descriptor_full']:
                    for fail in ['none','header_open','header_read','metadata_open','raw_open','read0']:
                        for fill in [0xa5,0x3c]:cases.append((raw,length,passes,mode,fail,fill))
    # Invalid selectors exercise the original fatal edge, including after a
    # successful prefix stage has produced another unrecognized selector.
    for bad in [0,3,0x7f,0x80,0xff]:
        inner,_=make_inner(17,True);inner=bytes([bad])+inner[1:]
        for passes in [1,2]:
            raw=inner if passes==1 else make_two_pass(inner,17)
            cases.append((raw,17,passes,'empty','none',0xa5))
    # Outer count zero still executes one dispatch; high-bit count1 also stops
    # after one dispatch and retains its native count/far-pointer ABI value.
    for count in [0,1]:
        inner,_=make_inner(17,True);cases.append((bytes([0x80|count])+b'\x11\0\0'+inner,17,1,'empty','none',0x3c))
    coverage=Counter();vectors=instructions=0;table=0x68e2;origin=0x6100;pool_bytes=0x20000;sp=0xe000
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;ds=ss=load+0x178f
        relocated=bytearray(image)
        for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
        uc.mem_write(load*16,bytes(relocated));allowed={((load+int(f['entry'].split(':')[0],16))*16+ip) for f in functions for ip in f['instructions']};fatal=(load+0x16a7)*16+2;active={}
        def fetch(u,address,size,_):
            if address==fatal:
                active['fatal']=True;active['message']=struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0];u.emu_stop();return
            require(address in allowed,f'Instruction fence {address:x}');active['instructions']+=1
            for stage,(ip,frame) in enumerate([(0x71b4,22),(0x5e8a,22),(0x70a3,24),(0x5e1c,22),(0x6aa2,26)]):
                if address==cs*16+ip and u.reg_read(UC_X86_REG_SP)==sp-frame:active['stage']=stage
            if address==cs*16+0x6db0:active['stage']=5
        def service(model,op,handle,segment,offset,count,write):
            if op=='open':
                require((segment,offset)==(ds,0x120),'Filename coordinates');which=model['opens'];model['opens']+=1;model['position']=0;model['events'].append(['open',which])
                return (2,0,1) if active['fail']==['header_open','metadata_open','raw_open'][which] else (3+2*which,0,0)
            which=model['opens']-1;require(handle==3+2*which,'Handle flow')
            if op in ['end','rewind']:
                require(which==1 and count==offset==0,'Seek profile');model['events'].append([op,handle]);return (len(active['file']),0,active['carry']) if op=='end' else (5,0xabcd,active['carry'])
            if op=='read':
                require((which==0 and count==4) or (which==2 and count==0x4000),'Read count');model['events'].append(['read',handle,segment,offset,count]);model['reads']+=1
                if which==0 and active['fail']=='header_read':
                    data=active['file'][:3];write(segment*16+offset,data);return 3,0,active['carry']
                if which==2 and active['fail']=='read0':
                    write(segment*16+offset,b'\xd7'*active['partial']);return 5,0,1
                data=active['file'][model['position']:model['position']+count];model['position']+=len(data);write(segment*16+offset,data);return len(data),0,active['carry'] if which==0 else 0
            require(op=='close','Unknown service');model['events'].append(['close',handle]);return 5,0,active['carry']
        def interrupt(u,num,_):
            require(num==0x21,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);ah=ax>>8
            if ah==0x3d:require(ax&255==0,'Open mode');op='open'
            elif ah==0x42:require(ax&255 in [0,2] and u.reg_read(UC_X86_REG_CX)==0,'Seek mode');op='end' if ax&255==2 else 'rewind'
            else:require(ah in [0x3e,0x3f],'DOS service');op='close' if ah==0x3e else 'read'
            av,dv,cf=service(active['guest'],op,u.reg_read(UC_X86_REG_BX),u.reg_read(UC_X86_REG_DS),u.reg_read(UC_X86_REG_DX),u.reg_read(UC_X86_REG_CX),lambda at,data:u.mem_write(at,data) if data else None)
            u.reg_write(UC_X86_REG_AX,av)
            if op in ['end','rewind']:u.reg_write(UC_X86_REG_DX,dv)
            u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|cf)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for raw,length,passes,mode,fail,fill in cases:
            entries=[(b'\0'*12,0,origin,0) for _ in range(50)];entries[0]=(b'\0'*12,0,origin,2);entries[49]=(b'\0'*12,0,origin+pool_bytes//16,1);top,first=0,49
            if mode in ['hit_first','hit_second','hole']:
                first=47;entries[47]=((b'fixture' if mode=='hit_first' else b'OTHER').ljust(12,b'\0'),4,origin+0x100,0 if mode=='hole' else 1);entries[48]=((b'fixture' if mode in ['hit_second','hole'] else b'OTHER2').ljust(12,b'\0'),4,origin+0x104,1)
            if mode=='descriptor_full':
                top=48
                for i in range(1,49):entries[i]=(b'ACTIVE'.ljust(12,b'\0'),1,origin+i-1,2)
            packed=b''.join(struct.pack('<12sHHH',*e) for e in entries);initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed;initial[0x6c66:0x6c6e]=struct.pack('<4H',table,table+18*top,table+18*first,table+18*49);name=b'fixture\0'+b'\0'*12;initial[0x120:0x120+len(name)]=name
            pool=bytes((i*37+11)&255 for i in range(pool_bytes));uc.mem_write(origin*16,pool);uc.mem_write(ds*16,bytes(initial));uc.mem_write(ss*16+sp-0x800,bytes([fill])*0x808);uc.mem_write(ss*16+sp,struct.pack('<3H',0x100,0xa000,0x120))
            for reg,val in [(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6d50),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x3333),(UC_X86_REG_SI,0x2222),(UC_X86_REG_DI,0x4444),(UC_X86_REG_EFLAGS,0x202)]:uc.reg_write(reg,val)
            active.update(file=raw,fail=fail,carry=vectors&1,partial=3 if vectors&2 else 0,guest={'opens':0,'reads':0,'position':0,'events':[]},fatal=False,stage=0,instructions=0)
            uc.emu_start(cs*16+0x6d50,0xa0100,count=1000000)
            arena=Arena.from_buffer_copy(packed+struct.pack('<2H',top,first));memory=(C.c_uint8*pool_bytes).from_buffer_copy(pool);nb=(C.c_uint8*len(name)).from_buffer_copy(name);seed=(C.c_uint8*4)(fill,fill,fill,fill);model={'opens':0,'reads':0,'position':0,'events':[]};errors=[];header_bytes=bytearray([fill]*4)
            def write(at,data):
                require(origin*16<=at and at+len(data)<=origin*16+pool_bytes,'Native pool write');memory[at-origin*16:at-origin*16+len(data)]=data
            def metadata_cb(ctx,req,res):
                try:
                    q=req.contents;op={0:'open',1:'read',2:'close',3:'end',4:'rewind'}[q.operation]
                    def header_write(at,data):
                        require(bool(q.header_destination),'Header destination');C.memmove(q.header_destination,data,len(data));header_bytes[:len(data)]=data
                    # Coordinates of original header READ are stack-local;
                    # they are supplied to both event traces explicitly.
                    at=sp-0x1e if op=='read' else q.filename_offset if op=='open' else 0
                    av,dv,cf=service(model,op,q.handle,ds,at,q.count,header_write if op=='read' else write);res.contents.ax,res.contents.dx,res.contents.carry=av,dv,cf;return 1
                except Exception as e:errors.append(str(e));return 0
            def raw_cb(ctx,req,res):
                try:
                    q=req.contents;av,dv,cf=service(model,{0:'open',1:'read',2:'close'}[q.operation],q.handle,q.segment,q.offset,q.count,write);res.contents.ax,res.contents.carry=av,cf;return 1
                except Exception as e:errors.append(str(e));return 0
            mc,rc=M.Service(metadata_cb),R.Service(raw_cb);result=Result()
            native(C.byref(arena),memory,pool_bytes,origin,nb,len(name),ds,0x120,mc,rc,None,seed,fill*257,0x2222,0x4444,16,1000000,C.byref(result))
            label=f'{load:x}/{length}/{passes}/{mode}/{fail}/{fill:x}'
            require(not errors,'Native service '+label+str(errors));require(model==active['guest'],f'Service trace {label}: {model} != {active["guest"]}')
            require(result.status==int(active['fatal']) and result.stage==active['stage'],f'Status/stage {label}: {result.status}/{result.stage} vs {active["fatal"]}/{active["stage"]}')
            require(bytes(uc.mem_read(ds*16+table,900))==bytes(arena.entries),'Descriptor bytes '+label)
            require(bytes(uc.mem_read(ds*16+0x6c66,8))==struct.pack('<4H',table,table+18*arena.active_top,table+18*arena.cached_first,table+49*18),'Boundary words '+label)
            require(bytes(memory)==bytes(uc.mem_read(origin*16,pool_bytes)),'Full payload '+label)
            if active['fatal']:
                message={1:0x5d7a,2:0x6574 if result.allocation_event==1 else 0x654a,3:0x5d7a,4:0x64e0,5:0x6503}[result.stage];require(active['message']==message,'Fatal message '+label)
            else:
                require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP),uc.reg_read(UC_X86_REG_BP),uc.reg_read(UC_X86_REG_DS))==(0xa000,0x100,sp+4,0x3333,ds),'Far return '+label)
                require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX),uc.reg_read(UC_X86_REG_SI),uc.reg_read(UC_X86_REG_DI))==(result.offset,result.segment,result.final_si,result.final_di),'Return and shifted pops '+label)
            require(bytes(uc.mem_read(ss*16+sp+4,2))==struct.pack('<H',0x120),'Caller argument')
            coverage[mode]+=1;coverage['stage_'+str(result.stage)+'_status_'+str(result.status)]+=1;coverage['codec_passes_'+str(result.passes)]+=1;instructions+=active['instructions'];vectors+=1
    deps=['tools/validate_cache_allocate.py','tools/validate_file_paragraphs.py','tools/validate_raw_load.py','tools/validate_packed_loader_composition.py']
    record={'schema':1,'function_id':'FN-EGA-000173','result':'pass','vectors':vectors,'image_sha256':image_sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_packed_load.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'flow_sha256':hashlib.sha256(flow_path.read_bytes()).hexdigest(),'executed_entries':[f['entry'] for f in functions],'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Complete wrapper with actual listed original callees, synthetic serialized valid pool/DS=SS/codec/DOS profiles. Original ADDSP8, shifted SI/DI, count-vs-pointer returns and partial failure state preserved. No supplied resource decoded, actual DOS/IRQ/caller lifetime, full scratch-register/flag contract or game/fidelity acceptance. Native codec bounds/work diagnostics are outside original error equivalence.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
