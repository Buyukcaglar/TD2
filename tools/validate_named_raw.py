"""Compare complete6D18 and actual cache/metadata/raw callees to composed C.

Only DOS service responses and byte streams are synthetic. Fatal calls stop
at16A7:0002 before cleanup. No corpus file, IRQ or game session executes.
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
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','stage','acquire_event','allocation_event','offset','segment']]+[('metadata',M.Result),('raw',R.Result)]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();library=a.library.resolve();output=a.output.resolve()
    require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private library/fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    dll=C.CDLL(str(library));native=dll.td2ega_named_raw_load
    native.argtypes=[C.POINTER(Arena),C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,M.Service,R.Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];native.restype=None
    counts=Counter();vectors=0;instructions=0;spans=[]
    ds,ss,sp,table=0x5000,0x9000,0x8000,0x68e2
    cases=[]
    for mode in ['empty','miss','hit_first','hit_second','hole','descriptor_full','segment_zero']:
        for size in [0,1,15,16,17,0x3fff,0x4000,0x4001,0x8000,0x8001]:
            for fail in ['none','metadata_open','raw_open','read0','read1']:
                for name in [b'C:\\DIR\\FILE.BIN\0'+b'\0'*12,b'FILE\0'+b'\0'*12,b'file.bin\0'+b'\0'*12]:
                    if mode=='segment_zero' and size>0x100:continue
                    cases.append((mode,size,size,fail,name))
    cases += [('empty',0x20010,0,'none',b'FILE.BIN\0'+b'\0'*12)]
    cases += [('empty',declared,actual,'none',b'FILE.BIN\0'+b'\0'*12) for declared in [0,1] for actual in [0x4001,0x10001]]
    for load in [0x1000,0x2345]:
        uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);cs=load+0x6c9;fatal=(load+0x16a7)*16+2
        starts=set();active={}
        for ip,length in [(0x6d18,56),(0x71b4,191),(0x7083,32),(0x6fe8,72),(0x7147,109),(0x7030,83),(0x5e1c,110),(0x70a3,164),(0x6aa2,96)]:
            first=0x6c90+ip;code=bytearray(image[first:first+length])
            for r in relocs:
                if first<=r<first+length:struct.pack_into('<H',code,r-first,(struct.unpack_from('<H',code,r-first)[0]+load)&65535)
            uc.mem_write(cs*16+ip,bytes(code));starts.update(cs*16+i.address for i in Cs(CS_ARCH_X86,CS_MODE_16).disasm(code,ip))
            if load==0x1000:spans.append({'module_offset':first,'length':length,'unrelocated_sha256':hashlib.sha256(image[first:first+length]).hexdigest()})
        def fetch(u,address,size,_):
            if address==fatal:
                active['fatal']=True;active['message']=struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP)+4,2)))[0];u.emu_stop();return
            require(address in starts,f'Instruction fence {address:x}')
            active['instructions']+=1
            for stage,(ip,frame) in enumerate([(0x71b4,8),(0x5e1c,8),(0x70a3,10),(0x6aa2,12)]):
                if address==cs*16+ip and u.reg_read(UC_X86_REG_SP)==sp-frame:active['stage']=stage
        def service(model,op,handle,segment,offset,count,write):
            if op=='open':
                require((segment,offset)==(ds,0x120),'Filename coordinates')
                which=model['opens'];model['opens']+=1;model['events'].append(['open',which])
                fail=(active['fail']=='metadata_open' and which==0) or (active['fail']=='raw_open' and which==1)
                return (2,0,1) if fail else (5 if which==0 else 7,0,0)
            require(handle==(5 if model['opens']==1 else 7),'Handle provenance')
            if op in ['end','rewind']:
                require(model['opens']==1 and count==offset==0,'Metadata seek profile');model['events'].append([op,handle])
                return (active['declared']&65535,active['declared']>>16,active['seek_cf']) if op=='end' else (5,0xabcd,active['close_cf'])
            if op=='read':
                index=model['reads'];model['reads']+=1
                require(model['opens']==2 and count==0x4000 and offset==0,'Raw read profile')
                model['events'].append(['read',handle,segment,offset,count])
                if active['fail']=='read'+str(index):
                    write(segment*16+offset,b'\xd7'*active['partial']);return 5,0,1
                data=active['file'][model['position']:model['position']+count];model['position']+=len(data);write(segment*16+offset,data);return len(data),0,0
            require(op=='close','Unknown service');model['events'].append(['close',handle]);return 5,0,active['close_cf']
        def interrupt(u,num,_):
            require(num==0x21,'Unexpected interrupt');ax=u.reg_read(UC_X86_REG_AX);ah=ax>>8
            if ah==0x3d:require(ax&255==0,'Open mode');op='open'
            elif ah==0x42:require(ax&255 in [0,2] and u.reg_read(UC_X86_REG_CX)==0,'Seek mode');op='end' if ax&255==2 else 'rewind'
            else:require(ah in [0x3e,0x3f],'DOS service');op='close' if ah==0x3e else 'read'
            def write(at,data):
                require(active['origin']*16<=at and at+len(data)<=active['origin']*16+active['pool_bytes'],'Guest service write fence')
                if data:u.mem_write(at,data)
            av,dv,cf=service(active['guest'],op,u.reg_read(UC_X86_REG_BX),u.reg_read(UC_X86_REG_DS),u.reg_read(UC_X86_REG_DX),u.reg_read(UC_X86_REG_CX),write)
            u.reg_write(UC_X86_REG_AX,av)
            if op in ['end','rewind']:u.reg_write(UC_X86_REG_DX,dv)
            u.reg_write(UC_X86_REG_EFLAGS,(u.reg_read(UC_X86_REG_EFLAGS)&~1)|cf)
        uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
        for mode,declared,actual,fail,name in cases:
            origin=0 if mode=='segment_zero' else 0x6100;pool_bytes=0x2000 if mode=='segment_zero' else 0x20000
            entries=[(b'\0'*12,0,origin,0) for _ in range(50)];entries[0]=(b'\0'*12,0,origin,2);entries[49]=(b'\0'*12,0,origin+pool_bytes//16,1)
            top,first=0,49
            if mode in ['miss','hit_first','hit_second','hole']:
                first=47
                entries[47]=((b'FILE.BIN' if mode=='hit_first' else b'OTHER').ljust(12,b'\0'),4,origin+0x100,0 if mode=='hole' else 1)
                entries[48]=((b'FILE.BIN' if mode in ['hit_second','hole'] else b'OTHER2').ljust(12,b'\0'),4,origin+0x104,1)
            if mode=='descriptor_full':
                top=48
                for i in range(1,49):entries[i]=(b'ACTIVE'.ljust(12,b'\0'),1,origin+i-1,2)
            if mode=='segment_zero':first=48;entries[48]=(b'FILE.BIN'.ljust(12,b'\0'),4,0x1fc,1)
            packed=b''.join(struct.pack('<12sHHH',*e) for e in entries)
            initial=bytearray(b'\xcc'*65536);initial[table:table+900]=packed;initial[0x6c66:0x6c6e]=struct.pack('<4H',table,table+18*top,table+18*first,table+18*49);initial[0x120:0x120+len(name)]=name
            pool=bytes((i*37+11)&255 for i in range(pool_bytes));file=bytes((i*13+7)&255 for i in range(actual))
            uc.mem_write(origin*16,pool);uc.mem_write(ds*16,bytes(initial));uc.mem_write(ss*16+sp-256,b'\xa5'*256+struct.pack('<3H',0x100,0xa000,0x120))
            preserved=[(UC_X86_REG_DS,ds),(UC_X86_REG_SS,ss),(UC_X86_REG_BP,0x5678),(UC_X86_REG_SI,0x4567),(UC_X86_REG_DI,0x3456)]
            for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6d18),(UC_X86_REG_SP,sp),(UC_X86_REG_ES,0x6789),(UC_X86_REG_EFLAGS,0x603)]:uc.reg_write(reg,val)
            active.update(origin=origin,pool_bytes=pool_bytes,declared=declared,file=file,fail=fail,partial=7 if vectors&1 else 0,seek_cf=vectors&1,close_cf=(vectors>>1)&1,guest={'opens':0,'reads':0,'position':0,'events':[]},fatal=False,stage=0,instructions=0)
            uc.emu_start(cs*16+0x6d18,0xa0100,count=2000000)
            arena=Arena.from_buffer_copy(packed+struct.pack('<2H',top,first));memory=(C.c_uint8*pool_bytes).from_buffer_copy(pool);nb=(C.c_uint8*len(name)).from_buffer_copy(name);model={'opens':0,'reads':0,'position':0,'events':[]};errors=[]
            def write(at,data):
                require(origin*16<=at and at+len(data)<=origin*16+pool_bytes,'Native service write fence');memory[at-origin*16:at-origin*16+len(data)]=data
            def metadata_cb(ctx,req,res):
                try:
                    q=req.contents;op={0:'open',2:'close',3:'end',4:'rewind'}[q.operation]
                    av,dv,cf=service(model,op,q.handle,ds,q.filename_offset if op=='open' else 0,0,write);res.contents.ax,res.contents.dx,res.contents.carry=av,dv,cf;return 1
                except Exception as e:errors.append(str(e));return 0
            def raw_cb(ctx,req,res):
                try:
                    q=req.contents;av,dv,cf=service(model,{0:'open',1:'read',2:'close'}[q.operation],q.handle,q.segment,q.offset,q.count,write);res.contents.ax,res.contents.carry=av,cf;return 1
                except Exception as e:errors.append(str(e));return 0
            mc,rc=M.Service(metadata_cb),R.Service(raw_cb);result=Result()
            native(C.byref(arena),memory,pool_bytes,origin,nb,len(name),ds,0x120,mc,rc,None,16,C.byref(result))
            label=f'{load:x}/{mode}/{declared}/{actual}/{fail}/{name!r}'
            require(not errors,'Native service '+label+str(errors));require(model==active['guest'],'Service trace '+label)
            require(result.status==int(active['fatal']) and result.stage==active['stage'],f'Status/stage {result.status}/{result.stage} vs {active["fatal"]}/{active["stage"]} '+label)
            expected=bytearray(initial);expected[table:table+900]=bytes(arena.entries);expected[0x6c68:0x6c6c]=struct.pack('<2H',table+18*arena.active_top,table+18*arena.cached_first)
            require(bytes(uc.mem_read(ds*16,65536))==expected,'FullDS '+label);require(bytes(memory)==bytes(uc.mem_read(origin*16,pool_bytes)),'Full payload '+label)
            if active['fatal']:
                message=0x5d7a if result.stage==1 else (0x6574 if result.allocation_event==1 else 0x654a) if result.stage==2 else 0x64e0
                require(active['message']==message,'Fatal message '+label);counts['fatal_stage_'+str(result.stage)]+=1
            else:
                require((uc.reg_read(UC_X86_REG_CS),uc.reg_read(UC_X86_REG_IP),uc.reg_read(UC_X86_REG_SP))==(0xa000,0x100,sp+4),'Far return '+label)
                require(all(uc.reg_read(reg)==val for reg,val in preserved),'Preserved registers '+label)
                require((uc.reg_read(UC_X86_REG_AX),uc.reg_read(UC_X86_REG_DX))==(result.offset,result.segment),'Returned far pointer '+label)
                require(uc.reg_read(UC_X86_REG_EFLAGS)&0x400==0,'Final DF '+label)
                counts['normal_stage_'+str(result.stage)]+=1
            require(bytes(uc.mem_read(ss*16+sp+4,2))==struct.pack('<H',0x120),'Caller argument')
            counts[mode]+=1;instructions+=active['instructions'];vectors+=1
    dependencies=['tools/validate_cache_allocate.py','tools/validate_file_paragraphs.py','tools/validate_raw_load.py']
    record={'schema':1,'function_id':'FN-EGA-000172','result':'pass','vectors':vectors,'image_sha256':hashlib.sha256(image).hexdigest(),'executed_ranges':spans,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_named_raw.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in dependencies],'original_instructions_executed':instructions,'fixture_coverage':dict(counts),'limits':'Complete6D18 composition, actual listed callees, synthetic serialized valid cache pools/name/DOS profiles. Segment-zero acquisition, partial failures, ignored seek/close carry, file-growth overwrite included. No real file decoded; caller pool/lifetime/IRQ guards and platform integration remain open. Fatal cleanup is fenced.'}
    output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
