"""Actual runtime lookup/dispatch/wrapper plus original message and exit bodies."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_runtime_exit import Registers,StateRegisters,DOSRequest,DOSService,CallbackRequest,CallbackService,require,values
from validate_timer_handler_bus import ww,rw
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[0x2d57,0x2c1c,0x29f6];FAMILY_NAMES=['13A8:2D57','13A8:2C1C','13A8:29F6'];CHILD_NAMES=['13A8:0599','13A8:060D','13A8:066E','13A8:0620','13A8:088C','13A8:08B7','13A8:05E0'];FAMILY_CALLS={0x2c42:(1,0x2c47),0x2c83:(2,0x2c86),0x2c93:(3,0x2c98),0x2c9c:(4,0x2ca1),0x29fd:(5,0x2a02),0x2a06:(6,0x2a0b),0x2a0f:(7,0x2a14)};FAMILY_STEPS={0x2d57,0x2d61,0x2c1c,0x2c2b,0x2c31,0x2c64,0x2c67,0x2c78,0x2c7a,0x29f6};UNREACHED={0x611,0x614,0x616,0x619,0x61b,0x61d,0x2a14,0x2a16,0x2a17};ARITH=0x8d5
class Request(C.Structure):_fields_=[(n,C.c_uint16) for n in ['kind','site','target_segment','target_ip','stack_segment','stack_sp','flags_word','flags_mask']]+[('incoming',StateRegisters)]
class Response(C.Structure):_fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip','flags_word','flags_mask']]+[('bus_writes',C.c_uint32),('returned',StateRegisters),('exit_request',DOSRequest)]
Handler=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.c_uint32,C.POINTER(Request),C.POINTER(Response))
class Services(C.Structure):_fields_=[('dos',DOSService),('handler',Handler),('finalizer',CallbackService),('context',C.c_void_p)]
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['steps','calls','message_operations','exit_operations']]
class Result(C.Structure):_fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','services','callbacks','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','stage','halt_site','raw_target','raw_segment']]+[('returned',StateRegisters),('exit_request',DOSRequest)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require((C.sizeof(Request),C.sizeof(Response),C.sizeof(Result),C.sizeof(Limits),C.sizeof(Services))==(40,76,100,16,32),'Layouts')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fs=[f for f in g['functions'] if f['entry'] in FAMILY_NAMES+CHILD_NAMES];family={ip for f in fs if f['entry'] in FAMILY_NAMES for ip in f['instructions']};fence={ip for f in fs for ip in f['instructions']};require(len(family)==97 and len(fence)==228,'97family-228union');md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x13a80+ip:0x13a80+ip+15],ip,count=1)) for ip in fence};return_sites={ip for ip,i in decoded.items() if i.mnemonic in ['ret','retf']};call_sizes={int(c['site'][5:],16):c['size'] for f in fs for c in f['calls']};call_sizes.update({0x633:4,0x5e9:4,0x2c83:3,0x2c93:5});cleanup_calls={0x68a,0x627,0x63b,0x8be,0x29fd}
    fn=C.CDLL(str(lib)).td2ega_runtime_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=0,arg=0,ax=0xa500,same=False,ss=None,sp=0xe000,flags=2,mask=65535,kind='default',mode=0,platform=0,checksum=0,fallback=True,keys=None,jump=None,steps=32,calls=8,msg_ops=128,exit_ops=128,tag='base');c.update(kw);return c
    cases=[case(ax=0xa500|v,flags=f,same=same) for v,f,same in itertools.product(range(256),[2,0x643],[False,True])]
    cases +=[case(entry=1,arg=arg,kind=kind,flags=f,same=same,mode=mode,platform=profile,tag='dispatch') for arg,kind,f,same,mode,profile in itertools.product([0,2,4,8,11,15,22,0x108,0x116,0xffff],['default','ignore','custom'],[2,0x643],[False,True],range(3),range(2))]
    cases +=[case(entry=2,kind=kind,flags=f,same=same,mode=mode,platform=profile,checksum=check,tag='wrapper') for kind,f,same,mode,profile,check in itertools.product(['default','ignore','custom'],[2,0x643],[False,True],range(3),range(2),[0,1])]
    cases +=[case(entry=e,arg=22,ax=22,kind=kind,steps=steps,calls=calls,same=same,tag='family_budget') for e,kind,steps,calls,same in itertools.product(range(3),['default','custom'],[0,1,2,4,7,12,32],range(5),[False,True])]
    cases +=[case(entry=e,arg=22,ax=22,kind='custom',same=True,sp=sp,flags=f,tag='SS_state_alias') for e,sp,f in itertools.product(range(3),[100,0x7054,0x7058,0x7060,0x706c,0x7074,0x7076,0x707e,0x7082,0x7086,0x82c4,0x82c8,0xa3ce,0xffe0],[2,0x643])]
    cases +=[case(ss='code',sp=sp,ax=arg,tag='CS_key_frame_alias') for sp,arg in itertools.product([0x2cb0,0x2cb1,0x2cb2,0x2cb3,0x2cb4,0x2cb6],[2,4,8,11,15,22,0x56,0x78])]
    cases +=[case(entry=1,arg=arg,jump=target,tag='literal_CS_dispatch') for arg,target in itertools.product([4,8,11,15,22],[0x2c90,0x2c98,0x2ca7,0x2ca1,0])]
    cases +=[case(entry=1,arg=8,kind=kind,fallback=False,tag='guard_before_lookup') for kind in ['default','ignore','custom']]
    cases +=[case(entry=e,arg=22,ax=22,steps=steps,mask=mask,tag='partial_flags') for e,steps,mask in itertools.product(range(3),[0,1,32],[0xffef,0xf72b,0xf72a])]
    vectors=instructions=synthetic=0;sites=set();boundaries=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,principal=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[0xa2010]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def state():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def fields(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
        def dos_effect(r,site,vector):
            returned=StateRegisters.from_buffer_copy(bytes(r));returned.carry=active['c']['platform'];returned.registers.ax=0x1234 if vector==0x23 else 0
            if active['c']['platform']:returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            return returned
        def callback_effect(r,site,ss,sp,mode):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if mode==1:returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.si=0x3456;returned.registers.di=0x4567;returned.registers.es=0x6000;returned.carry^=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if mode==2:mutations.append((ss,sp,0x4444))
            return returned,mutations
        def apply(r,mutations):
            for reg,v in zip(REGS,values(r.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,r.bp);u.reg_write(UC_X86_REG_EFLAGS,2|r.carry|(r.registers.interrupts_enabled<<9)|(r.registers.direction<<10));active['mask']=0xf72b
            for sg,o,v in mutations:ww(backing,sg,o,v)
        def code(cpu,address,size,_):
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if active.get('synthetic_stepping'):return
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if active.get('foreign'):
                expected=active['foreign'];require((segment,ip)==expected[:2],'Actualforeignentry');active['foreign_entry']=state();active['foreign_flags']=u.reg_read(UC_X86_REG_EFLAGS)&65535;active['foreign_mask']=active['mask'];active['ret_kind']='handler' if expected[2] in [0x2c83,0x2c93] else 'finalizer';u.emu_stop();return
            require(segment==cs and ip in fence and ip not in UNREACHED,'Runtimefamilyfence '+hex(address))
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            if ip in FAMILY_STEPS:
                if active['steps']==active['c']['steps']:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['steps']+=1
            if ip in FAMILY_CALLS:
                if active['calls']==active['c']['calls']:active['status']=3;active['halt']=ip;u.emu_stop();return
                active['calls']+=1
            if ip==0x2c5f:
                target=rw(backing,cs,u.reg_read(UC_X86_REG_BX)+0x2c10)
                if target not in [0x2c90,0x2c98,0x2ca7,0x2ca1]:active['status']=6;active['halt']=ip;active['raw']=(target,cs);u.emu_stop();return
            legacy_operation=ip in [0x677,0x899,0x633,0x5e9,0x8d9,0x5f5,0x609,0x5c8,0x5d1,0x5de] or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX)!=0)
            if legacy_operation:
                field='message_operations' if active['stage']==5 else 'exit_operations';limit=active['c']['msg_ops' if active['stage']==5 else 'exit_ops']
                if active[field]==limit:active['status']=3;active['halt']=ip;u.emu_stop();return
                active[field]+=1
            if ip in [0x2c31,0x5de]:active['status']=5;active['halt']=ip;active['exit_request']=DOSRequest(0x21,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),state());boundaries.add(ip);u.emu_stop();return
            if ip in return_sites:active['ret_kind']='original';active['ret_ip']=ip;u.emu_stop();return
            if ip in call_sizes:
                parent=active['stage'];ret=ip+call_sizes[ip];stage=FAMILY_CALLS[ip][0] if ip in FAMILY_CALLS else parent
                active['frames'].append((cs,ret,(u.reg_read(UC_X86_REG_SP)+(2 if ip in cleanup_calls else 0))&65535,parent,ip));active['stage']=stage
                if ip in [0x29fd,0x2c9c,0x2a0f]:active['message_operations']=active['exit_operations']=0
                if ip in [0x2c83,0x2c93,0x633,0x5e9]:
                    if ip==0x2c83:o=rw(backing,active['ss'],u.reg_read(UC_X86_REG_BP)-4);s=rw(backing,active['ss'],u.reg_read(UC_X86_REG_BP)-2)
                    elif ip==0x2c93:o=rw(backing,active['ss'],0x707e);s=rw(backing,active['ss'],0x7080)
                    elif ip==0x633:o=rw(backing,u.reg_read(UC_X86_REG_DS),0x6dcc);s=rw(backing,u.reg_read(UC_X86_REG_DS),0x6dce)
                    else:o=rw(backing,u.reg_read(UC_X86_REG_DS),0x7076);s=rw(backing,u.reg_read(UC_X86_REG_DS),0x7078)
                    active['foreign']=(s,o,ip)
            mnemonic=decoded[ip].mnemonic
            if mnemonic in ['cmp','sub','add','neg']:active['pending_mask']=active['mask']|ARITH
            elif mnemonic in ['inc','dec']:active['pending_mask']=active['mask']|(ARITH^1)
            elif mnemonic in ['or','and','xor','test','shl','shr']:active['pending_mask']=(active['mask']|ARITH)&0xffef
            elif mnemonic in ['stc','clc']:active['pending_mask']=active['mask']|1
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,_):active['writes']+=1
        def interrupt(cpu,number,_):
            ip=u.reg_read(UC_X86_REG_IP)-2;require(number in [0x21,0x23] and ip in [0x2c2b,0x5d1,0x8d9,0x5f5,0x609],'Explicitplatformboundary');r=state();active['dos'].append(fields(DOSRequest(number,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),r)));apply(dos_effect(r,ip,number),[])
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        for c in cases:
            ds=principal;ss=cs if c['ss']=='code' else c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];data=bytearray(base)
            for sg in [ds,ds+0x100]:data[sg*16:sg*16+65536]=bytes(65536)
            for sg in [ds,ds+0x100]:
                data[sg*16]=0x55^c['checksum'];cursor=0x82c4
                for key in [0xa,0xfc,0xff,1]:ww(data,sg,cursor,key);cursor+=2;data[sg*16+cursor:sg*16+cursor+3]=b'AB\0';cursor+=3
                ww(data,sg,cursor,0xffff);ww(data,sg,0x6d89,0x1234);ww(data,sg,0x6d8b,0x7000);ww(data,sg,0x6dc8,0x5678);ww(data,sg,0x6dca,0x7100)
                for slot in range(6):ww(data,sg,0x7058+4*slot,0 if c['kind']=='default' else 1 if c['kind']=='ignore' else 0x100);ww(data,sg,0x705a+4*slot,0xa000 if c['kind']=='custom' else 0)
                ww(data,sg,0x7076,0x100 if c['fallback'] else 0);ww(data,sg,0x7078,0xa100 if c['fallback'] else 0);ww(data,sg,0x6dcc,0x100);ww(data,sg,0x6dce,0 if c['checksum']==0 else 0xa100)
            ww(data,ss,0x707e,0x100);ww(data,ss,0x7080,0xa000);ww(data,ss,sp,0x1111);ww(data,ss,sp+2,0x2222);ww(data,ss,sp+4,c['arg'])
            if c['jump'] is not None:
                for slot in range(6):ww(data,cs,0x2c10+2*slot,c['jump'])
            if c['keys'] is not None:data[cs*16+0x2cae:cs*16+0x2cb4]=bytes(c['keys'])
            incoming=StateRegisters(Registers(c['ax'],0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.clear();active.update(c=c,ss=ss,steps=0,calls=0,stage=0,mask=c['mask'],writes=0,instructions=0,sites=set(),frames=[],foreign=None,ret_kind=None,status=0,halt=0,raw=(0,0),dos=[],handlers=[],finalizers=[],message_operations=0,exit_operations=0,exit_request=None);root=False
            u.emu_start(cs*16+ENTRIES[c['entry']],0,count=200000)
            while active['ret_kind']:
                kind=active['ret_kind'];active['ret_kind']=None
                if kind!='original':
                    s,o,site=active['foreign'];qsp=u.reg_read(UC_X86_REG_SP);r=active['foreign_entry'];mode=c['mode'] if kind=='handler' else 0;ret,mutations=callback_effect(r,site,ss,qsp,mode)
                    if kind=='handler':active['handlers'].append((site,s,o,qsp,bytes(r),active['foreign_flags'],active['foreign_mask']))
                    else:active['finalizers'].append([site,s,o,ss,qsp,*values(r.registers),r.bp,r.carry])
                    apply(ret,mutations);active['foreign']=None;active['halt']=site;u.reg_write(UC_X86_REG_CS,0xa200);u.reg_write(UC_X86_REG_IP,0x10);active['synthetic_stepping']=True;u.emu_start(0xa2010,0,count=1);active['synthetic_stepping']=False;synthetic+=1
                else:
                    ip=active['ret_ip'];active['halt']=ip
                    if ip in [0x2d7e,0x2cac] and u.reg_read(UC_X86_REG_SP)>0xfffc:active['status']=7;break
                    active['stepping']=True;u.emu_start(cs*16+ip,0,count=1);active['stepping']=False
                if not active['frames']:root=True;active['stage']=0;break
                frame=active['frames'].pop();now=(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))
                if now!=frame[:3]:active['status']=1;break
                if frame[4]==0x29fd:active['mask']=0xf72b
                active['stage']=frame[3];u.emu_start(now[0]*16+now[1],0,count=200000)
            require(root or active['status'],'Qualifiedruntimeoutcome');bus=(C.c_uint8*len(data)).from_buffer_copy(data);native_dos=[];native_handlers=[];native_finalizers=[];errors=[]
            def dos_service(ctx,memory,qptr,rptr):
                q=qptr.contents;native_dos.append(fields(q));rptr[0]=dos_effect(q.incoming,q.site,q.vector);return 1
            def handler_service(ctx,memory,bytes_count,qptr,rptr):
                try:
                    q=qptr.contents;require(q.kind==(0 if q.site==0x2c83 else 1) and q.stack_segment==ss and bytes_count==len(data),'Handlerkind-SS-bussize');index=len(native_handlers);expected=active['handlers'][index];require((q.site,q.target_segment,q.target_ip,q.stack_sp,bytes(q.incoming))==expected[:5],'Actualhandlerrequest');require(q.flags_mask==expected[6] and q.flags_word&q.flags_mask==expected[5]&q.flags_mask,'HandlerdefinedFLAGS');native_handlers.append(expected);returned,mutations=callback_effect(q.incoming,q.site,ss,q.stack_sp,c['mode'])
                    for sg,o,v in mutations:ww(memory,sg,o,v)
                    r=rptr.contents;r.status=0;r.current_sp=(q.stack_sp+4)&65535;r.next_ip=rw(memory,ss,q.stack_sp);r.next_segment=rw(memory,ss,q.stack_sp+2);r.flags_word=2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10);r.flags_mask=0xf72b;r.returned=returned;return 1
                except Exception as error:errors.append(str(error));return 0
            def finalizer_service(ctx,memory,qptr,rptr):
                q=qptr.contents;native_finalizers.append([q.site,q.target_segment,q.target_ip,q.stack_segment,q.stack_sp,*values(q.incoming.registers),q.incoming.bp,q.incoming.carry]);rptr[0]=callback_effect(q.incoming,q.site,ss,q.stack_sp,0)[0];return 1
            dsrv=DOSService(dos_service);hsrv=Handler(handler_service);fsrv=CallbackService(finalizer_service);services=Services(dsrv,hsrv,fsrv,None);caps=Limits(c['steps'],c['calls'],c['msg_ops'],c['exit_ops']);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],flags,c['mask'],C.byref(incoming),C.byref(caps),C.byref(services),C.byref(r));label=str((load,c))
            if active['stage'] in [4,5,7]:active['mask']=0xf72b
            require(not errors and native_dos==active['dos'] and native_handlers==active['handlers'] and native_finalizers==active['finalizers'],'Wholefamilyservices '+label+str(errors));observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.calls,r.services,r.callbacks,r.bus_writes,r.stage,r.raw_target,r.raw_segment);expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['calls'],len(active['dos']),len(active['handlers'])+len(active['finalizers']),active['writes'],active['stage'],*active['raw']);require(observed==expected,'Runtimecontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'WholefamilyRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'RuntimeGPR-BP '+label);ef=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'RuntimeCFIFDF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==ef&r.flags_mask,'RuntimeFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(ef),hex(active['mask']))))
            if active['exit_request'] is not None:require(fields(r.exit_request)==fields(active['exit_request']),'Preparedrequest '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['stage_'+str(r.stage)]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['DOSservices']+=r.services;coverage['handler_callbacks']+=len(native_handlers);coverage['finalizer_callbacks']+=len(native_finalizers);coverage['root_returns_changed']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['DS_equals_SS']+=int(ds==ss)
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%2048==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    admitted_family=family-{0x2a14,0x2a16,0x2a17,0x2c31};require(admitted_family.issubset(sites) and boundaries=={0x2c31,0x5de},'All93family-sites-andtwoexitboundaries '+str(sorted(admitted_family-sites)))
    deps=['tools/validate_runtime_exit.py','tools/validate_runtime_message.py','tools/validate_finalizer_list.py','tools/validate_line_draw.py','tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/runtime-dispatch-bus-build-setup-v1.json','analysis/history/runtime-dispatch-bus-validation-refinement-v2.json','analysis/reviews/session-caller-bus-frontier-v1.json','docs/recovery/evidence/td2ega-runtime-exit-validation-v1.json','docs/recovery/evidence/td2ega-runtime-message-validation-v1.json']
    record={'schema':1,'result':'pass','function_ids':['FN-EGA-000340','FN-EGA-000339','FN-EGA-000332'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_dispatch_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':228,'instruction_sites_exercised':len(sites),'family_instruction_sites_in_fence':97,'family_instruction_sites_admitted':93,'family_instruction_sites_exercised':len(admitted_family&sites),'prepared_exit_boundary_sites':['13A8:2C31','13A8:05DE'],'postterminal_wrapper_sites_not_followed':['13A8:2A14','13A8:2A16','13A8:2A17'],'synthetic_callback_RETF_instructions':synthetic,'fixture_coverage':dict(coverage),'limits':'Actual2D57-2C1C-29F6/fullSS-GPR-BP-CFIFDF-definedFLAGS/literalcurrentCSkeys-andnearworddispatch/SS707Efallback/actualcallee message-exit bodies/callerargumentcleanup/typedretiredhandlers-wholeRAM-independentwrites. DOSserviceABI omitsrealINTframes/device; actualcallbackbodies-universaltargetdomains-allwriters/callerSS-SP/terminal-historicalDOS/B0FEarenaexclusion/core/P1-GATE unproved. PreparedAH4Crequests notactualprocess exit; postterminalepilogue notinvented. Physical086Cunassigned/CGAbehindEGAclosure.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','family_instruction_sites_exercised','instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
