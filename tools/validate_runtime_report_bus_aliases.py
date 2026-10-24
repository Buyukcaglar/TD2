"""Supplemental actual keyboard-cleanup low-memory root-frame alias comparison."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_runtime_dispatch_bus import Registers,StateRegisters,DOSRequest,DOSService,CallbackRequest,CallbackService,Request as RuntimeRequest,Response as RuntimeResponse,Handler,Services as RuntimeServices,Limits as RuntimeLimits,FAMILY_CALLS,FAMILY_STEPS,UNREACHED,require,values
from validate_line_draw import Request as DeviceRequest,Response as DeviceResponse,Service as DeviceService
from validate_fallback_mode import device_event
from validate_timer_handler_bus import PortService,ww,rw
from validate_timer_control_bus import PORTS as TIMER_PORTS
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];ARITH=0x8d5;VIDEO_OUTS={0x8418,0x841c,0x8422,0x8426,0x8436,0x843a};KEY_PORTS={0x68c4,0x68ca,0x6904};PARENT_CALLS={5:(1,0xa),0xa:(2,0xf),0xf:(3,0x14),0x23:(4,0x28),0x2b:(5,0x30)};PARENT_STEPS={2,0x14,0x17,0x1a,0x1d,0x20}
class Services(C.Structure):_fields_=[('bios',DOSService),('device',DeviceService),('port',PortService),('formatter',Handler),('runtime',RuntimeServices),('context',C.c_void_p)]
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['steps','calls','keyboard_ports','video_calls','video_events','timer_steps','timer_ports']]+[('runtime',RuntimeLimits)]
class Result(C.Structure):_fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','services','callbacks','ports','device_events','device_bytes','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','stage','halt_site','raw_target','raw_segment']]+[('returned',StateRegisters),('exit_request',DOSRequest)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');require((C.sizeof(Services),C.sizeof(Limits),C.sizeof(Result))==(72,44,112),'ReportABI')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    graph=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());names=['16A7:0002','06C9:642E','06C9:840A','06C9:68C4','06C9:610A','13A8:2D57','13A8:2C1C','13A8:29F6','13A8:0599','13A8:060D','13A8:066E','13A8:0620','13A8:088C','13A8:08B7','13A8:05E0'];fs=[f for f in graph['functions'] if f['entry'] in names];fence={(int(f['entry'][:4],16),ip) for f in fs for ip in f['instructions']};require(len(fence)==342,'342siteunion');md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={coord:next(md.disasm(image[coord[0]*16+coord[1]:coord[0]*16+coord[1]+15],coord[1],count=1)) for coord in fence};returns={coord for coord,i in decoded.items() if i.mnemonic in ['ret','retf']};call_sizes={(int(c['site'][:4],16),int(c['site'][5:],16)):c['size'] for f in fs for c in f['calls']};call_sizes.update({(0x13a8,0x633):4,(0x13a8,0x5e9):4,(0x13a8,0x2c83):3,(0x13a8,0x2c93):5});cleanup={(0x13a8,ip) for ip in [0x68a,0x627,0x63b,0x8be,0x29fd]};fn=C.CDLL(str(lib)).td2ega_runtime_report_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    def case(**kw):
        c=dict(entry=1,ss=None,same=False,sp=0xe000,flags=2,mask=65535,pic=0xa5,speaker=0xa7,oldkey=0x1234,timer=0,bios=0,format=0,runtime_kind='ignore',steps=7,calls=5,kports=3,vcalls=1,vevents=8008,tsteps=1,tports=8,rsteps=32,rcalls=8,msg_ops=128,exit_ops=128,port_mutation=0,tag='keyboard');c.update(kw);return c
    placements=[(0,sp) for sp in [0x22,0x23,0x24,0x25,0x26,0x27,0x56,0x57,0x58,0x59,0x5a,0x5b,0x416,0x417,0x418]]+[(0x40,sp) for sp in [0x16,0x17,0x18]]
    cases=[case(ss=ss,sp=sp,flags=f,oldkey=key,pic=pic,tag='physical_root_alias') for (ss,sp),f,key,pic in itertools.product(placements,[2,0x643],[0,1],[0,0xa5,0xff])]
    vectors=instructions=synthetic=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        ds,ecs,rcs,pcs=load+0x178f,load+0x6c9,load+0x13a8,load+0x16a7;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[0xa2010]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def state():
            ef=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),u.reg_read(UC_X86_REG_BP),ef&1)
        def req_fields(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
        def apply(r,mutations=()):
            for reg,v in zip(REGS,values(r.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,r.bp);u.reg_write(UC_X86_REG_EFLAGS,2|r.carry|(r.registers.interrupts_enabled<<9)|(r.registers.direction<<10));active['mask']=0xf72b
            for sg,o,v in mutations:ww(backing,sg,o,v)
        def bios_effect(r,site):
            v=StateRegisters.from_buffer_copy(bytes(r));profile=active['c']['bios']
            if profile==1:v.bp=(active['sp']-16)&65535
            if profile==2:v.registers.ax=0xf123+(site==0x6457);v.registers.bx=0xbeef;v.registers.cx=0xcafe;v.registers.dx=0xd00d;v.registers.si=0x1357;v.registers.di=0x2468;v.registers.ds=ds+0x100;v.registers.es=0x8000;v.bp=(active['sp']-16)&65535;v.carry=1;v.registers.interrupts_enabled^=1;v.registers.direction^=1
            return v
        def dos_effect(r):v=StateRegisters.from_buffer_copy(bytes(r));v.registers.ax=0;v.carry=0;return v
        def callback_effect(r,kind,sp):
            v=StateRegisters.from_buffer_copy(bytes(r));mut=[]
            if kind=='formatter' and active['c']['format']==1:mut.append((active['ss'],sp,0x4444))
            return v,mut
        def music(memory,events,model,operation,number,value,enabled):
            events.append((operation,number,value,enabled));returned=model.get(number,0)
            if operation:model[number]=value
            if len(events)==1 and active['c']['port_mutation']:
                if active['c']['port_mutation']==1:ww(memory,active['ss'],active['sp']-2,0x8888)
                else:ww(memory,active['ss'],active['sp']-4,0x7777)
            return returned
        def code(cpu,address,size,_):
            actual_cs,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP);coord=((actual_cs-load)&65535,ip)
            if active.get('synthetic_stepping'):return
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(coord);return
            if active.get('foreign'):
                require((actual_cs,ip)==active['foreign'][:2],'Actualforeignentry');active['foreign_state']=state();active['foreign_flags']=u.reg_read(UC_X86_REG_EFLAGS)&65535;active['foreign_mask']=active['mask'];active['ret_kind']=active['foreign'][3];u.emu_stop();return
            require(coord in fence and not (coord[0]==0x13a8 and ip in UNREACHED) and coord not in [(0x16a7,0x30),(0x16a7,0x31)],'Reportfence '+str(coord))
            if 'pending_mask' in active:active['mask']=active.pop('pending_mask')
            own_step=(coord[0]==0x16a7 and ip in PARENT_STEPS) or coord==(0x6c9,0x68c4)
            if own_step:
                if active['steps']==active['c']['steps']:active['status']=3;u.emu_stop();return
                active['steps']+=1
            if coord[0]==0x16a7 and ip in PARENT_CALLS:
                if active['calls']==active['c']['calls']:active['status']=3;u.emu_stop();return
                active['calls']+=1
            if coord==(0x6c9,0x6431):
                if active['video_calls']==active['c']['vcalls']:active['status']=3;u.emu_stop();return
                active['video_calls']+=1
            if coord[0]==0x6c9 and ip in KEY_PORTS:
                if active['keyboard_ports']==active['c']['kports']:active['status']=3;u.emu_stop();return
                active['keyboard_ports']+=1;active['ports']+=1
            if coord==(0x6c9,0x610a):
                if active['timer_steps']==active['c']['tsteps']:active['status']=3;u.emu_stop();return
                active['timer_steps']+=1
            if coord[0]==0x6c9 and ip in TIMER_PORTS:
                if active['timer_ports']==active['c']['tports']:active['status']=3;u.emu_stop();return
                active['timer_ports']+=1;active['ports']+=1
            video_effect=coord[0]==0x6c9 and (ip in VIDEO_OUTS or ip in [0x6450,0x6457] or (ip==0x842f and u.reg_read(UC_X86_REG_CX)))
            if video_effect:
                if len(active['video_events'])==active['c']['vevents']:active['status']=3;u.emu_stop();return
                if ip not in [0x6450,0x6457]:
                    r=state();kind=1 if ip in VIDEO_OUTS else 3;physical=((r.registers.es<<4)+r.registers.di)&0xfffff if kind==3 else 0;q=DeviceRequest(kind,ip,ecs,0,active['ss'],u.reg_read(UC_X86_REG_SP),r.registers.dx,r.registers.ax&255,(C.c_uint16*5)(0,0,0,0,0),physical,r);active['video_events'].append(('device',device_event(q)));active['device_bytes']+=int(kind==3)
            if coord[0]==0x13a8:
                if ip in FAMILY_STEPS:
                    if active['rsteps']==active['c']['rsteps']:active['status']=3;u.emu_stop();return
                    active['rsteps']+=1
                if ip in FAMILY_CALLS:
                    if active['rcalls']==active['c']['rcalls']:active['status']=3;u.emu_stop();return
                    active['rcalls']+=1
                if ip==0x2c5f:
                    target=rw(backing,rcs,u.reg_read(UC_X86_REG_BX)+0x2c10)
                    if target not in [0x2c90,0x2c98,0x2ca7,0x2ca1]:active['status']=6;active['raw']=(target,rcs);u.emu_stop();return
                legacy=ip in [0x677,0x899,0x633,0x5e9,0x8d9,0x5f5,0x609,0x5c8,0x5d1,0x5de] or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX))
                if legacy:
                    field='message_ops' if active['runtime_stage']==5 else 'exit_ops';limit=active['c']['msg_ops' if field=='message_ops' else 'exit_ops']
                    if active[field]==limit:active['status']=3;u.emu_stop();return
                    active[field]+=1
                if ip in [0x2c31,0x5de]:active['status']=5;active['exit_request']=DOSRequest(0x21,ip,rcs,active['ss'],u.reg_read(UC_X86_REG_SP),state());u.emu_stop();return
            if coord in returns:
                if decoded[coord].mnemonic=='retf' and u.reg_read(UC_X86_REG_SP)>0xfffc:active['status']=7;u.emu_stop();return
                active['ret_kind']='original';active['return_coord']=coord;u.emu_stop();return
            if coord in call_sizes:
                parent,rt=active['stage'],active['runtime_stage'];ret=ip+call_sizes[coord];stage=PARENT_CALLS[ip][0] if coord[0]==0x16a7 else parent;rst=FAMILY_CALLS[ip][0] if coord[0]==0x13a8 and ip in FAMILY_CALLS else rt;active['frames'].append((actual_cs,ret,(u.reg_read(UC_X86_REG_SP)+(2 if coord in cleanup else 0))&65535,parent,rt,coord));active['stage']=stage;active['runtime_stage']=rst
                if coord[0]==0x13a8 and ip in [0x29fd,0x2c9c,0x2a0f]:active['message_ops']=active['exit_ops']=0
                if coord==(0x16a7,0x23):active['foreign']=(rcs,0xb00,coord,'formatter')
                if coord[0]==0x13a8 and ip in [0x2c83,0x2c93,0x633,0x5e9]:
                    if ip==0x2c83:o=rw(backing,active['ss'],u.reg_read(UC_X86_REG_BP)-4);s=rw(backing,active['ss'],u.reg_read(UC_X86_REG_BP)-2)
                    elif ip==0x2c93:o=rw(backing,active['ss'],0x707e);s=rw(backing,active['ss'],0x7080)
                    elif ip==0x633:o=rw(backing,u.reg_read(UC_X86_REG_DS),0x6dcc);s=rw(backing,u.reg_read(UC_X86_REG_DS),0x6dce)
                    else:o=rw(backing,u.reg_read(UC_X86_REG_DS),0x7076);s=rw(backing,u.reg_read(UC_X86_REG_DS),0x7078)
                    active['foreign']=(s,o,coord,'handler' if ip in [0x2c83,0x2c93] else 'finalizer')
            m=decoded[coord].mnemonic
            if m in ['cmp','sub','add','neg']:active['pending_mask']=active['mask']|ARITH
            elif m in ['inc','dec']:active['pending_mask']=active['mask']|(ARITH^1)
            elif m in ['or','and','xor','test','shl','shr']:active['pending_mask']=(active['mask']|ARITH)&0xffef
            elif m in ['stc','clc']:active['pending_mask']=active['mask']|1
            active['instructions']+=1;active['sites'].add(coord)
        def written(cpu,access,address,size,value,_):active['writes']+=1
        def interrupt(cpu,number,_):
            ip=u.reg_read(UC_X86_REG_IP)-2;segment=u.reg_read(UC_X86_REG_CS);q=DOSRequest(number,ip,segment,active['ss'],u.reg_read(UC_X86_REG_SP),state())
            if segment==ecs and number==0x10:active['video_events'].append(('bios',req_fields(q)));active['bios'].append(req_fields(q));apply(bios_effect(q.incoming,ip))
            else:require(segment==rcs and number in [0x21,0x23] and ip in [0x2c2b,0x5d1,0x8d9,0x5f5,0x609],'ExplicitDOSboundary');active['dos'].append(req_fields(q));apply(dos_effect(q.incoming))
        def port_in(cpu,number,width,_):require(width==1 and number in [0x21,0x61],'MusicIN');return music(backing,active['music'],active['model'],0,number,u.reg_read(UC_X86_REG_AX)&255,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
        def port_out(cpu,number,width,value,_):
            require(width==1,'ByteOUT')
            if number in [0x21,0x61,0x40,0x43]:music(backing,active['music'],active['model'],1,number,value,(u.reg_read(UC_X86_REG_EFLAGS)>>9)&1)
            else:require(active['video_events'] and active['video_events'][-1][0]=='device','VideoOUTrequest')
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)
        for c in cases:
            ss=c['ss'] if c['ss'] is not None else ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags'];data=bytearray(base)
            for sg in [ds,ds+0x100]:data[sg*16:sg*16+65536]=bytes(65536)
            for sg in [ds,ds+0x100]:
                data[sg*16]=0x55;cursor=0x82c4
                for key in [0xa,0xfc,0xff,1]:ww(data,sg,cursor,key);cursor+=2;data[sg*16+cursor:sg*16+cursor+3]=b'AB\0';cursor+=3
                ww(data,sg,cursor,0xffff)
                for slot in range(6):ww(data,sg,0x7058+4*slot,0 if c['runtime_kind']=='default' else 1);ww(data,sg,0x705a+4*slot,0)
                ww(data,sg,0x6d89,0x1234);ww(data,sg,0x6d8b,0x7000);ww(data,sg,0x6dc8,0x5678);ww(data,sg,0x6dca,0x7100)
                for off,value in [(0x62ae,c['oldkey']),(0x62b0,0x2345),(0x62b2,0x3456),(0x62b4,0x4567),(0x5e88,0x9876),(0x5e8a,0x8765)]:ww(data,sg,off,value)
            ww(data,0,0x20,0x61bf if c['timer']==2 else 0x4321);ww(data,0,0x22,ecs if c['timer'] else 0x5678);data[0x417]=0xab;ww(data,0x40,0x10,0x30);ww(data,ss,0x707e,0x100);ww(data,ss,0x7080,0xa000)
            for i,value in enumerate([0x1111,0x2222,0x1357,0x2468,0x369c,0x48ad,0x5bce]):ww(data,ss,sp+2*i,value)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data));startseg,startip=(ecs,0x68c4) if c['entry'] else (pcs,2)
            for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,startseg),(UC_X86_REG_IP,startip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.clear();active.update(c=c,ss=ss,sp=sp,mask=c['mask'],steps=0,calls=0,stage=0,runtime_stage=0,video_calls=0,keyboard_ports=0,timer_steps=0,timer_ports=0,ports=0,rsteps=0,rcalls=0,message_ops=0,exit_ops=0,writes=0,instructions=0,sites=set(),frames=[],foreign=None,ret_kind=None,status=0,raw=(0,0),video_events=[],device_bytes=0,bios=[],dos=[],music=[],model={0x21:c['pic'],0x61:c['speaker']},formatters=[],handlers=[],finalizers=[],exit_request=None);root=False;u.emu_start(startseg*16+startip,0,count=200000)
            while active['ret_kind']:
                kind=active['ret_kind'];active['ret_kind']=None
                if kind!='original':
                    s,o,coord,_=active['foreign'];qsp=u.reg_read(UC_X86_REG_SP);r=active['foreign_state'];v,mut=callback_effect(r,kind,qsp);row=(coord,s,o,qsp,bytes(r),active['foreign_flags'],active['foreign_mask'],[rw(backing,ss,qsp+4+2*i) for i in range(5)] if kind=='formatter' else [])
                    active[kind+'s' if kind!='finalizer' else 'finalizers'].append(row);apply(v,mut);active['foreign']=None
                    if kind=='formatter' and c['format']==2:active['status']=3;break
                    u.reg_write(UC_X86_REG_CS,0xa200);u.reg_write(UC_X86_REG_IP,0x10);active['synthetic_stepping']=True;u.emu_start(0xa2010,0,count=1);active['synthetic_stepping']=False;synthetic+=1
                else:
                    s,ip=active['return_coord'];active['stepping']=True;u.emu_start((load+s)*16+ip,0,count=1);active['stepping']=False
                if not active['frames']:root=True;active['stage']=0;break
                frame=active['frames'].pop();now=(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))
                if now!=frame[:3]:active['status']=1;break
                if frame[5] in [(0x16a7,5),(0x13a8,0x29fd)]:active['mask']=0xf72b
                active['stage'],active['runtime_stage']=frame[3:5];u.emu_start(now[0]*16+now[1],0,count=200000)
            require(root or active['status'],'Qualifiedreportoutcome');bus=(C.c_uint8*len(data)).from_buffer_copy(data);nbios=[];ndos=[];nvideo=[];nmusic=[];model={0x21:c['pic'],0x61:c['speaker']};nformat=[];nhandlers=[];nfinal=[];errors=[]
            def bios(ctx,m,qptr,rptr):q=qptr.contents;nbios.append(req_fields(q));nvideo.append(('bios',req_fields(q)));rptr[0]=bios_effect(q.incoming,q.site);return 1
            def dos(ctx,m,qptr,rptr):q=qptr.contents;ndos.append(req_fields(q));rptr[0]=dos_effect(q.incoming);return 1
            def device(ctx,m,qptr,rptr):
                q=qptr.contents;nvideo.append(('device',device_event(q)));rptr.contents.returned=q.incoming;rptr.contents.returned.carry=2;rptr.contents.returned.registers.direction=2
                if q.kind==3:m[q.address]=q.value
                return 1
            def mport(ctx,qptr,value):q=qptr.contents;value[0]=music(bus,nmusic,model,q.operation,q.port,q.value,q.interrupts_enabled);return 1
            def retired(ctx,m,bytes_count,qptr,rptr,kind):
                try:
                    q=qptr.contents;rows=active['formatters' if kind=='formatter' else 'handlers'];observed=nformat if kind=='formatter' else nhandlers;expected=rows[len(observed)];require((q.site,q.target_segment,q.target_ip,q.stack_sp,bytes(q.incoming))==(expected[0][1],*expected[1:5]),'Retiredrequest');require(q.kind==(2 if kind=='formatter' else 0 if q.site==0x2c83 else 1) and q.stack_segment==ss and q.flags_mask==expected[6] and q.flags_word&q.flags_mask==expected[5]&q.flags_mask,'Retiredrequestflags-kind-SS')
                    if kind=='formatter':require([rw(m,ss,q.stack_sp+4+2*i) for i in range(5)]==expected[7],'FiveactualSSwords')
                    observed.append(expected);v,mut=callback_effect(q.incoming,kind,q.stack_sp)
                    for sg,off,value in mut:ww(m,sg,off,value)
                    o=rptr.contents;o.returned=v;o.flags_word=2|v.carry|(v.registers.interrupts_enabled<<9)|(v.registers.direction<<10);o.flags_mask=0xf72b
                    if kind=='formatter' and c['format']==2:o.status=3;o.current_sp=q.stack_sp;o.next_segment=q.target_segment;o.next_ip=q.target_ip
                    else:o.current_sp=q.stack_sp+4;o.next_ip=rw(m,ss,q.stack_sp);o.next_segment=rw(m,ss,q.stack_sp+2)
                    return 1
                except Exception as error:errors.append(str(error));return 0
            def fmt(ctx,m,n,q,r):return retired(ctx,m,n,q,r,'formatter')
            def handler(ctx,m,n,q,r):return retired(ctx,m,n,q,r,'handler')
            def finalizer(ctx,m,qptr,rptr):
                q=qptr.contents;row=active['finalizers'][len(nfinal)];require((q.site,q.target_segment,q.target_ip,q.stack_sp,bytes(q.incoming))==(row[0][1],*row[1:5]),'Finalizerrequest');nfinal.append(row);rptr[0]=q.incoming;return 1
            bios_cb=DOSService(bios);dos_cb=DOSService(dos);device_cb=DeviceService(device);port_cb=PortService(mport);fmt_cb=Handler(fmt);handler_cb=Handler(handler);final_cb=CallbackService(finalizer);rsrv=RuntimeServices(dos_cb,handler_cb,final_cb,None);srv=Services(bios_cb,device_cb,port_cb,fmt_cb,rsrv,None);caps=Limits(c['steps'],c['calls'],c['kports'],c['vcalls'],c['vevents'],c['tsteps'],c['tports'],RuntimeLimits(c['rsteps'],c['rcalls'],c['msg_ops'],c['exit_ops']));r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],flags,c['mask'],C.byref(incoming),C.byref(caps),C.byref(srv),C.byref(r));label=str((load,c))
            if active['stage']==1 or (active['stage']==5 and active['runtime_stage'] in [4,5,7]):active['mask']=0xf72b
            expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['steps'],active['calls'],len(active['bios'])+len(active['dos']),len(active['formatters'])+len(active['handlers'])+len(active['finalizers']),active['ports'],len(active['video_events']),active['device_bytes'],active['writes'],active['stage'],*active['raw']);observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.steps,r.calls,r.services,r.callbacks,r.ports,r.device_events,r.device_bytes,r.bus_writes,r.stage,r.raw_target,r.raw_segment)
            require(not errors and nbios==active['bios'] and ndos==active['dos'] and nvideo==active['video_events'] and nmusic==active['music'] and model==active['model'] and nformat==active['formatters'] and nhandlers==active['handlers'] and nfinal==active['finalizers'],'Reportservices '+label+str(errors));require(observed==expected,'Reportcontrolcounts '+label+str((observed,expected)));require(bytes(bus)==bytes(backing),'ReportwholeRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'ReportGPR-BP '+label);ef=u.reg_read(UC_X86_REG_EFLAGS)&65535;require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'ReportCFIFDF '+label);require(r.flags_mask==active['mask'] and r.flags_word&r.flags_mask==ef&r.flags_mask,'ReportFLAGS '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(ef),hex(active['mask']))))
            if active['exit_request'] is not None:require(req_fields(r.exit_request)==req_fields(active['exit_request']),'Preparedreportexit '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['status_'+str(r.status)]+=1;coverage['tag_'+c['tag']]+=1;coverage['stage_'+str(r.stage)]+=1;coverage['CPU_writes']+=r.bus_writes;coverage['music_ports']+=r.ports;coverage['device_bytes']+=r.device_bytes;coverage['formatters']+=len(nformat);coverage['late_forwarding_all5678']+=sum(row[7]==[0x5678]*5 for row in nformat);coverage['prepared_exit_requests']+=int(r.status==5);coverage['changed_keyboard_root_words']+=int(c['entry']==1 and r.status==0 and (r.next_ip,r.next_segment)!=(0x1111,0x2222))
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
            if vectors%1024==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
    parent={(0x16a7,ip) for ip in [2,3,5,0xa,0xf,0x14,0x17,0x1a,0x1d,0x20,0x23,0x28,0x2b]};keyboard={(0x6c9,ip) for f in fs if f['entry']=='06C9:68C4' for ip in f['instructions']};require(keyboard.issubset(sites) and coverage['changed_keyboard_root_words'] and not synthetic and len(cases)==216,'Keyboard22-physicalroot-aliascoverage '+str(sorted(keyboard-sites)))
    deps=['tools/validate_runtime_report_bus.py','analysis/history/runtime-report-alias-supplement-setup-v1.json','tools/validate_runtime_dispatch_bus.py','tools/validate_video_reset.py','tools/validate_line_draw.py','tools/validate_fallback_mode.py','tools/validate_timer_control_bus.py','tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/runtime-report-bus-build-setup-v1.json','analysis/reviews/runtime-report-bus-frontier-v1.json','docs/recovery/evidence/td2ega-runtime-dispatch-bus-validation-v2.json'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000348','FN-EGA-000158'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_report_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':342,'instruction_sites_exercised':len(sites),'parent_instruction_sites_admitted':13,'parent_instruction_sites_exercised':len(parent&sites),'keyboard_instruction_sites_admitted':22,'keyboard_instruction_sites_exercised':len(keyboard&sites),'synthetic_callback_RETF_instructions':synthetic,'fixture_coverage':dict(coverage),'supplementary':True,'limits':'Supplementonly:216low-memorykeyboard-rootcasesperload/SS0IVTwordsandSS40BDA0417aliases/all22cleanupsites/actualfarwords/wholeRAM-GPR-BP-CFIFDF-definedFLAGS-ports-writes. Primaryparentcorpusretainedseparately. No addedparentcoverage. Actual16A7reportparent/68C4cleanup/actual642E-840A-610A-29F6-runtimecallee bodies/fullSS-latefivewordreads/returnedBPaliases/callerADDSP0A/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/orderedBIOS-device-music-DOS/independentCPUwrites. Formatter0B00andotherindirectbodies remainexplicitretiredABIeffects+genericRETF/notbodyproof. PreparedDOSexitnotexecuted; parentpostterminalPOPBP-RETFnotinvented. No fullformatter/actual16A7historicalterminal/B0FEdatafallthroughpruning/allwriters-lifetime-IRQcore-P1-GATE/DOSsession-renderer-audio-game-fidelity. CGAbehindEGAclosure/physical086Cunassigned.'};out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','parent_instruction_sites_exercised','keyboard_instruction_sites_exercised','fixture_coverage']},indent=2))
if __name__=='__main__':main()
