"""Whole403B with actual SS, original callees, modeled INT FLAGS and PUSHF storage."""


import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys


from collections import Counter


from pathlib import Path


ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))


from validate_key_dispatch_bus import Registers,StateRegisters,Request as KeyRequest,Response as KeyResponse,Service as KeyService,require,values


from validate_gameport_bus import Request as PortRequest,Service as PortService


from validate_mutable_control import State
from validation.validate_state_tick_bus_diagnostics import SimLimits,Limits as TickLimits,Result as TickResult
from validate_sim_controller import TARGETS as SIM_TARGETS
from validate_mode_controller import TARGETS as MODE_TARGETS


from validation.twenty_bit_bus import map_twenty_bit_ram


from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR,UC_HOOK_INSN


from unicorn.x86_const import *


from capstone import Cs,CS_ARCH_X86,CS_MODE_16


REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]


ENTRIES=[0x403b]


UNREACHED={0x69c8,0x69cb,0x69cd,0x69e9,0x69ec,0x69f0}


from validate_input_poll_bus import Limits


class Services(C.Structure):_fields_=[('key',KeyService),('key_context',C.c_void_p),('port',PortService),('port_context',C.c_void_p),('undefined_af',C.c_uint16)]


class Result(C.Structure):


 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bios_calls','callback_calls','port_reads','port_transfers','bus_writes']]+[(n,C.c_uint16) for n in ['stage','unresolved_target','zero_flag','flags_valid','flags_word','flags_mask']]+[('returned',StateRegisters)]


def main():


 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]


 g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());byentry={f['entry']:f for f in g['functions']};names={'06C9:403B','06C9:69B7','06C9:5446'}|{f'06C9:{v:04X}' for v in SIM_TARGETS};todo=list(names)
 while todo:
  name=todo.pop();require(name in byentry,'Missing graphentry '+name)
  for call in byentry[name]['calls']:
   if call['target'] not in names:names.add(call['target']);todo.append(call['target'])
 fs=[byentry[name] for name in names];fence={(int(f['entry'][:4],16),ip) for f in fs for ip in f['instructions'] if int(f['entry'][:4],16)!=0x6c9 or ip not in UNREACHED};md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={site:next(md.disasm(image[site[0]*16+site[1]:site[0]*16+site[1]+15],site[1],count=1)) for site in fence};mnemonics={site:i.mnemonic for site,i in decoded.items()};returns={site for site in fence if mnemonics[site] in ['ret','retf','iret']};calls={}
 for f in fs:
  for c in f['calls']:
   owner=int(f['entry'][:4],16);site=(owner,int(c['site'][5:],16));callee=byentry[c['target']];kinds={mnemonics[(int(callee['entry'][:4],16),i)] for i in callee['instructions'] if (int(callee['entry'][:4],16),i) in returns};extra=2 if c['kind']=='call' and kinds=={'retf'} else 0
   calls[site]={'ip':site[1]+c['size'],'cs':owner,'clean':(8 if c['target']=='13A8:2EE8' else 0)+extra,'bp_check':c['site']=='06B3:0114','target':c['target'],'size':c['size']}
 root_calls={site for site in calls if calls[site]['target'] in {c['target'] for c in byentry['06C9:403B']['calls']} and site in {(0x6c9,int(c['site'][5:],16)) for c in byentry['06C9:403B']['calls']}};root_fence={(0x6c9,i) for i in byentry['06C9:403B']['instructions']};require(len(root_calls)==11 and len(root_fence)==80,'Rootinventory');ints={0x6603,0x6614};fn=C.CDLL(str(lib)).td2ega_state_tick_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(State),C.POINTER(TickLimits),C.POINTER(Services),C.POINTER(TickResult)];fn.restype=None;require(C.sizeof(TickLimits)==92 and C.sizeof(TickResult)==48,'Layouts')
 profiles=[(0x50,0,0x4e20,8,0,0),(0,4000,500,8,100,300),(100,300,200,1,125,275),(100,300,200,0,125,275),(0x7fff,0x8000,0xffff,1,0x7ffe,0x8001),(0x8000,0x7fff,0x8001,1,0xffff,0),(0xffff,0,0x7fff,0xffff,0x8000,0x7fff)]


 def sim_case(**kw):
  c=dict(window=0,cl=0,state=0,mode=0,speed=1,count=0x100,stream=0x3b31,record=0,callback_record=127,callback_selector=0,target=0x4a18,selector=0,threshold=255,ring=0,cursor=2,second=None,source_flags=0,remaining=100,deadline=1,dx_high=0,dx_low=0x1000,accum=0,step=0,lo=0x8000,hi=0x7fff,scalar=0,token=255,coef=0,presence=1,external=0,width=14,flags=2,same=False,ds=None,sp=0xe000,iterations=4,rows=8,ring_calls=64,guard_calls=16,sample_calls=8,child_calls=32,control_calls=32,dispatch_calls=8,long=None,blocked=0,byte_field=0,word_field=0,control_field=1000,multiplier=0x8000,seedcounter=0,raw_selector=1,late=0,existing=0);c.update(dict(marked=0,bit=0,flag=0,row=None,armflag=0,byte_limit=255),**kw);return c
 def case(**kw):
  c=dict(entry=0,pending=0,directions=1,enabled=0,config=1,repeat=0,table=0x4567,target=0,mode=0,outds=None,x=1,y=2,xp=profiles[0],yp=profiles[0],initial=0xff,final=0xdf,af=0,same=False,ds=None,ss=None,sp=0xe000,flags=2,mask=0xffff,limits=(16,2,1,5000),paused=0,idle=0,activity=2,automatic=0,control=0,scan_target=0x44bf,scan_match=True,rotation=0x8000,tag='base',counter=1,secondary=2,exit=0,age=1,active=0,root_calls=11,records=0,changes=[],simulation=sim_case());c.update(kw);return c
 cases=[case(paused=p,activity=activity,same=same,flags=f,af=af) for p,activity,same,f,af in itertools.product([0,1,2,4],[0,1,2],[False,True],[2,0x643],[0,1])]
 cases += [case(counter=counter,secondary=second,exit=exit,age=age,active=active,automatic=marked,tag='counters') for counter,second,exit,age,active,marked in itertools.product([0,1,2,255],[0,1,2],[0,1,2,255],[0,0x707,0x708,0xffff],[0,1],[0,1])]
 cases += [case(root_calls=limit,paused=p,same=same,flags=f,tag='root_budget') for limit,p,same,f in itertools.product(range(12),[0,1],[False,True],[2,0x643])]
 cases += [case(pending=key,target=0x645a,mode=mode,outds=outds,paused=p,same=True,flags=f,tag='callbacks') for key,mode,outds,p,f in itertools.product([1,0x80,0x8500],range(6),[None,0x6000],[0,1],[2,0x643])]
 for target,selector,window,marked,same in itertools.product(SIM_TARGETS+[0],[0,127,255],[0,436],[0,1],[False,True]):
  sc=sim_case(target=target,callback_selector=selector,window=window,marked=marked,existing=1);cases.append(case(simulation=sc,same=same,tag='simulation'))
 for mode,record_count,af,same in itertools.product([0,1,2,7],[0,8,16,32],[0,1],[False,True]):
  sc=sim_case(existing=1,mode=mode);changes=[(0x33b6,mode,1),(0x33b7,mode,1),(0x52da,100,2),(0x5354,record_count,2),(0x5356,record_count,2),(0x3379,0,1),(0x33b8,0,1),(0x380d,100,2),(0x3811,0x3b51,2)]
  for origin in [0x3813,0x39a3]:
   for i in range(4):changes +=[(origin+8*i,4,2),(origin+8*i+2,0,2),(origin+8*i+4,0,2),(origin+8*i+6,0,2)]
  cases.append(case(simulation=sc,records=record_count,changes=changes,af=af,same=same,tag='mode_records'))
 cases += [case(sp=sp,same=True,paused=p,flags=f,tag='stack_alias') for sp,p,f in itertools.product([46,0xffe0,0xa3ce,0x3368,0x336a,0x33d4,0x52ce,0x52d2,0x5354,0x66e6,0x942e],[0,1],[2,0x643])]

 # Append16 independently verified wholecaller nonlocal/FLAGS producers.
 for same,sp,af,flags in itertools.product([False,True],[46,0xe000],[0,1],[2,0x643]):
  sc=sim_case(existing=1,stream=201,mode=1)
  changes=[(0x33b6,0,1),(0x33b7,1,1),(0x52d8,0,2),(0x52da,1,2),(0x52d2,0,2),(0x52de,0,2),(0x331a,0,2),(0x5366,0,2),(0x3379,0,1),(0x33b8,0,1),(0x3460,0x57b7,2),(0x3446,0x55a5,2),(0x5354,8,2),(0x5356,8,2),(0x330c,0,2),(0x330e,0,2),(0x3314,0,2),(0x3316,0,2),(0x380d,1000,2)]
  for origin in [0x3813,0x39a3]:changes +=[(origin,4,2),(origin+2,0,2),(origin+4,0,2),(origin+6,0,2)]
  cases.append(case(simulation=sc,same=same,sp=sp,af=af,flags=flags,records=8,activity=2,changes=changes,tag='nonlocal_probe'))
 vectors=instructions=synthetic_returns=0;sites=set();coverage=Counter();pattern=bytes(65536);direction_offsets=[0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305]


 for load,form in itertools.product([0x1000,0x2345],itertools.product([0,2],[0,2],[1,2])):


  cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)


  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)


  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;base[0xa0100]=0xcb


  for at,branch in zip([0x424a,0x4275,0x42ad],form):base[cs*16+at]={0:0x76,1:0x77,2:0x75}[branch]


  u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}


  def state(cpu):


   ef=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),cpu.reg_read(UC_X86_REG_BP),ef&1)


  def resolve_af(cpu):


   pending=active.get('pending_af');active['pending_af']=None


   if pending=='undefined':


    active['af_valid']=False;active['af_value']=active['c']['af']


   elif pending=='defined':active['af_valid']=True


  def peek(sg,o):
   at=((sg<<4)+(o&65535))&0xfffff;return u.mem_read(at,1)[0]|(u.mem_read((at+1)&0xfffff,1)[0]<<8)
  def budget(name,limit):
   if active['counts'][name]==limit:active['prefix']=3;u.emu_stop();return False
   active['counts'][name]+=1;return True
  def code(cpu,address,size,unused):
   if active.get('executing_control'):return
   resolve_af(cpu);ip=cpu.reg_read(UC_X86_REG_IP);sg=(cpu.reg_read(UC_X86_REG_CS)-load)&65535;site=(sg,ip);require(site in fence,'403Bfence '+hex(address));active['last_ip']=ip
   if site==(0x6c9,0x780e):active['ring_entries']+=1
   if site in root_calls:
    active['stage']=ip
    if not budget('root_calls',active['caps'].root_calls):return
    active['root_calls']+=1
    for name in ['math_calls','control_outer','control_nested','mode_outer','mode_leaf','pair_calls','record_steps']:active['counts'][name]=0
    active['outer_calls']=0;active['mode_leaf_calls']=0;active['record_steps']=0;active['mode_exit']=0 if ip==0x4114 else active['mode_exit']
    if ip in [0x40d9,0x4107,0x4114]:active['raw_target']=0
    if ip==0x40d9:active['calls']=active['bios']=active['callbacks']=0
    if ip==0x4107:
     for name in ['iterations','rows','ring_calls','guard_calls','sample_calls','child_calls','control_calls','dispatch_calls']:active['counts']['sim_'+name]=0
   if site in returns:active['return']=site;cpu.emu_stop();return
   mnemonic=mnemonics[site]
   if mnemonic=='pushf':active['pushf']=site;cpu.emu_stop();return
   if mnemonic=='popf':
    if peek(cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP))&0x7100:active['prefix']=5;cpu.emu_stop();return
    active['popf']=site;cpu.emu_stop();return
   caps=active['caps'];stage=active['stage']
   if stage==0x40d9:
    if ip in ints and active['bios']==active['c']['limits'][1]:active['prefix']=3;cpu.emu_stop();return
    if site in calls and site not in root_calls:
     if active['calls']==active['c']['limits'][0]:active['prefix']=3;cpu.emu_stop();return
     active['calls']+=1
   if stage in [0x40f0,0x4111] and site in calls and site not in root_calls:
    if not budget('math_calls',caps.math_calls):return
   if stage in [0x40f3,0x4124] and site in calls and site not in root_calls:
    if ip==0x460e:
     if not budget('control_nested',caps.control_nested_calls):return
    else:
     if not budget('control_outer',caps.control_calls):return
     active['counts']['control_nested']=0
   if stage==0x4114 and site in calls and site not in root_calls:
    if ip in [0x54f4,0x5581,0x5650]:
     if not budget('mode_outer',caps.mode_calls):return
     active['counts']['mode_leaf']=0
    elif not budget('mode_leaf',caps.mode_nested_calls):return
   if stage==0x411a and site in calls and site not in root_calls:
    if not budget('pair_calls',caps.pair_calls):return
   if stage==0x4117:
    if ip in [0x4d41,0x4da3] or (site in calls and site not in root_calls):
     if not budget('record_steps',caps.record_steps):return
   if ip in [0x5299,0x4f92,0x5022,0x5446]:active['counts']['local_iterations']=0
   if ip in [0x52bf,0x4fda,0x5026,0x5477,0x54aa]:
    limit=caps.record_calls if stage==0x4117 else caps.mode_iterations if stage==0x4114 else caps.math_iterations
    if not budget('local_iterations',limit):return
   if stage==0x4107:
    category='iterations' if ip==0x46ca else 'rows' if ip in [0x4735,0x4c3e] else 'ring_calls' if ip in [0x46f4,0x4713,0x475b] else 'guard_calls' if ip in [0x49fe,0x4a10,0x4a26,0x4b7e,0x4b90,0x4d0e] else 'sample_calls' if ip in [0x4b96,0x4d14,0x4d1d] else 'child_calls' if ip in [0x4a31,0x4a39,0x4a41] else 'control_calls' if ip==0x460e else 'dispatch_calls' if ip==0x491d else None
    if category:
     if active['counts']['sim_'+category]==getattr(caps.simulation,category):active['prefix']=3;cpu.emu_stop();return
     if ip==0x491d:
      target=peek(cpu.reg_read(UC_X86_REG_DS),cpu.reg_read(UC_X86_REG_BX)+0x33e6)
      if target not in SIM_TARGETS:active['prefix']=6;active['raw_target']=target;cpu.emu_stop();return
     active['counts']['sim_'+category]+=1
   if site==(0x6c9,0x44ba):
    target=peek(cpu.reg_read(UC_X86_REG_DS),cpu.reg_read(UC_X86_REG_BX)+0x33dc)
    if target not in [0x44be,0x44bf,0x44c5,0x44d2]:active['prefix']=6;active['raw_target']=target;cpu.emu_stop();return
   if site==(0x6c9,0x6559):
    active['target']=cpu.reg_read(UC_X86_REG_BX)
    if active['callbacks']==active['c']['limits'][2]:active['prefix']=3
    else:active['call_pending']=True
    cpu.emu_stop();return
   if ip in [0x5514,0x55a1,0x57a7]:
    base=0x3456 if ip==0x5514 else 0x3446 if ip==0x55a1 else 0x3460;target=peek(cpu.reg_read(UC_X86_REG_DS),base+cpu.reg_read(UC_X86_REG_BX));active['raw_target']=target
    if target not in ([0x57ab,0x57b7,0x57cf] if ip==0x57a7 else MODE_TARGETS):active['prefix']=6;cpu.emu_stop();return
   if site==(0x6c9,0x585a):active['mode_exit']=1
   if site in calls or site==(0x6c9,0x491d):
    meta=calls[site] if site in calls else {'ip':0x4921,'cs':0x6c9,'clean':0,'bp_check':False,'target':'indirect491D'}
    active['frames'].append({'kind':'call','ip':meta['ip'],'cs':load+meta['cs'],'sp':(cpu.reg_read(UC_X86_REG_SP)+meta['clean'])&65535,'bp':cpu.reg_read(UC_X86_REG_BP) if meta['bp_check'] else None,'target':meta['target']})
   if ip==0x4c68:
    divisor=cpu.reg_read(UC_X86_REG_BP);divisor=divisor if divisor<32768 else divisor-65536;wide=(cpu.reg_read(UC_X86_REG_DX)<<16)|cpu.reg_read(UC_X86_REG_AX);wide=wide if wide<0x80000000 else wide-0x100000000;q=None if not divisor else abs(wide)//abs(divisor)*(1 if (wide>=0)==(divisor>=0) else -1)
    if q is None or not -32768<=q<=32767:active['prefix']=4;cpu.emu_stop();return
   if ip==0x5c79:
    divisor=cpu.reg_read(UC_X86_REG_DI);wide=(cpu.reg_read(UC_X86_REG_DX)<<16)|cpu.reg_read(UC_X86_REG_AX)
    if divisor==0 or wide//divisor>65535:active['prefix']=5;cpu.emu_stop();return
   if ip in [0x669f,0x66ba,0x67f0]:
    if active['guest_port']['reads']==active['c']['limits'][3]:active['prefix']=3;cpu.emu_stop();return
    active['port_request']=PortRequest(0,cpu.reg_read(UC_X86_REG_DX),cpu.reg_read(UC_X86_REG_AX)&255,cs,ip,cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP),(cpu.reg_read(UC_X86_REG_EFLAGS)>>6)&1,state(cpu))
   elif ip==0x66b5:active['port_request']=PortRequest(1,cpu.reg_read(UC_X86_REG_DX),cpu.reg_read(UC_X86_REG_AX)&255,cs,ip,cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP),(cpu.reg_read(UC_X86_REG_EFLAGS)>>6)&1,state(cpu))
   if mnemonic in ['and','or','xor','test','shl','shr','sar','rcl','rcr','mul','imul','div','idiv']:active['pending_af']='undefined'
   elif mnemonic in ['add','sub','sbb','adc','cmp','neg','inc','dec']:active['pending_af']='defined'
   active['instructions']+=1;active['sites'].add(site)
  def write(cpu,access,address,size,value,unused):


   active['writes']+=1


   touched={(address+i)&0xfffff for i in range(size)}


   for frame in active['frames']:


    if frame['kind']=='bios' and frame['flags_address'] in touched:frame['af_valid']=True


  def guest_word_put(sg,o,v,width=2):


   at=((sg<<4)+(o&65535))&0xfffff;u.mem_write(at,bytes([v&255]))


   if width==2:u.mem_write((at+1)&0xfffff,bytes([(v>>8)&255]))


  def interrupt(cpu,number,unused):


   require(number==0x16 and active['last_ip'] in ints,'OnlymodeledINT16');before=cpu.reg_read(UC_X86_REG_SP);ef=cpu.reg_read(UC_X86_REG_EFLAGS)&65535;ss=cpu.reg_read(UC_X86_REG_SS);site=active['last_ip'];active['bios']+=1


   if not active['af_valid']:ef=(ef&~0x10)|(active['af_value']<<4)


   for delta,value in [(2,ef),(4,cs),(6,site+2)]:guest_word_put(ss,before-delta,value)


   active['writes']+=3;active['INT_frame_writes']+=3;active['frames'].append({'kind':'bios','ip':site+2,'cs':cs,'bp':None,'sp':before,'flags_address':((ss<<4)+((before-2)&65535))&0xfffff,'af_valid':active['af_valid']});cpu.reg_write(UC_X86_REG_SP,(before-6)&65535);cpu.reg_write(UC_X86_REG_CS,cs);cpu.reg_write(UC_X86_REG_IP,0x69b7);cpu.reg_write(UC_X86_REG_EFLAGS,ef&~0x300)


  def device(model,q):


   require(q.port==0x201,'Port201');iff=q.state.registers.interrupts_enabled


   if q.operation:require(model['phase']=='trigger' and iff==0 and q.value==active['c']['initial'],'Trigger');model['phase']='poll';value=0


   elif model['phase']=='initial':value=active['c']['initial'];model['phase']='trigger';model['reads']+=1


   elif model['phase']=='poll' and iff==0:


    tick=model['polls'];model['polls']+=1;value=(0xf0 if tick&1 else 0x0c)|(1 if tick<active['c']['x'] else 0)|(2 if tick<active['c']['y'] else 0);model['reads']+=1


   else:require(model['phase']=='poll' and iff==1,'FinalIN');value=active['c']['final'];model['phase']='done';model['reads']+=1


   model['events'].append((bytes(q),value));return value


  def port_in(cpu,port,size,unused):require(port==0x201 and size==1,'INwidth');return device(active['guest_port'],active['port_request'])


  def port_out(cpu,port,size,value,unused):require(port==0x201 and size==1 and value==active['port_request'].value,'OUTwidth');device(active['guest_port'],active['port_request'])


  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INTR,interrupt);u.hook_add(UC_HOOK_INSN,port_in,None,1,0,UC_X86_INS_IN);u.hook_add(UC_HOOK_INSN,port_out,None,1,0,UC_X86_INS_OUT)


  def key_effects(c,q,put):


   sp=q.stack_sp;ss=q.stack_segment


   if c['mode']==1:


    for delta,value in [(4,0xcafe),(6,0xbabe),(8,0xf00d)]:put(ss,sp+delta,value)


   elif c['mode']==2:put(ss,sp,0x4444)


   elif c['mode']==3:put(ss,sp+2,0x5555)


   elif c['mode']==5:put(ss,sp+10,0x3333);put(ss,sp+12,0x4444)


   r=StateRegisters(Registers(0x1357,0x2468,0x369c,0xabcd,0x1111,0x2222,q.incoming.registers.ds if c['outds'] is None else c['outds'],0x7070,c['mode']&1,(c['mode']>>1)&1),0xaaaa,(c['mode']>>2)&1)


   return r,(sp+2)&65535 if c['mode']==4 else sp


  for c in cases:


   if c['tag']=='all_directions' and form!=(0,0,1):continue

   if c['tag'] in ['motion_edges','targeted_fields','port_coverage','random_fields'] and form not in [(0,0,1),(2,2,2)]:continue


   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000


   if c['ss'] is not None:ss=c['ss']


   sp=c['sp'];ef=c['flags'];start=(ds<<4)&0xfffff;cut=min(65536,0x100000-start);data[start:start+cut]=pattern[:cut]


   if cut<65536:data[:65536-cut]=pattern[cut:]


   def put(sg,o,v,width=2):


    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255


    if width==2:data[(at+1)&0xfffff]=(v>>8)&255


   put(principal,0x62b6,c['pending']);put(ds,0x6252,0,1);put(ds,0x6cfc,c['enabled'],1);put(ds,0x6cfe,c['config'],1);put(ds,0x6274,c['repeat'])


   for i in range(16):put(ds,0x6254+2*i,c['table'])


   block=struct.pack('<H',c['target'])*261;at=((ds<<4)+0x6048)&0xfffff;first=min(len(block),0x100000-at);data[at:at+first]=block[:first]


   if first<len(block):data[:len(block)-first]=block[first:]


   for i,o in enumerate(direction_offsets):put(ds,o,(c['directions']>>i)&1,1)


   for offset,profile in [(0x6282,c['xp']),(0x628e,c['yp'])]:


    for i,value in enumerate(profile):put(ds,offset+2*i,value)


   for sg in set([ds]+([c['outds']] if c['outds'] is not None else [])):


    for o,v in [(0x3352,c['idle']),(0x8a9a,c['activity']),(0x332c,0),(0x23aa,0x100),(0x23ac,0x200),(0x23ae,0x80),(0x3324,0),(0x3326,0),(0x2f4c,0),(0x2f4e,0),(0x3328,0),(0x52ce,0),(0x335a,0xffff),(0x3322,1),(0x2f46,c['rotation']),(0x2f4a,0),(0x23c8,0)]:put(sg,o,v)


    for o,v in [(0x33d4,c['paused']),(0x33d5,c['automatic']),(0x3365,c['control']),(0x3366,0),(0x3367,0),(0x90a8,0),(0x33af,0),(0x2f56,0),(0x23a6,0),(0x336e,0)]:put(sg,o,v,1)


    for i in range(8):put(sg,0x335d+i,0,1)


    for i in range(16):put(sg,0x339d+i,(i&1),1);put(sg,0x33a6+i,0,1)


    for i in range(5):put(sg,0x33dc+2*i,c['scan_target'])


   for esg in [0x8000,0x7070]:


    for i in range(5):put(esg,0x33da-i,(c['pending']+1)&255,1)


    if c['scan_match']:put(esg,0x33d8,c['pending']&255,1)


   def wb(o,value):put(ds,o,value,1)
   sc=c['simulation']
   for i in range(256):wb(0x66e8+i,sc['ring'])
   if sc['second'] is not None:wb(0x66e8+((sc['cursor']-2)&255),sc['second'])
   if sc['long']=='reject1793':wb(0x66e8+((sc['cursor']-1)&255),1)
   for i in range(128):wb(0x368a+i,255);wb(0x370a+i,0)
   for i in range(80):put(ds,0x1db4+4*i,sc['presence'])
   for i in range(129):put(ds,0x54aa+2*i,sc['scalar'])
   for i in range(256):put(ds,0x33e6+2*i,0x4a18)
   for i in range(128):put(ds,0x347e+4*i,0);wb(0x347e+4*i+2,0);wb(0x347e+4*i+3,0)
   wb(0x347e,sc['record']);wb(0x347f,sc['coef']);wb(0x347e+4*sc['callback_record']+3,sc['callback_selector']);put(ds,0x33e6+2*sc['callback_selector'],sc['target'])
   for o,v in [(0x52cc,sc['window']),(0x52ce,(sc['speed']<<8)|0x20),(0x52c8,sc['count']),(0x52ca,sc['stream']),(0x3320,sc['remaining']),(0x5342,sc['deadline']),(0x2f46,sc['accum']),(0x2f4a,sc['accum']),(0x2f48,sc['accum']),(0x3322,sc['step']),(0x3338,sc['lo']),(0x333a,sc['hi']),(0x23b2,sc['dx_low']),(0x23b4,sc['dx_high']),(0x37a6,0),(0x66e6,sc['cursor']),(0x8a9a,sc['blocked']),(0x3328,sc['multiplier']),(0x33c8,sc['word_field']),(0x33ca,sc['word_field']),(0x33cc,sc['word_field']),(0x52da,sc['existing']),(0x9410,sc['existing']),(0x940e,sc['external'])]:put(ds,o,v)
   for o,v in [(0x3371,sc['cl']),(0x33d5,sc['marked']),(0x33b7,sc['mode']),(0x5490,sc['state']),(0x533e,sc['selector']),(0x337a,sc['threshold']),(0x33bd,sc['source_flags']),(0x2f56,sc['raw_selector']),(0x5491,sc['bit']),(0x37f6,sc['flag']),(0x337b,sc['seedcounter']),(0x90a8,sc['late']),(0x33c6,sc['byte_field']),(0x2418,sc['byte_limit'])]:wb(o,v)
   for i in range(32):wb(0x337c+i,7)
   if sc['row'] is not None:
    for i,v in enumerate(sc['row']):put(ds,0x37a6+2*i,v)
    put(ds,0x37ae,0)
   wb((sc['stream']+1+0x3c)&65535,sc['armflag'])
   wb((sc['stream']+0x47)&65535,0);wb((sc['stream']+1)&65535,0);put(ss,(sc['stream']+2)&65535,sc['callback_record'],1)
   ix=(sc['selector']+1)&127;wb(0x368a+ix,sc['token']);wb(0x370a+ix,sc['coef'])
   if 30<=sc['token']<128:
    q,r=divmod(sc['token']-30,5);put(sc['external'],2*q+512*r,0x100);put(sc['external'],0x100,sc['width'])
   if sc['long']=='rows8193':
    for offset in range(0x37a6,0x37a6+65536,8):put(ds,offset,1);put(ds,offset+2,0)
    for o,v in [(0x52ca,0x3aec),(0x52c8,0x100),(0x52cc,0),(0x66e6,1000)]:put(ds,o,v)
    wb(0x337a,255);wb(0x3aec+0x47,0);wb(0x66e8+((1000-1)&255),0);wb(0x66e8+((1000-2)&255),5)
   for at,value,width in [(0x3368,c['counter'],1),(0x3369,c['secondary'],1),(0x5490,c['exit'],1),(0x942e,c['age'],2),(0x336b,c['active'],1),(0x8a9a,c['activity'],2),(0x33d5,c['automatic'],1),(0x33d4,c['paused'],1),(0x5354,c['records'],2),(0x5356,c['records'],2),(0x3318,0x100,2),(0x380d,100,2),(0x380f,100,2),(0x3811,0x3b51,2),(0x3378,0,1),(0x3375,0,1)]:put(ds,at,value,width)
   for i in range(5):put(ds,0x33da-i,(c['pending']+1)&255,1)
   if c['scan_match']:put(ds,0x33d8,c['pending']&255,1)
   for at,value,width in c.get('changes',[]):put(ds,at,value,width)

   put(ss,sp,0x1111);put(ss,sp+2,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x8000,(ef>>9)&1,(ef>>10)&1),0x5678,ef&1);caps=TickLimits(c['root_calls'],8,4,32,128,8,16,128,128,128,3,SimLimits(8,16,1800,32,16,64,32,16),Limits(*c['limits']));u.mem_write(0,bytes(data))


   for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,value)


   active.update(c=c,calls=0,bios=0,callbacks=0,writes=0,INT_frame_writes=0,instructions=0,sites=set(),frames=[],af_valid=bool(c['mask']&0x10),af_value=(ef>>4)&1,pending_af=None,executing_control=False,call_pending=False,prefix=0,target=0,unknown_target=0,key_request=None,root_calls=0,stage=0,raw_target=0,mode_exit=0,counts=Counter(),caps=caps,ring_entries=0,pushf=None,popf=None,flag_words=0,synthetic_returns=0,guest_port={'phase':'initial','polls':0,'reads':0,'events':[]},**{'return':None});label=str((load,form,c));root=raw=False;u.emu_start(cs*16+ENTRIES[c['entry']],0,count=100000)


   for _ in range(100000):


    if active['pushf'] or active['popf']:
     flag_site=active['pushf'] or active['popf'];is_push=bool(active['pushf']);active['pushf']=active['popf']=None;active['instructions']+=1;active['sites'].add(flag_site);active['executing_control']=True;u.emu_start((load+flag_site[0])*16+flag_site[1],0,count=1);active['executing_control']=False
     if is_push:
      active['flag_words']+=1
      if not active['af_valid']:
       value=peek(ss,u.reg_read(UC_X86_REG_SP));guest_word_put(ss,u.reg_read(UC_X86_REG_SP),(value&~0x10)|(c['af']<<4))
     else:active['af_valid']=True;active['af_value']=(u.reg_read(UC_X86_REG_EFLAGS)>>4)&1
     u.emu_start(u.reg_read(UC_X86_REG_CS)*16+u.reg_read(UC_X86_REG_IP),0,count=100000);continue
    if active['call_pending']:


     active['call_pending']=False;before=u.reg_read(UC_X86_REG_SP);active['instructions']+=1;active['sites'].add((0x6c9,0x6559));active['callbacks']+=1;active['executing_control']=True;u.emu_start(cs*16+0x6559,0,count=1);active['executing_control']=False;q=KeyRequest(0x6559,cs,active['target'],ss,u.reg_read(UC_X86_REG_SP),state(u));active['key_request']=bytes(q);changed,child_sp=key_effects(c,q,guest_word_put)


     for reg,value in list(zip(REGS,values(changed.registers)[:8]))+[(UC_X86_REG_BP,changed.bp),(UC_X86_REG_SP,child_sp),(UC_X86_REG_EFLAGS,2|changed.carry|(c['af']<<4)|(changed.registers.interrupts_enabled<<9)|(changed.registers.direction<<10))]:u.reg_write(reg,value)


     active['af_valid']=False;active['af_value']=c['af']


     if child_sp>0xfffc:active['prefix']=5;break


     u.reg_write(UC_X86_REG_CS,0xa000);u.reg_write(UC_X86_REG_IP,0x100);active['executing_control']=True;u.emu_start(0xa0100,0,count=1);active['executing_control']=False;active['synthetic_returns']+=1


     if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x655b,(before+2)&65535):raw=True;break


     u.emu_start(cs*16+0x655b,0,count=100000);continue


    if active['return']:


     ret=active['return'];active['return']=None;bound=0xfffa if ret==(0x6c9,0x69d1) else 0xfffe if mnemonics[ret]=='ret' else 0xfffc


     if u.reg_read(UC_X86_REG_SP)>bound:active['prefix']=5;break


     if ret==(0x6c9,0x585b):
      require(active['frames'][-1].get('target')=='06C9:56ED','Nonlocal56EDframe');active['frames'].pop()
     active['instructions']+=1;active['sites'].add(ret);active['executing_control']=True;u.emu_start((load+ret[0])*16+ret[1],0,count=1);active['executing_control']=False


     if not active['frames']:root=True;break


     frame=active['frames'].pop()


     if ret==(0x6c9,0x69d1):active['af_valid']=frame['af_valid'];active['af_value']=(u.reg_read(UC_X86_REG_EFLAGS)>>4)&1


     if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(frame['cs'],frame['ip'],frame['sp']) or (frame['bp'] is not None and u.reg_read(UC_X86_REG_BP)!=frame['bp']):raw=True;break


     u.emu_start(u.reg_read(UC_X86_REG_CS)*16+u.reg_read(UC_X86_REG_IP),0,count=100000);continue


    break


   require(root or raw or active['prefix'],'Outcome '+label);native_port={'phase':'initial','polls':0,'reads':0,'events':[]};errors=[];native_keys=[]


   def native_key(ctx,memory,qptr,rptr):


    try:


     q=qptr.contents;require(bytes(q)==active['key_request'],'Fullkeyrequest');native_keys.append(bytes(q))


     def nput(sg,o,value,width=2):


      at=((sg<<4)+(o&65535))&0xfffff;memory[at]=value&255


      if width==2:memory[(at+1)&0xfffff]=(value>>8)&255


     changed,child_sp=key_effects(c,q,nput);response=rptr.contents;response.returned=changed;response.bus_writes=0


     if child_sp>0xfffc:response.status=5;response.current_sp=child_sp;response.next_segment=q.target_segment;response.next_ip=q.target_ip


     else:


      def nword(o):


       at=((q.stack_segment<<4)+(o&65535))&0xfffff;return memory[at]|(memory[(at+1)&0xfffff]<<8)


      response.status=0;response.current_sp=(child_sp+4)&65535;response.next_ip=nword(child_sp);response.next_segment=nword(child_sp+2)


     return 1


    except Exception as error:errors.append(str(error));return 0


   def native_device(ctx,q,value):


    try:value.contents.value=device(native_port,q.contents);return 1


    except Exception as error:errors.append(str(error));return 0


   key=KeyService(native_key);port=PortService(native_device);services=Services(key,None,port,None,c['af']);limits=Limits(*c['limits']);code_state=State();code_state.branch_424a,code_state.branch_4275,code_state.branch_42ad=form;bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=TickResult();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(code_state),C.byref(caps),C.byref(services),C.byref(r));observed=u.reg_read(UC_X86_REG_EFLAGS)&65535;expected_status=0 if root else 1 if raw else active['prefix']


   require(not errors,'Nativeservices '+label+str(errors));require(native_port==active['guest_port'],'Fullorderedports '+label)
   require((r.status,r.current_sp,r.next_segment,r.next_ip,r.root_calls,r.bus_writes,r.stage,r.raw_target,r.mode_exit_kind)==(expected_status,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['root_calls'],active['writes'],active['stage'],active['raw_target'],active['mode_exit']),'403Bcontrol/counts '+label+str((r.status,r.current_sp,r.next_segment,r.next_ip,r.root_calls,r.bus_writes,r.stage,r.raw_target,r.mode_exit_kind,active['writes'])))
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Whole403BRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'Whole403BGPR '+label);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(observed&1,(observed>>9)&1,(observed>>10)&1),'Whole403BCFIFDF '+label)
   vectors+=1;instructions+=active['instructions'];synthetic_returns+=active['synthetic_returns'];sites.update(active['sites']);coverage['root_far_RETF' if root else 'raw_child_return' if raw else 'prefix_'+str(active['prefix'])]+=1;coverage['root_CALLs']+=r.root_calls;coverage['CPU_and_modeled_INT_writes']+=r.bus_writes;coverage['modeled_INT_frame_writes']+=active['INT_frame_writes'];coverage['actual_69B7_entries']+=active['bios'];coverage['PUSHF_words']+=active['flag_words'];coverage['actual_780E_entries']+=active['ring_entries'];coverage['mode_nonlocal_exits']+=active['mode_exit'];coverage['AF_choice_'+str(c['af'])]+=1;coverage['form_'+str(form)]+=1;coverage['tag_'+c['tag']]+=1
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)


   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return


  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{seg:04X}:{ip:04X}' for seg,ip in sorted(fence-sites)]}),flush=True)


 require(root_fence.issubset(sites) and root_calls.issubset(sites),'403Broot80site-11CALLcoverage '+str(sorted(root_fence-sites)))
 require(coverage['PUSHF_words'] and coverage['mode_nonlocal_exits'] and all(coverage['AF_choice_'+str(v)] for v in [0,1]),'403BFLAGS-nonlocalcoverage '+str(coverage))
 deps=['tools/validate_input_update_bus.py','tools/validate_sim_controller.py','tools/validate_mode_controller.py','tools/validate_record_controller.py','tools/validate_field_controller.py','tools/validate_secondary_fields.py','tools/validation/validate_state_tick_bus_diagnostics.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-input-update-bus-validation-v3.json','analysis/history/state-tick-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-state-tick-bus-context-v2.json','analysis/history/state-tick-validation-refinement-v2.json','analysis/history/state-tick-validation-refinement-v3.json','analysis/history/state-tick-validation-refinement-v4.json','analysis/history/state-tick-validation-attempt-v4.json','analysis/history/state-tick-nonlocal-probe-v1.json','analysis/reviews/probe_state_tick_nonlocal_v1.py'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000365'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_state_tick_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'root_instruction_sites_in_fence':80,'root_instruction_sites_exercised':len(root_fence&sites),'actual_callee_bodies_in_fence':len(fs)-1,'synthetic_callback_farRET_operations':synthetic_returns,'fixture_coverage':dict(coverage),'limits':'Whole403B originalroot80sites/11CALLs plusactualoriginalcalleeinstructions; previouslyunit-reviewedchildcodecoverage remainsseparatefromthiscallerprofile. ActualSS/farrootRET/DS-ES-DI-BP restoration/motionfullFLAGS-inputINT/actual69B7/actual56EDnonlocalPOPAX-RET/actualPUSHF-POPFprofile/wholeRAM-GPR-CFIFDF-control-writecounts. UndefinedAF materializedonlyatmodeledINTFLAGS orpostCPU-PUSHF storage; noCODE-hookEFLAGSrewrites. Explicitbudgets/unknownindirect/division-or-POPFprefixes distinctfromsourceerrors. Keycallbacks ABIeffects+genericRETF/notbodyproof; sourcewriter-reset-lifetime-IRQ/core/P1-GATE remainopen. NoDOSsession/realdevices/renderer/audio/fullresources/complete-state-machine/gameplay/fidelity. Physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','root_instruction_sites_exercised','synthetic_callback_farRET_operations','fixture_coverage']},indent=2))

if __name__=='__main__':main()


