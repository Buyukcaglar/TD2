"""ActualSS input roots/installed69B7/modeled INT FLAGS frames and AF profiles."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_key_dispatch_bus import Registers,StateRegisters,Request as KeyRequest,Response as KeyResponse,Service as KeyService,require,values
from validate_gameport_bus import Request as PortRequest,Service as PortService
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
ENTRIES=[0x65c5,0x6601,0x6620]
UNREACHED={0x69c8,0x69cb,0x69cd,0x69e9,0x69ec,0x69f0}
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in ['calls','bios_calls','callback_calls','port_reads']]
class Services(C.Structure):_fields_=[('key',KeyService),('key_context',C.c_void_p),('port',PortService),('port_context',C.c_void_p),('undefined_af',C.c_uint16)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','bios_calls','callback_calls','port_reads','port_transfers','bus_writes']]+[(n,C.c_uint16) for n in ['flags_word','flags_mask','zero_flag','flags_valid']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
 g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());roots=[f'06C9:{ip:04X}' for ip in ENTRIES+[0x69b7,0x6528,0x6686]];fence={ip for f in g['functions'] if f['entry'] in roots for ip in f['instructions']}-UNREACHED;require(len(fence)==273,'Fence');md=Cs(CS_ARCH_X86,CS_MODE_16);mnemonics={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic for ip in fence};returns={ip for ip in fence if mnemonics[ip] in ['retf','iret']};calls={0x65d0:0x65d5,0x65d9:0x65de,0x6617:0x661c,0x6680:0x6685};ints={0x65c7,0x65cd,0x6603,0x6614};fn=C.CDLL(str(lib)).td2ega_input_poll_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None;require((C.sizeof(Limits),C.sizeof(Services),C.sizeof(Result))==(16,40,64),'Layouts')
 profiles=[(0x50,0,0x4e20,8,0,0),(0,4000,500,8,100,300),(100,300,200,1,125,275),(100,300,200,0,125,275),(0x7fff,0x8000,0xffff,1,0x7ffe,0x8001),(0x8000,0x7fff,0x8001,1,0xffff,0),(0xffff,0,0x7fff,0xffff,0x8000,0x7fff)]
 def case(**kw):
  c=dict(entry=0,pending=0x1234,directions=0,enabled=0,config=1,repeat=0,table=0x4567,target=0,mode=0,outds=None,x=1,y=2,xp=profiles[0],yp=profiles[0],initial=0xff,final=0xdf,af=0,same=False,ds=None,ss=None,sp=0xe000,flags=2,mask=0xffff,limits=(1,2,1,5000));c.update(kw);return c
 all_flags=[2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7)|(iff<<9)|(df<<10)|(of<<11) for cf,pf,af,zf,sf,iff,df,of in itertools.product([0,1],repeat=8)]
 cases=[case(entry=e,pending=pending,same=same,af=af,flags=flags,mask=0xffef if flags&0x10 else 0xffff,target=0x645a if pending&1 else 0) for e,pending,same,af,flags in itertools.product([0,1],[0,1,0x8000],[False,True],[0,1],all_flags)]
 cases += [case(entry=2,directions=bits,same=same,af=af,flags=flags) for bits,same,af,flags in itertools.product(range(1024),[False,True],[0,1],[2,0x643])]
 cases += [case(entry=e,pending=pending,target=0x645a,mode=mode,outds=ds,same=same,af=af,flags=flags) for e,pending,mode,ds,same,af,flags in itertools.product([0,1],[1,0x80,0x8500,0xffff],range(6),[None,0x6000],[False,True],[0,1],[2,0x643])]
 for (x,y),(xi,xp),(yi,yp),af in itertools.product([(0,0),(0,1),(1,0),(1,2),(2,1),(79,81),(81,79)],enumerate(profiles),enumerate(profiles),[0,1]):cases.append(case(pending=0,enabled=1,x=x,y=y,xp=xp,yp=yp,af=af,same=(xi+yi)&1==0,flags=0x643 if xi&1 else 2,initial=0xff if yi&1 else 0x33,final=0xdf if xi&1 else 0xef,repeat=0x0d if (xi+yi)&1 else 0))
 stack=[0,1,2,4,6,8,10,0xfffa,0xfffc,0xfffd,0xfffe,0xffff]+list(range(0x62b0,0x62c7))+[0x6250,0x6252,0x6254,0x6256,0x6274,0x627c,0x6280,0x6cfc]
 cases += [case(entry=e,pending=pending,target=0x645a,mode=mode,same=True,sp=sp,af=af,flags=flags,limits=limits) for e,pending,mode,sp,af,flags,limits in itertools.product(range(3),[0,1],[0,2],stack,[0,1],[2,0x643],[(1,2,1,5000),(0,1,0,0)])]
 cases += [case(entry=e,ds=ds,ss=ss,sp=0x4000,af=af,flags=flags,pending=0x1234,target=0x645a) for e,ds,ss,af,flags in itertools.product(range(3),[0,0xffff],[0,0xffff,0x9000],[0,1],[2,0x643])]
 cases += [case(entry=e,pending=0,enabled=1,x=x,y=y,af=af,limits=limits) for e,(x,y),af,limits in itertools.product([0,2],[(0,4001),(4001,4001)],[0,1],[(1,2,1,4002),(1,2,1,4003),(1,0,0,0)])]
 rng=random.Random(0x65c56620)
 for _ in range(128):cases.append(case(entry=rng.randrange(3),pending=rng.randrange(65536),directions=rng.randrange(1024),enabled=rng.randrange(2),target=rng.choice([0,0x645a,0x646f,0x6518]),mode=rng.randrange(6),same=rng.choice([False,True]),af=rng.randrange(2),flags=rng.choice(all_flags),x=rng.randrange(4),y=rng.randrange(4)))
 for candidate,(x,y),entry,af,same,flags in itertools.product([0,1,80,100,0x7fff,0x8000,0xffff],[(1,2),(80,80),(81,79)],[0,2],[0,1],[False,True],[2,0x643]):
  profile=(0,0,candidate,1,0,0);cases.append(case(entry=entry,pending=0,enabled=1,x=x,y=y,xp=profile,yp=profile,af=af,same=same,flags=flags,profile_tag='counter_flush'))
 cases += [case(entry=entry,pending=1,sp=sp,same=same,af=af,flags=flags,profile_tag='ADD_SP2') for entry,sp,same,af,flags in itertools.product([0,1],[0,1,15,16,0x7fff,0x8000,0x8001,0xffff],[False,True],[0,1],[2,0xed7])]
 cases += [case(pending=0,enabled=0,table=table,repeat=repeat,same=same,af=af,flags=flags,profile_tag='lookup_CMP') for table,repeat,same,af,flags in itertools.product([0,1,0x7fff,0x8000,0xffff],[0,1,0x7fff,0x8000,0xffff],[False,True],[0,1],[2,0xed7])]
 vectors=instructions=synthetic_returns=0;sites=set();coverage=Counter();pattern=bytes((i*37+11)&255 for i in range(65536));direction_offsets=[0x62f3,0x62d6,0x6301,0x6302,0x6303,0x6307,0x630b,0x630a,0x6309,0x6305]
 for load in [0x1000,0x2345]:
  cs,principal=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;base[0xa0100]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def state(cpu):
   ef=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),cpu.reg_read(UC_X86_REG_BP),ef&1)
  def resolve_af(cpu):
   pending=active.get('pending_af');active['pending_af']=None
   if pending=='undefined':
    active['af_valid']=False;active['af_value']=active['c']['af']
   elif pending=='defined':active['af_valid']=True
  def code(cpu,address,size,unused):
   if active.get('executing_control'):return
   resolve_af(cpu);ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(address));active['last_ip']=ip
   if ip in returns:active['return']=ip;cpu.emu_stop();return
   if ip in ints and active['bios']==active['c']['limits'][1]:active['prefix']=3;cpu.emu_stop();return
   if ip in calls:
    if active['calls']==active['c']['limits'][0]:active['prefix']=3;cpu.emu_stop();return
    active['calls']+=1;active['frames'].append({'kind':'call','ip':calls[ip],'sp':cpu.reg_read(UC_X86_REG_SP)})
   if ip==0x6559:
    active['target']=cpu.reg_read(UC_X86_REG_BX)
    if active['callbacks']==active['c']['limits'][2]:active['prefix']=3
    else:active['call_pending']=True
    cpu.emu_stop();return
   if ip in [0x669f,0x66ba,0x67f0]:
    if active['guest_port']['reads']==active['c']['limits'][3]:active['prefix']=3;cpu.emu_stop();return
    active['port_request']=PortRequest(0,cpu.reg_read(UC_X86_REG_DX),cpu.reg_read(UC_X86_REG_AX)&255,cs,ip,cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP),(cpu.reg_read(UC_X86_REG_EFLAGS)>>6)&1,state(cpu))
   elif ip==0x66b5:active['port_request']=PortRequest(1,cpu.reg_read(UC_X86_REG_DX),cpu.reg_read(UC_X86_REG_AX)&255,cs,ip,cpu.reg_read(UC_X86_REG_SS),cpu.reg_read(UC_X86_REG_SP),(cpu.reg_read(UC_X86_REG_EFLAGS)>>6)&1,state(cpu))
   mnemonic=mnemonics[ip]
   if mnemonic in ['and','or','xor','test','shl','shr','mul','imul','div','idiv']:active['pending_af']='undefined'
   elif mnemonic in ['add','sub','sbb','adc','cmp','neg','inc','dec']:active['pending_af']='defined'
   active['instructions']+=1;active['sites'].add(ip)
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
   active['writes']+=3;active['INT_frame_writes']+=3;active['frames'].append({'kind':'bios','ip':site+2,'sp':before,'flags_address':((ss<<4)+((before-2)&65535))&0xfffff,'af_valid':active['af_valid']});cpu.reg_write(UC_X86_REG_SP,(before-6)&65535);cpu.reg_write(UC_X86_REG_CS,cs);cpu.reg_write(UC_X86_REG_IP,0x69b7);cpu.reg_write(UC_X86_REG_EFLAGS,ef&~0x300)
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
   put(ss,sp,0x1111);put(ss,sp+2,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(ef>>9)&1,(ef>>10)&1),0x5678,ef&1);u.mem_write(0,bytes(data))
   for reg,value in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[c['entry']]),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,value)
   active.update(c=c,calls=0,bios=0,callbacks=0,writes=0,INT_frame_writes=0,instructions=0,sites=set(),frames=[],af_valid=bool(c['mask']&0x10),af_value=(ef>>4)&1,pending_af=None,executing_control=False,call_pending=False,prefix=0,target=0,key_request=None,synthetic_returns=0,guest_port={'phase':'initial','polls':0,'reads':0,'events':[]},**{'return':None});label=str((load,c));root=raw=False;u.emu_start(cs*16+ENTRIES[c['entry']],0,count=100000)
   for _ in range(12):
    if active['call_pending']:
     active['call_pending']=False;before=u.reg_read(UC_X86_REG_SP);active['instructions']+=1;active['sites'].add(0x6559);active['callbacks']+=1;active['executing_control']=True;u.emu_start(cs*16+0x6559,0,count=1);active['executing_control']=False;q=KeyRequest(0x6559,cs,active['target'],ss,u.reg_read(UC_X86_REG_SP),state(u));active['key_request']=bytes(q);changed,child_sp=key_effects(c,q,guest_word_put)
     for reg,value in list(zip(REGS,values(changed.registers)[:8]))+[(UC_X86_REG_BP,changed.bp),(UC_X86_REG_SP,child_sp),(UC_X86_REG_EFLAGS,2|changed.carry|(c['af']<<4)|(changed.registers.interrupts_enabled<<9)|(changed.registers.direction<<10))]:u.reg_write(reg,value)
     active['af_valid']=False;active['af_value']=c['af']
     if child_sp>0xfffc:active['prefix']=5;break
     u.reg_write(UC_X86_REG_CS,0xa000);u.reg_write(UC_X86_REG_IP,0x100);active['executing_control']=True;u.emu_start(0xa0100,0,count=1);active['executing_control']=False;active['synthetic_returns']+=1
     if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0x655b,(before+2)&65535):raw=True;break
     u.emu_start(cs*16+0x655b,0,count=100000);continue
    if active['return']:
     ret=active['return'];active['return']=None;bound=0xfffa if ret==0x69d1 else 0xfffc
     if u.reg_read(UC_X86_REG_SP)>bound:active['prefix']=5;break
     active['instructions']+=1;active['sites'].add(ret);active['executing_control']=True;u.emu_start(cs*16+ret,0,count=1);active['executing_control']=False
     if not active['frames']:root=True;break
     frame=active['frames'].pop()
     if ret==0x69d1:active['af_valid']=frame['af_valid'];active['af_value']=(u.reg_read(UC_X86_REG_EFLAGS)>>4)&1
     if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,frame['ip'],frame['sp']):raw=True;break
     u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=100000);continue
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
   key=KeyService(native_key);port=PortService(native_device);services=Services(key,None,port,None,c['af']);limits=Limits(*c['limits']);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,c['entry'],ef,c['mask'],C.byref(incoming),C.byref(limits),C.byref(services),C.byref(r));observed=u.reg_read(UC_X86_REG_EFLAGS)&65535;expected_status=0 if root else 1 if raw else active['prefix']
   require(not errors,'Native services '+label+str(errors));require(native_port==active['guest_port'],'Fullorderedports '+label);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bios_calls,r.callback_calls,r.port_reads,r.port_transfers,r.bus_writes)==(expected_status,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['calls'],active['bios'],active['callbacks'],native_port['reads'],len(native_port['events']),active['writes']),'Result '+label+str((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bios_calls,r.callback_calls,r.port_reads,r.port_transfers,r.bus_writes,active['writes'])))
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/completeINTflagwords '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(observed&1,(observed>>9)&1,(observed>>10)&1),'CFIFDF '+label);require((r.flags_word& r.flags_mask)==(observed&r.flags_mask),'FullFLAGSvalidbits '+label+str((hex(r.flags_word),hex(r.flags_mask),hex(observed))));require((r.flags_valid,r.zero_flag)==(int(root),(observed>>6)&1 if root else 0),'NormalZF '+label)
   if root:require(bool(r.flags_mask&0x10)==active['af_valid'],'AFsemanticvalidity '+label)
   vectors+=1;instructions+=active['instructions'];synthetic_returns+=active['synthetic_returns'];sites.update(active['sites']);coverage['entry_'+str(c['entry'])]+=1;coverage['AF_choice_'+str(c['af'])]+=1;coverage['root_RETF' if root else 'raw_child_return' if raw else 'prefix_'+str(active['prefix'])]+=1;coverage['actual_far_calls']+=r.calls;coverage['actual_69B7_entries']+=r.bios_calls;coverage['actual_near_callback_CALLs']+=r.callback_calls;coverage['modeled_INT_frame_writes']+=active['INT_frame_writes'];coverage['CPU_and_modeled_INT_writes']+=r.bus_writes;coverage['port_reads']+=r.port_reads;coverage['DS_equals_SS']+=int(ds==ss);coverage['changed_root_coordinates']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['normal_AF_undefined']+=int(root and not r.flags_mask&0x10);coverage['normal_AF_defined']+=int(root and bool(r.flags_mask&0x10));coverage['initial_AF_unknown']+=int(c['mask']==0xffef)
   coverage['normal_consumed_ADD_SP2_OF1']+=int(root and r.bios_calls==2 and r.calls==1 and bool(r.flags_word&0x800));coverage['lookup_CMP_boundary_cases']+=int(c.get('profile_tag')=='lookup_CMP')
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and all(coverage[k] for k in ['raw_child_return','prefix_3','prefix_5','normal_AF_defined','normal_AF_undefined','AF_choice_0','AF_choice_1','normal_consumed_ADD_SP2_OF1','lookup_CMP_boundary_cases']),'Coverage '+str(sorted(fence-sites)))
 deps=['tools/validate_key_dispatch_bus.py','tools/validate_gameport_bus.py','tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-keyboard-bios-bus-validation-v1.json','docs/recovery/evidence/td2ega-key-dispatch-bus-validation-v1.json','docs/recovery/evidence/td2ega-gameport-bus-validation-v1.json','analysis/reviews/input-frame-flags-frontier-v1.json','analysis/history/validate_input_poll_bus_attempt_v1.py','analysis/history/input-poll-AF-hook-probe-v1.json','analysis/reviews/probe_input_poll_af_hook_v1.py','analysis/history/input-poll-bus-probe-difference-v1.json','analysis/reviews/probe_input_poll_bus_diff_v1.py','analysis/history/input-poll-bus-validation-refinement-v2.json','analysis/history/validate_input_poll_bus_attempt_v2.py','analysis/history/input-poll-bus-validation-attempt-v2.json'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000155','FN-EGA-000410','FN-EGA-000411'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_input_poll_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'unreachable_under_INT16_operation_profile':[f'06C9:{ip:04X}' for ip in sorted(UNREACHED)],'synthetic_callback_farRET_operations':synthetic_returns,'fixture_coverage':dict(coverage),'limits':'ThreeadditionalactualSSinputroots+actual69B7/6528/6686/273admittedsites; modeledINT16FLAGS-CS-IP/IF-TFentryframe, actualhandlerIRET-vsRETF2 andfullflagword-validity withexplicitundefinedAF0-1 analysischoices. UndefinedAF validitytrackedwithoutCODE-hook EFLAGSwrites; explicitAFvaluechosenatmodeledINTFLAGSstorage orsyntheticcallbackboundary, nothistoricalCPU qualification. ExactpriorCODE-hookEFLAGSconditional-executionfailureandfreshuntouched-backend128caseprobe preserved; recoveredC-DLLunchanged. Earlierfullv2all40284casesmatched267sites/missing6counterflushsites; archivepreserved and664casesperloadaddzero-countdowncandidate-flush plusADD-SP2-OFandlookup-CMPfullFLAGboundaries. FullRAM/GPR-BP-CFIFDF/definedfullFLAGS/control/orderedportrequests/CPUplusseparatemodeledINTframewrites. Keycallbackbodies remainABIeffects+privategenericRETF, syntheticreturnsnotoriginalbodyinstructions. No realIVT/INT-IRQ/PIC/DOS-device/session/renderer/audio/fullresourceformats/complete-state-machine/gameplay/fidelity; otherCPU/trap/reservedprofiles andactualcaller-allwriters-lifetime/exclusion/whole420A-403B-core/P1-GATE open. Oldsources-DLL-receiptsfrozen/same3originalentriescountedonce; physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised','synthetic_callback_farRET_operations','fixture_coverage']},indent=2))
if __name__=='__main__':main()
