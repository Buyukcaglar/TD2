"""Compare whole4674 plus25 actual bodies/fullSS/13 recognized indirect targets."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
TARGETS=[0x4929,0x4947,0x494d,0x495d,0x499a,0x49c9,0x49cf,0x49d5,0x49db,0x49e1,0x49e7,0x4a18,0x4a19]
FAMILY=[0x4674,0x4afa,0x4b5d,0x4b9a,0x4c85,0x4d26,0x4a2e,0x45fc,0x4612,0x7977,0x780e]+TARGETS
COUNTS=['iterations','rows','ring_calls','guard_calls','sample_calls','child_calls','control_calls','dispatch_calls']
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Limits(C.Structure):_fields_=[(n,C.c_uint32) for n in COUNTS]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in COUNTS+['direct_calls','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid','unresolved_target','reserved']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
 gp='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/gp).read_text());names={f'06C9:{v:04X}' for v in FAMILY}|{'13A3:0012'};fs=[f for f in g['functions'] if f['entry'] in names];require(len(fs)==25,'Family');fence={(int(f['entry'][:4],16),ip) for f in fs for ip in f['instructions']};require(len(fence)==687,'Fence');returns={(sg,ip) for sg,ip in fence if image[sg*16+ip] in [0xc3,0xcb]};calls={int(c['site'][5:],16):c for f in fs for c in f['calls']};root_calls={int(c['site'][5:],16) for f in fs if f['entry']=='06C9:4674' for c in f['calls']}
 fn=C.CDLL(str(lib)).td2ega_sim_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Result)];fn.restype=None;require(C.sizeof(Limits)==32 and C.sizeof(Result)==80,'Layout')
 vectors=instructions=0;sites=set();coverage=Counter();rng=random.Random(0x4674491d)
 def case(**kw):
  c=dict(window=0,cl=0,state=0,mode=0,speed=1,count=0x100,stream=0x3b31,record=0,callback_record=127,callback_selector=0,target=0x4a18,selector=0,threshold=255,ring=0,cursor=2,second=None,source_flags=0,remaining=100,deadline=1,dx_high=0,dx_low=0x1000,accum=0,step=0,lo=0x8000,hi=0x7fff,scalar=0,token=255,coef=0,presence=1,external=0,width=14,flags=2,same=False,ds=None,sp=0xe000,iterations=4,rows=8,ring_calls=64,guard_calls=16,sample_calls=8,child_calls=32,control_calls=32,dispatch_calls=8,long=None,blocked=0,byte_field=0,word_field=0,control_field=1000,multiplier=0x8000,seedcounter=0,raw_selector=1,late=0,existing=0);c.update(dict(marked=0,bit=0,flag=0,row=None,armflag=0,byte_limit=255),**kw);return c
 cases=[case(cl=cl,mode=mode,window=window,same=same,flags=flags) for cl,mode,window,same,flags in itertools.product([0,1,2,3,127,128,255],[0,1,2,8,255],[0,59,60,159,160,161,559,560,0x7fff,0x8000,0xffff],[False,True],[2,0x603])]
 cases += [case(speed=speed,count=count,state=state,flags=flags,same=same) for speed,count,state,flags,same in itertools.product([0,1,5,6,85,86,127,128,255],[0,1,0xff,0x100,0xfffd,0xffff],[0,1,2,255],[2,0x603],[False,True])]
 cases += [case(ring=b,threshold=threshold,source_flags=bits,second=second,record=record,same=same) for b,threshold,bits,second,record,same in itertools.product([0,1,2,3,5,7,63,64,127,128,255],[0,1,7,255],[0,0x8c,0xe0],[None,0,5],[0,128],[False,True])]
 cases += [case(callback_selector=selector,target=target,same=same,flags=flags) for selector,target,same,flags in itertools.product(range(256),TARGETS,[False,True],[2,0x603])]
 # Match initial/final window center to each coefficient's actual indexed center.
 for token,coef,bit,same,selector in itertools.product([0,19,20,29,30,79,80,127,128,255],[0,1,10,20,127,128,255],[0,1],[False,True],[0,16]):
  signedcoef=coef if coef<128 else coef-256;center=signedcoef*50;center+=500 if center>=0 else -500;center+=400 if center>=0 and bit else 0
  cases.append(case(window=(center-40)&65535,token=token,coef=coef,record=bit,selector=selector,same=same,external=0xf000 if token>=30 and token<128 else 0,presence=0 if token>=30 else 1))
 cases += [case(window=window,selector=selector,ring=ring,blocked=blocked,seedcounter=counter,raw_selector=raw,byte_field=field,word_field=field,control_field=control,same=same) for window,selector,ring,blocked,counter,raw,field,control,same in itertools.product([0,436,0xfe44],[0,16],[0,12,25,38,50,128],[0,1],[0,4],[1,151],[0,25],[0,2000],[False,True])]
 for name,values_ in [('iterations',[0,1,2]),('rows',[0,1]),('ring_calls',[0,1,2,3]),('guard_calls',[0,1,2]),('sample_calls',[0,1]),('child_calls',[0,1,2,3]),('control_calls',[0,1]),('dispatch_calls',[0,1])]:
  for v,window,token,same in itertools.product(values_,[0,436],[255,20],[False,True]):cases.append(case(**{name:v},window=window,token=token,coef=0,same=same))
 cases += [case(target=target,callback_selector=selector,same=same) for target,selector,same in itertools.product([0,1,0xffff,0x4674,0x48ae],[0,1,47,255],[False,True])]
 cases += [case(target=target,same=True,sp=sp,cl=cl,window=window,token=token) for target,sp,cl,window,token in itertools.product(TARGETS,[0x3334,0x3336,0x3338,0x52ca,0x52cc,0x5490,0x36d2,0x37f8,0x37f9,0x33e8,0x66e8,0x66ec,0x5efc],[0,1],[0,436],[255,20])]
 cases += [case(ds=ds,same=same,sp=sp,flags=flags) for ds,same,sp,flags in itertools.product([0,0xffff],[False,True],[24,0xffe0],[2,0x603])]
 # Genuine 1793 rejection calls after two initializer calls: both initializers
 # transform1->3, leaving every slot3 at the rejection-loop entry.
 cases += [case(long='reject1793',ring=3,second=1,ring_calls=1800,rows=8,same=same) for same in [False,True]]
 cases += [case(long='rows8193',rows=8193,ring_calls=2,same=False)]
 for _ in range(1024):cases.append(case(window=rng.randrange(65536),cl=rng.choice([0,1,128]),mode=rng.randrange(256),speed=rng.randrange(256),count=rng.randrange(65536),record=rng.randrange(256),callback_selector=rng.randrange(256),target=rng.choice(TARGETS+[0]),selector=rng.randrange(256),ring=rng.randrange(256),threshold=rng.randrange(256),accum=rng.randrange(65536),step=rng.randrange(65536),dx_high=rng.randrange(65536),dx_low=rng.randrange(65536),scalar=rng.randrange(65536),token=rng.randrange(256),coef=rng.randrange(256),flags=rng.choice([2,0x603]),same=rng.choice([False,True])))
 # Fresh v2 root contexts: the indexed flags are read BEFORE the late record
 # XOR, so explicit incoming5491/37F6 is separate from the record byte.
 cases += [case(threshold=0,window=436,second=seed,byte_field=field&255,word_field=field,same=same,flags=flags) for seed,field,same,flags in itertools.product(range(256),[0,25,199,2000,0xffe7,0xffff],[False,True],[2,0x603])]
 cases += [case(cl=1,marked=1,speed=speed,target=target,existing=existing,count=count,same=same) for speed,target,existing,count,same in itertools.product([1,6],[0x4929,0x4a18],[0,1],[0x100,0x200],[False,True])]
 cases += [case(target=0x495d,speed=64,armflag=flag,same=same) for flag,same in itertools.product([0,0x80],[False,True])]
 cases += [case(target=0x49e7,record=1,flag=flag,same=same) for flag,same in itertools.product([0,1],[False,True])]
 cases += [case(remaining=remaining,accum=accum,step=step,lo=lo,hi=hi,blocked=blocked,same=same) for remaining,accum,step,(lo,hi),blocked,same in itertools.product([0,1],[0,1,0x7fff,0x8000,0xffff],[0,1,0xffff],[(0,0),(0,1),(0xffff,0x7fff)],[0,1],[False,True])]
 cases += [case(second=5,row=row,stream=stream,selector=1,same=same) for row,stream,same in itertools.product([(1,100,0,0),(100,100,0,0),(1,10,0,0)],[0x3b31,0x3aed,0x3aec],[False,True])]
 cases += [case(threshold=0,window=window,selector=1,stream=(0x3b33+distance)&65535,row=row,same=same) for window,distance,row,same in itertools.product([436,600],[0,1,50,101,0xfffe],[(1,100,0,0),(1,100,0xff9c,0xff9c),(1,1,0,0),(1,0xffff,0,0x8000)],[False,True])]
 for token,coef,bit,flag,same in itertools.product([20,30,80],[0,128,255],[0,1],[0,1],[False,True]):
  signedcoef=coef if coef<128 else coef-256;center=signedcoef*50;center+=500 if center>=0 else -500
  if bit:center+=400 if center>=0 else -400 if flag else 0
  cases.append(case(threshold=0,window=(center-40)&65535,token=token,coef=coef,bit=bit,flag=flag,same=same,external=0xf000 if token>=30 else 0,presence=0 if token>=30 else 1))
 # Freshv3: priorbyte limit255 excludes4A78 becauseBYTE SHL isalways even.
 cases += [case(threshold=0,window=436,second=0,byte_field=before,byte_limit=limit,same=same,flags=flags) for before,limit,same,flags in itertools.product([0,230,231,255],[0,1,49,50,51,254,255],[False,True],[2,0x603])]
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def peek(sg,o):at=((sg<<4)+(o&65535))&0xfffff;return int.from_bytes(u.mem_read(at,1)+u.mem_read((at+1)&0xfffff,1),'little')
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   sg=(cpu.reg_read(UC_X86_REG_CS)-load)&65535;ip=cpu.reg_read(UC_X86_REG_IP);require((sg,ip) in fence,'Fence '+hex(address))
   if (sg,ip) in returns:active['return']=(sg,ip);cpu.emu_stop();return
   category='iterations' if ip==0x46ca else 'rows' if ip in [0x4735,0x4c3e] else 'ring_calls' if ip in [0x46f4,0x4713,0x475b] else 'guard_calls' if ip in [0x49fe,0x4a10,0x4a26,0x4b7e,0x4b90,0x4d0e] else 'sample_calls' if ip in [0x4b96,0x4d14,0x4d1d] else 'child_calls' if ip in [0x4a31,0x4a39,0x4a41] else 'control_calls' if ip==0x460e else 'dispatch_calls' if ip==0x491d else None
   if category:
    if active[category]==getattr(active['limits'],category):active['prefix']=3;cpu.emu_stop();return
    if ip==0x491d:
     target=peek(cpu.reg_read(UC_X86_REG_DS),cpu.reg_read(UC_X86_REG_BX)+0x33e6)
     if target not in TARGETS:active['prefix']=6;active['unresolved_target']=target;cpu.emu_stop();return
     active['targets'].add(target);active['callback_selectors'].add(cpu.reg_read(UC_X86_REG_BX)//2)
    active[category]+=1
   if ip in calls or ip==0x491d:
    active['frames'].append((cs,ip+(4 if ip==0x491d else calls[ip]['size']),cpu.reg_read(UC_X86_REG_SP),'dispatch' if ip==0x491d else f'{ip:04X}'))
    if ip in root_calls:active['direct_calls']+=1
   if ip==0x4c68:
    divisor=cpu.reg_read(UC_X86_REG_BP);divisor=divisor if divisor<32768 else divisor-65536;wide=(cpu.reg_read(UC_X86_REG_DX)<<16)|cpu.reg_read(UC_X86_REG_AX);wide=wide if wide<0x80000000 else wide-0x100000000
    quotient=None if not divisor else abs(wide)//abs(divisor)*(1 if (wide>=0)==(divisor>=0) else -1)
    if quotient is None or not -32768<=quotient<=32767:active['prefix']=4;cpu.emu_stop();return
   if ip==0x47bf:require(cpu.reg_read(UC_X86_REG_CX)>cpu.reg_read(UC_X86_REG_DX),'Guarded DIV predicate')
   if ip==0x475b:active['rejection_calls']+=1
   if ip==0x4735 and cpu.reg_read(UC_X86_REG_SI)==0 and active['rows']>1:active['source_row_wraps']+=1
   active['instructions']+=1;active['sites'].add((sg,ip))
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=ds if c['same'] else 0x9000;sp=c['sp'];flags=c['flags']
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   def wb(o,v):put(ds,o,v,1)
   for i in range(256):wb(0x66e8+i,c['ring'])
   if c['second'] is not None:wb(0x66e8+((c['cursor']-2)&255),c['second'])
   if c['long']=='reject1793':wb(0x66e8+((c['cursor']-1)&255),1)
   for i in range(128):wb(0x368a+i,255);wb(0x370a+i,0)
   for i in range(80):put(ds,0x1db4+4*i,c['presence'])
   for i in range(129):put(ds,0x54aa+2*i,c['scalar'])
   for i in range(256):put(ds,0x33e6+2*i,0x4a18)
   for i in range(128):put(ds,0x347e+4*i,0);wb(0x347e+4*i+2,0);wb(0x347e+4*i+3,0)
   wb(0x347e,c['record']);wb(0x347f,c['coef']);wb(0x347e+4*c['callback_record']+3,c['callback_selector']);put(ds,0x33e6+2*c['callback_selector'],c['target'])
   for o,v in [(0x52cc,c['window']),(0x52ce,(c['speed']<<8)|0x20),(0x52c8,c['count']),(0x52ca,c['stream']),(0x3320,c['remaining']),(0x5342,c['deadline']),(0x2f46,c['accum']),(0x2f4a,c['accum']),(0x2f48,c['accum']),(0x3322,c['step']),(0x3338,c['lo']),(0x333a,c['hi']),(0x23b2,c['dx_low']),(0x23b4,c['dx_high']),(0x37a6,0),(0x66e6,c['cursor']),(0x8a9a,c['blocked']),(0x3328,c['multiplier']),(0x33c8,c['word_field']),(0x33ca,c['word_field']),(0x33cc,c['word_field']),(0x52da,c['existing']),(0x9410,c['existing']),(0x940e,c['external'])]:put(ds,o,v)
   for o,v in [(0x3371,c['cl']),(0x33d5,c['marked']),(0x33b7,c['mode']),(0x5490,c['state']),(0x533e,c['selector']),(0x337a,c['threshold']),(0x33bd,c['source_flags']),(0x2f56,c['raw_selector']),(0x5491,c['bit']),(0x37f6,c['flag']),(0x337b,c['seedcounter']),(0x90a8,c['late']),(0x33c6,c['byte_field']),(0x2418,c['byte_limit'])]:wb(o,v)
   for i in range(32):wb(0x337c+i,7)
   if c['row'] is not None:
    for i,v in enumerate(c['row']):put(ds,0x37a6+2*i,v)
    put(ds,0x37ae,0)
   wb((c['stream']+1+0x3c)&65535,c['armflag'])
   wb((c['stream']+0x47)&65535,0);wb((c['stream']+1)&65535,0);put(ss,(c['stream']+2)&65535,c['callback_record'],1)
   ix=(c['selector']+1)&127;wb(0x368a+ix,c['token']);wb(0x370a+ix,c['coef'])
   if 30<=c['token']<128:
    q,r=divmod(c['token']-30,5);put(c['external'],2*q+512*r,0x100);put(c['external'],0x100,c['width'])
   if c['long']=='rows8193':
    for offset in range(0x37a6,0x37a6+65536,8):put(ds,offset,1);put(ds,offset+2,0)
    for o,v in [(0x52ca,0x3aec),(0x52c8,0x100),(0x52cc,0),(0x66e6,1000)]:put(ds,o,v)
    wb(0x337a,255);wb(0x3aec+0x47,0);wb(0x66e8+((1000-1)&255),0);wb(0x66e8+((1000-2)&255),5)
   put(ss,sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);limits=Limits(*(c[n] for n in COUNTS));u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x4674),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update({n:0 for n in COUNTS});active.update(limits=limits,frames=[],instructions=0,writes=0,sites=set(),targets=set(),callback_selectors=set(),direct_calls=0,executing_return=False,prefix=0,unresolved_target=0,rejection_calls=0,source_row_wraps=0,**{'return':None});label=str((load,c));u.emu_start(cs*16+0x4674,0,count=150000);root=raw=False;rawkind=''
   while active['return']:
    sg,ip=active['return'];active['return']=None;active['sites'].add((sg,ip));active['instructions']+=1;active['executing_return']=True;u.emu_start((load+sg)*16+ip,0,count=1);active['executing_return']=False
    if not active['frames']:require((sg,ip)==(0x6c9,0x4673),'Root RET '+label);root=True;break
    segment,nextip,nextsp,kind=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(segment,nextip,nextsp):raw=True;rawkind=kind;break
    u.emu_start(u.reg_read(UC_X86_REG_CS)*16+u.reg_read(UC_X86_REG_IP),0,count=150000)
   require(root or raw or active['prefix'],'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);result=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(limits),C.byref(result));status=0 if root else 1 if raw else active['prefix'];require((result.status,result.current_sp,result.next_segment,result.next_ip)==(status,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
   require([getattr(result,n) for n in COUNTS+['direct_calls','bus_writes']]==[active[n] for n in COUNTS+['direct_calls']]+[active['writes']],'Counts '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(result.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and result.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((result.returned.carry,result.returned.registers.interrupts_enabled,result.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'CFIFDF '+label);require((result.flags_valid,result.zero_flag)==(int(root),(ef>>6)&1 if root else 0),'RootZF '+label);require(result.unresolved_target==active['unresolved_target'],'Unknown target '+label)
   if c['long']=='reject1793':require(active['rejection_calls']==1793,'Actualrejectionbound '+label)
   if c['long']=='rows8193':require(status==3 and result.next_ip==0x4735 and result.rows==8193 and result.returned.registers.si==8 and active['source_row_wraps']==1,'Actualrowwrap '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['root_RET' if root else 'raw_'+rawkind if raw else 'prefix_'+str(active['prefix'])]+=1;coverage['changed_root_coordinates']+=int(root and result.next_ip!=0x1111);coverage['DS_equals_SS']+=int(ds==ss);coverage['rejection_calls']+=active['rejection_calls'];coverage['actual_1793_rejection_loops']+=int(c['long']=='reject1793');coverage['actual_8192_source_row_cycles']+=active['source_row_wraps']
   for n in COUNTS+['direct_calls']:coverage[n]+=active[n]
   for target in active['targets']:coverage[f'target_{target:04X}']+=1
   for selector in active['callback_selectors']:coverage[f'callback_selector_{selector:02X}']+=1
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'root_sites':len({ip for sg,ip in sites if sg==0x6c9 and ip in next(f for f in fs if f['entry']=='06C9:4674')['instructions']})}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{sg:04X}:{ip:04X}' for sg,ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence,'Coverage '+str([f'{sg:04X}:{ip:04X}' for sg,ip in sorted(fence-sites)]));require(all(coverage[f'target_{t:04X}']>0 for t in TARGETS) and coverage['actual_1793_rejection_loops']==4 and coverage['actual_8192_source_row_cycles']>=2,'Target/loop witnesses')
 deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000380'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sim_controller.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Whole241-site4674/25actualbodies/687sites/actualSSnear-farframes/frozenCcalleecomposition/13recognized491Dtargets/currentDS-independentSS/operand-before-frame/read-after-write/CFIFDF-rootZF/GPR-BP/fullbus/control/counts/globalprefixcaps/unknown-targetprefix/rawchildRETneverfollowed. Validtargetdomain-allwriters/sharedsource-reset-IRQ-exclusion-storage-lifetime/whole403B-core open. No realDOSsession/devices/rendering/audio/fullresourcecodec/complete-state-machine/gameplay/fidelity; physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised']},indent=2))
if __name__=='__main__':main()
