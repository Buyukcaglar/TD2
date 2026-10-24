"""Compare18B0 actual0B42/fullallocator-reader/fullSS/DECSFguard/orderedcursor-byte/farRET."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Request(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['vector','site','segment','stack_segment','stack_sp']]+[('incoming',StateRegisters)]
class WalkLimits(C.Structure):
 _fields_=[(n,C.c_uint32) for n in ['calls','iterations','align_calls','align_iterations','tail_calls','wrapper_calls','adjust_calls','records','services']]
class PublicLimits(C.Structure):
 _fields_=[('calls',C.c_uint32),('walk',WalkLimits)]
class BufferLimits(C.Structure):
 _fields_=[('calls',C.c_uint32),('public_heap',PublicLimits)]
class PullLimits(C.Structure):
 _fields_=[(n,C.c_uint32) for n in ['calls','services','read_mapper_calls','read_steps']]+[('buffer',BufferLimits)]
class Limits(C.Structure):
 _fields_=[('calls',C.c_uint32),('pull',PullLimits)]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','pull_calls','buffer_calls','public_calls','heap_calls','align_calls','tail_calls','wrapper_calls','adjust_calls','read_calls','read_steps','services','records','iterations','child_iterations','bus_writes']]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid']]+[('returned',StateRegisters)]
Service=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint8),C.POINTER(Request),C.POINTER(StateRegisters))
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def state(cpu):
 f=cpu.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[cpu.reg_read(reg) for reg in REGS],(f>>9)&1,(f>>10)&1),cpu.reg_read(UC_X86_REG_BP),f&1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Fresh private paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_stream_next_byte;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.POINTER(Limits),Service,C.c_void_p,C.POINTER(Result)];require(C.sizeof(Result)==100 and C.sizeof(Limits)==64,'Layout');graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());family=['13A8:'+v for v in ['18B0','0B42','0BE8','26A8','26F1','27D4','280E','2830','2852','28C0','247C','094A']];fence={ip for f in g['functions'] if f['entry'] in family for ip in f['instructions']};require(len(fence)==543,'Fence');proof=json.loads((ROOT/'docs/recovery/evidence/td2ega-block-align-context-v1.json').read_text())['parent_mode_proof'];excluded={int(v[5:],16) for v in proof['parent_excluded_sites']};require(len(excluded)==29,'Disposition');vectors=instructions=0;sites=set();coverage=Counter();root_steps={0x2700,0x2707,0x2758,0x275f};root_calls={0x27a1,0x27ad,0x27b5};returns={0x18c7,0x18d5,0x0b5c,0x0be6,0x0943,0x0973,0x0c4c,0x26ed,0x2748,0x27d3,0x280d,0x282f,0x2850,0x28bf,0x2915}
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x13a8;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);emulated_bus=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip==0x943 and u.reg_read(UC_X86_REG_SP)>0xfffc:active['qualification']=True;u.emu_stop();return
   if ip in returns:active['return']=ip;u.emu_stop();return
   if ip==0x18cc:
    if active['next_calls']==active['next_limit']:active['prefix']='next_call';u.emu_stop();return
    active['next_calls']+=1;active['frames'].append((0x18d1,u.reg_read(UC_X86_REG_SP)))
   if ip in [0xb8f,0xbb2]:
    if active['push_calls']==active['push_limit']:active['prefix']='parent_call';u.emu_stop();return
    active['push_calls']+=1;active['frames'].append((0xb92 if ip==0xb8f else 0xbb7,u.reg_read(UC_X86_REG_SP)))
   if ip==0x939:
    if active['read_calls']==active['parent_limits'].read_mapper_calls:active['prefix']='mapper_call';u.emu_stop();return
    active['read_calls']+=1;active['frames'].append((0x93c,u.reg_read(UC_X86_REG_SP)))
   if ip==0x24d0:
    if active['read_steps']==active['parent_limits'].read_steps:active['prefix']='read_step';u.emu_stop();return
    active['read_steps']+=1
   if ip in [0x2904,0x28a9,0x24a5,0x2504,0x2511,0x2522,0x2538] and len(active['requests'])==active['parent_limits'].services:active['prefix']='global_service';u.emu_stop();return
   if ip==0x0bf0:
    if active['stream_calls']==active['stream_limit']:active['prefix']='stream_call';u.emu_stop();return
    active['stream_calls']+=1;active['frames'].append((0x0bf5,u.reg_read(UC_X86_REG_SP)))
   if ip in [0x26ba,0x26e5]:
    if active['public_calls']==active['public_limit']:active['prefix']='public_call';u.emu_stop();return
    active['public_calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP)));active['public_call_sites'].add(ip)
    if ip==0x26ba:active['local_wrapper_calls']=0
   if ip in root_steps:
    if active['iterations']==active['limits'].iterations:active['prefix']='root_iteration';u.emu_stop();return
    active['iterations']+=1
   if ip in root_calls:
    if active['calls']==active['limits'].calls:active['prefix']='root_call';u.emu_stop();return
    active['calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP)));active['call_sites'].add(ip)
    if ip==0x27b5:active['local_align_calls']=0;active['local_align_iterations']=0
    else:active['local_tail_calls']=0
   if ip in [0x27e4,0x27ef]:
    if active['local_align_iterations']==active['limits'].align_iterations:active['prefix']='align_iteration';u.emu_stop();return
    active['local_align_iterations']+=1;active['child_iterations']+=1
   if ip==0x27ff:
    if active['local_align_calls']==active['limits'].align_calls:active['prefix']='align_call';u.emu_stop();return
    active['local_align_calls']+=1;active['align_calls']+=1;active['frames'].append((0x2802,u.reg_read(UC_X86_REG_SP)));active['local_tail_calls']=0
   if ip==0x2810:
    if active['local_tail_calls']==active['limits'].tail_calls:active['prefix']='tail_call';u.emu_stop();return
    active['local_tail_calls']+=1;active['tail_calls']+=1;active['frames'].append((0x2813,u.reg_read(UC_X86_REG_SP)));active['local_wrapper_calls']=0
   if ip==0x283e:
    if active['local_wrapper_calls']==active['limits'].wrapper_calls:active['prefix']='wrapper_call';u.emu_stop();return
    active['local_wrapper_calls']+=1;active['wrapper_calls']+=1;active['frames'].append((0x2843,u.reg_read(UC_X86_REG_SP)));active['local_adjust_calls']=0
   if ip in [0x286a,0x2883]:
    if active['local_adjust_calls']==active['limits'].adjust_calls:active['prefix']='adjust_call';u.emu_stop();return
    active['local_adjust_calls']+=1;active['adjust_calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP)));active['local_records']=0
   if ip==0x28c5:
    if active['local_records']==active['limits'].records:active['prefix']='record';u.emu_stop();return
    active['local_records']+=1;active['records']+=1
   if ip in [0x2904,0x28a9] and len(active['requests'])==active['limits'].services:active['prefix']='service';u.emu_stop();return
   if ip in [0x2700,0x2758] and u.reg_read(UC_X86_REG_EFLAGS)&0x400:active['DF1_lods']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def heap_response(r,site,profile):
   ret=StateRegisters.from_buffer_copy(bytes(r))
   if 40000<=profile<60000:ret.carry=0;ret.registers.direction=1;return ret
   if profile>=70000:ret.carry=0;ret.registers.direction=0;return ret
   mode=(profile//3)%7;ret.carry=int(mode in [1,2,4,6])
   if ret.carry:ret.registers.ax=8
   if mode>=3:
    ret.registers.bx=0xabcd;ret.registers.cx=0xbada;ret.registers.dx=0xcafe;ret.registers.si=0x6d20 if mode==5 else 0x6d34;ret.registers.di=0x6d2a;ret.registers.ds=ds+0x100;ret.registers.es=0x2468;ret.registers.interrupts_enabled=1-r.registers.interrupts_enabled;ret.registers.direction=1-r.registers.direction
    if mode==6:ret.bp=0xd000
   return ret
  def mutations(ss,sp,qsp,r,profile):
   if profile>=70000:return [(((ss<<4)+(qsp+8))&0xfffff,0x8000)]+[(((ss<<4)+0x8000+2*i)&0xfffff,v) for i,v in enumerate([0x1234,0x1357,0x2468,0xffff])]
   if profile>=60000:
    kind=profile%4
    if kind>=2:return []
    return [(((ss<<4)+(qsp if kind==0 else sp))&0xfffff,0x1357),(((r.registers.ds<<4)+r.registers.si)&0xfffff,0xa55a)]
   if profile>=30000:return []
   kind=(profile//2)%3
   if kind==0:return []
   return [(((ss<<4)+(sp if kind==1 else qsp))&0xfffff,0x1357),(((r.registers.ds<<4)+r.registers.si)&0xfffff,0xa55a)]
  def response(r,site,profile,ss,sp,qsp):
   if site==0x2904:
    ret=heap_response(r,site,profile);return ret,[(at,v,2) for at,v in mutations(ss,sp,qsp,ret,profile)]
   ret=StateRegisters.from_buffer_copy(bytes(r));rr=ret.registers;inc=r.registers;ret.carry=0;writes=[];mode=profile%10
   if 98200<=profile<98208:mode=[3,3,4,5,3,4,9,9][profile-98200]
   payload=[b'\xff',b'',b'A',b'A\r\nB',b'\r',b'\r',b'\r',b'\x00',b'\r',b'\r'][mode]
   if profile>=90000:payload=b'\r'
   if profile==98200:payload=b'\n'
   if profile==98201:payload=b'\x1a'
   if site==0x24a5:
    rr.ax=len(payload)
    if mode==2:ret.carry=1;rr.ax=1
    else:writes=[((((inc.ds<<4)+((inc.dx+i)&65535))&0xfffff),v,1) for i,v in enumerate(payload)]
    if mode==8:
     rr.bx=0;rr.cx=0xbada;rr.dx=0x7000;rr.si=0x1357;rr.di=0x2468;rr.ds=other;rr.es=0x7654;rr.interrupts_enabled=1-inc.interrupts_enabled;rr.direction=1-inc.direction
    if 92000<=profile<92010:ret.bp=[0,1,0xfffb,0xfffc,0xfffd,0xfffe,0xffff][(profile-92000)%7]
    if profile==95000:rr.ax=0x8000
   elif site==0x2504:rr.ax=0x5507;rr.dx=0x20 if mode==6 else 0;ret.carry=1
   elif site in [0x2511,0x2522]:
    rr.ax=0 if mode==9 else 1
    if mode==5 or 90000<=profile<91000:ret.carry=1;rr.ax=[0,1,0x13,0x14,0x20,0x21,0x22,0xff,0x8001][(profile//10)%9]
    elif mode!=9:writes=[((((inc.ds<<4)+inc.dx)&0xfffff),0x41 if mode==4 and profile!=98202 else 0xa,1)]
    if mode==9:rr.cx=2;rr.si=0x6001;rr.di=0x6000;rr.direction=1
   elif site==0x2538:rr.ax=0x1234;ret.carry=1
   else:raise RuntimeError('UnexpectedDOSsite '+hex(site))
   return ret,writes
  def interrupt(cpu,number,unused):
   site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site in [0x2904,0x24a5,0x2504,0x2511,0x2522,0x2538],'SyntheticDOSonly');r=state(u);require(r.registers.ax>>8==(0x4a if site==0x2904 else 0x3f) if site in [0x2904,0x24a5,0x2511,0x2522] else r.registers.ax==(0x4400 if site==0x2504 else 0x4201),'DOSidentity');qsp=u.reg_read(UC_X86_REG_SP);active['requests'].append([number,site,cs,active['ss'],qsp,*values(r.registers),r.bp,r.carry]);returned,writes=response(r,site,active['profile'],active['ss'],active['sp'],qsp)
   for reg,v in zip(REGS,values(returned.registers)[:8]):u.reg_write(reg,v)
   u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
   for at,v,size in writes:u.mem_write(at,v.to_bytes(size,'little'));active['service_write_events']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=[(p,s,f,sp,0 if kind==0 else 2,0 if kind==1 else 64,kind) for p,s,f,sp,kind in itertools.product(range(64),[0,1],[2,0x603],[78,0xe000,0x6f3c],range(5))];cases +=[(p,p%2,[2,0x203,0x402,0x603][p%4],0xe000,2,128,4) for p in range(10000,11000)];cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(range(30000,30016),[0,1],[2,0x203,0x402,0x603],[78,0xe000])];cases +=[(p,s,f,78,2,128,4) for p,s,f in itertools.product(range(40000,40004),[0,1],[2,0x603])];cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(range(50000,50002),[0,1],[2,0x203,0x402,0x603],[78,0xe000])];cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(range(60000,60021),[0,1],[2,0x203,0x402,0x603],[78,0xe000])]
  cases +=[(70000,s,f,sp,2,128,4) for s,f,sp in itertools.product([0,1],[2,0x203,0x402,0x603],[78,0xe000])]
  cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(range(48000,48002),[0,1],[2,0x203,0x402,0x603],[78,0xe000])]
  cases +=[(p,s,2,78,2,128,4) for p,s in itertools.product(range(80000,80256),[0,1])]
  cases +=[(p,s,f,sp,2,128,kind) for p,s,f,sp,kind in itertools.product(range(90000,90180),[0,1],[2,0x603],[78,0xe000],[4,5,6,7,8])]
  cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(list(range(92000,92007))+list(range(98200,98208))+[93000,94000,95000,96000,96002,97000],[0,1],[2,0x603],[78,0xe000])]
  cases +=[(96002,1,f,sp,2,128,4) for f,sp in itertools.product([2,0x603],[0x6dab,0x6d95])]
  cases +=[(p,s,2,78,2,128,kind) for p,s,kind in itertools.product(range(30000,30016),[0,1],[5,6,7,8,9])]
  cases +=[(p,s,f,sp,2,128,4) for p,s,f,sp in itertools.product(range(100000,100016),[0,1],[2,0x603],[78,0xe000,0x83f4])]
  for profile,same,flags,sp,publiclimit,iterationlimit,kind in cases:
   data=bytearray(base);key=[ds,ds+0x100,0,0xffff][profile%4];other=ds+0x200;ss=key if same else 0x9000;bx=0x6f26;request=[0,1,2,3,4,5,0xffed,0xffee,0xffff,0x7fff,0x8000][profile%11];shape=(profile//2)%10;end=[16,0x3010,0,0xffff][profile%4];initialize=bool((profile//4)%2);old_break=[0x3000,0x3001,0xfff0,0xfffe][profile%4]
   def put(sg,o,v):at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   def wb(sg,o,v):data[((sg<<4)+(o&65535))&0xfffff]=v&255
   if profile>=30000:key=ds+0x100;ss=key if same else 0x9000;request=4;shape=(profile-30000)%10;end=16 if profile%2 else 0x3010;initialize=bool(profile%2);old_break=0x3001
   if profile>=40000:shape=9;end=16;initialize=False
   if profile>=50000:key=0xffff if profile==50001 else ds+0x100;ss=key if same else 0x9000
   if profile>=70000:key=ds+0x100;ss=key if same else 0x9000;initialize=True;old_break=0x3001
   for segment in set([key,other,ds]):
    for o,v in [(bx,0 if initialize and segment==key else 0x3000),(bx+2,0x3000),(bx+6,end),(bx+8,0),(0x3000,0xfffe),(0x3002,0),(0x3004,0xfffe),(0x3006,0xfffe),(0x300a,0xfffe),(0x300e,0xfffe),(0x3010,0xfffe)]:put(segment,o,v)
   patterns={0:{0x3000:0x201},1:{0x3000:0x405},2:{0x3000:3,0x3004:0x201},3:{0x3000:3,0x3004:4,0x300a:0x405},4:{0x3000:4,0x3006:3,0x300a:0x201},5:{0x3000:4,0x3006:6,0x300e:0x405}}
   for o,v in patterns.get(shape,{}).items():put(key,o,v)
   if shape==6:put(key,bx+8,other);put(other,0x3000,0x405)
   if shape==7:put(other,0x3000,0x405)
   put(key,0x6f30,other if shape==7 else key);put(key,0x6f36,[0,1,3,7,0x7fff,0xffff][profile%6]);wb(key,0x6f3a,0xa5);put(key,0x6d2a,old_break if initialize else 16);put(key,0x6d2c,key);put(key,0x6d24,0 if kind==3 or profile>=40000 else 0xffff);put(key,0x6d9b,key)
   if profile>=30000:
    put(key,(ss-2)&65535,0);put(key,0x6f36,0)
    if profile==50000:put(key,(ss-2)&65535,0x203)
    if profile==30014:request=0xffff
    if profile==30015:request=0xffee
   stream=[0x1200,0x6f20,0x3000,(sp-4)&65535,0x6e90,0xfff8,0x6f24,0x8000][profile%8];channel=[0,1,19,20,0x7f,0x80,0xff,0x55][(profile//2)%8]
   if profile in [50000,50001]:stream=0x1200
   if profile in [48000,48001]:stream=0x6d28;channel=0
   baseptr=0 if profile%3==0 else 0x3002;cursor=[0x3002,baseptr,(baseptr+1)&65535,0,0xffff][(profile//5)%5];streamcount=[0,1,0xffff,0x8000][(profile//11)%4];streamflags=[0,1,0x11,0x41,0xff][profile%5];value=[0,1,0xff,0xffff,0x1234,0x8000][(profile//7)%6]
   if profile in [48000,48001,50000,50001,70000]:baseptr=0;streamflags=1;value=0x1234
   if 30000<=profile<80000:streamflags=1;streamcount=0
   if profile>=80000:stream=0x1200;channel=profile-80000 if profile<80256 else 0;baseptr=0x3002;cursor=0x3003;streamcount=0;streamflags=9;value=0x1234
   if profile==93000:streamflags=2
   if profile==94000:streamflags=1
   if profile==97000:baseptr=stream
   for segment in set([key,other,ds]):
    put(segment,0x6da2,128);wb(segment,0x6d9d,2+(profile//90)%2)
    for i in range(20):wb(segment,0x6dda+i,(0x80+13*i)&255)
    for h in [0,channel&127]:wb(segment,0x6da4+h,0x80 if profile%10 in [3,4,5,8,9] or profile>=90000 else 0xc0 if profile%10==6 else 0)
    for o,v in [(0x1357,0x7000),(0x1359,7),(0x135b,0x7000)]:put(segment,o,v)
   if 98200<=profile<98208:
    for segment in set([key,other,ds]):wb(segment,0x6da4,0xc0 if profile in [98202,98203,98207] else 0x80)
   index=6*((channel&255) if (channel&255)<128 else (channel&255)-256);wb(key,0x6e94+index,1 if profile==94000 else 0);put(key,0x6e96+index,1 if profile in [98204,98205,98206] else 4)
   if 92000<=profile<92007:
    bp=[0,1,0xfffb,0xfffc,0xfffd,0xfffe,0xffff][profile-92000]
    for i,v in enumerate([0x1357,0x2468,0x369c,0,baseptr,4]):put(ss,bp+2*i,v)
   if profile>=100000:
    streamcount=[0,1,0xffff,0x8000,0x8001,0x7fff][(profile-100000)%6]
    if profile==100012:cursor=stream;streamcount=1
   for o,v in [(stream,cursor),(stream+2,streamcount),(stream+4,baseptr)]:put(key,o,v)
   wb(key,(stream+6)&65535,streamflags);wb(key,(stream+7)&65535,channel)
   if profile in [48000,48001]:put(key,0x6d30,key if profile==48000 else 0x1234);put(key,0x6d7a,0x6d32)
   put(key,0x83ee,[0,0xffff,0x7fff,0x8000][profile%4]);put(key,0x83f2,stream)
   for i,v in enumerate([0x1111,0x2222]):put(ss,sp+2*i,v)
   for i,v in enumerate([0x7777,0x4444,0x5555]):put(ss,0xd000+2*i,v)
   incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,key,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);limits=Limits(0 if kind==9 else 1,PullLimits(1 if kind==8 else publiclimit,0 if kind==3 else 1 if kind==5 else 8,0 if kind==7 else 1,0 if kind==6 else 32,BufferLimits(2,PublicLimits(2,WalkLimits(8,iterationlimit,8,64,1,0 if kind==2 else 1,1,32,0 if kind==3 else 8)))));u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x18b0),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(next_calls=0,next_limit=limits.calls,parent_limits=limits.pull,read_calls=0,read_steps=0,qualification=False,limits=limits.pull.buffer.public_heap.walk,push_limit=limits.pull.calls,push_calls=0,stream_limit=limits.pull.buffer.calls,stream_calls=0,public_limit=limits.pull.buffer.public_heap.calls,public_calls=0,public_call_sites=set(),ss=ss,sp=sp,profile=profile,calls=0,align_calls=0,tail_calls=0,wrapper_calls=0,adjust_calls=0,records=0,iterations=0,child_iterations=0,local_align_calls=0,local_align_iterations=0,local_tail_calls=0,local_wrapper_calls=0,local_adjust_calls=0,local_records=0,DF1_lods=0,service_write_events=0,writes=0,instructions=0,sites=set(),call_sites=set(),requests=[],frames=[],executing_return=False,prefix=False,**{'return':False});label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{publiclimit}/{iterationlimit}/{kind}';u.emu_start(cs*16+0x18b0,0,count=500000);raw=root=False
   while active['return']:
    ip=active['return'];active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip in [0x18c7,0x18d5]:require(not active['frames'],'Rootframe '+label);root=True;break
    expected_ip,expected_sp=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,expected_ip,expected_sp):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=500000)
   require(active['prefix'] or active['qualification'] or raw or root,'Outcome '+label);native_requests=[]
   @Service
   def callback(context,memory,request_pointer,result):
    q=request_pointer.contents;r=q.incoming;native_requests.append([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(r.registers),r.bp,r.carry]);returned,writes=response(r,q.site,profile,ss,sp,q.stack_sp);result[0]=returned
    for at,v,size in writes:
     for i in range(size):memory[(at+i)&0xfffff]=(v>>(8*i))&255
    return 1
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(limits),callback,None,C.byref(r));actual=(r.status,r.current_sp,r.calls,r.pull_calls,r.buffer_calls,r.public_calls,r.heap_calls,r.align_calls,r.tail_calls,r.wrapper_calls,r.adjust_calls,r.read_calls,r.read_steps,r.services,r.records,r.iterations,r.child_iterations,r.bus_writes);expected=(5 if active['qualification'] else 3 if active['prefix'] else 1 if raw else 0,u.reg_read(UC_X86_REG_SP),active['next_calls'],active['push_calls'],active['stream_calls'],active['public_calls'],active['calls'],active['align_calls'],active['tail_calls'],active['wrapper_calls'],active['adjust_calls'],active['read_calls'],active['read_steps'],len(active['requests']),active['records'],active['iterations'],active['child_iterations'],active['writes']);require(actual==expected,'Status/count '+label+str((actual,expected)));require(native_requests==active['requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require([u.reg_read(reg) for reg in REGS]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((ef&1,(ef>>9)&1,(ef>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);require(r.flags_valid==int(root) and r.zero_flag==((ef>>6)&1 if root else 0),'RequiredZF '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['preRET_qualification' if active['qualification'] else 'prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'root_far_return']+=1;coverage['next_CALLs']+=r.calls;coverage['pull_CALLs']+=r.pull_calls;coverage['stream_CALLs']+=r.buffer_calls;coverage['public_CALLs']+=r.public_calls;coverage['heap_CALLs']+=r.heap_calls;coverage['root_iterations']+=r.iterations;coverage['child_iterations']+=r.child_iterations;coverage['bus_write_events']+=r.bus_writes;coverage['service_write_events']+=active['service_write_events'];coverage['syntheticDOS4A']+=sum(q[1]==0x2904 for q in native_requests);coverage['read_mapper_CALLs']+=r.read_calls;coverage['read_LODS_steps']+=r.read_steps;coverage['read_services']+=sum(q[1]!=0x2904 for q in native_requests);coverage['IOCTL_requests']+=sum(q[1]==0x2504 for q in native_requests);coverage['lookahead_requests']+=sum(q[1] in [0x2511,0x2522] for q in native_requests);coverage['seekback_requests']+=sum(q[1]==0x2538 for q in native_requests);coverage['initial_DS_equals_SS_cases']+=int(key==ss);coverage['minimumSP78_cases']+=int(sp==78);coverage['root_LODSW_DF1']+=active['DF1_lods'];coverage['raw_root_returns']+=int(root and (r.next_segment,r.next_ip)!=(0x2222,0x1111))
   coverage['fast_root_returns']+=int(root and ip==0x18c7);coverage['slow_root_returns']+=int(root and ip==0x18d5)
   if profile==70000:require(raw and r.current_sp==0x8006 and (r.next_segment,r.next_ip)==(0x2468,0x1357),'ChangedBPchildrawcontrol '+label);coverage['actual_changedBP_child_raw_cases']+=1
   for ip in active['call_sites']:coverage[f'root_CALL_{ip:04X}_cases']+=1
   for ip in active['public_call_sites']:coverage[f'public_CALL_{ip:04X}_cases']+=1
   if root:coverage['returned_ZF1' if r.zero_flag else 'returned_ZF0']+=1
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-excluded and coverage['root_LODSW_DF1']>0 and coverage['raw_root_returns']>0 and coverage['fast_root_returns']>0 and coverage['slow_root_returns']>0,'Coverage '+str(([f'{ip:04X}' for ip in sorted(fence-sites-excluded)],dict(coverage))));deps=['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_stream_push_byte.py','tools/validate_stream_pull_byte.py','tools/validate_read_span.py','docs/recovery/evidence/td2ega-stream-pull-byte-context-v1.json','docs/recovery/evidence/td2ega-read-span-context-v2.json','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/td2ega-block-align-context-v1.json','docs/recovery/evidence/td2ega-heap-walk-context-v1.json','docs/recovery/evidence/td2ega-heap-public-context-v1.json','docs/recovery/evidence/td2ega-stream-buffer-context-v1.json'];record={'schema':1,'result':'pass','function_ids':[next(r['id'] for r in json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'] if any(e.get('segment')==0x13a8 and e.get('segment_offset')==0x18b0 for e in r['entries']))],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_stream_next_byte.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'sites':proof['parent_excluded_sites'],'scope':'2852enteredonlythroughactual2830fixedmode1/highguard0frame','reason':'Same29entry-specificdispositions asfrozenwrapperproof; standalone2852all53passed, notglobaldead.'}],'fixture_coverage':dict(coverage),'limits':'Actual18B0 PUSHCS+nearCALL farframe/fullSS/currentDS83EEcount-83F2stream/DECSFguard/cursorINCbeforebytefetch/actual0B42-fullallocator-reader/globalDOSbudget/rawRET-qualification. Wholebus/GPR-BP-CFIFDF/rootZF/requests/control/counts. Serialized20bitRAM/noMEM_READhook/syntheticDOSnoINTframes/historicalCPU-A20unqualified. No actualcaller/allwriters-indexdomains-bufferbounds-storage-capacity-ownership-lifetime-exclusion/core/resource/device/session/gameplay/fidelity closure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
