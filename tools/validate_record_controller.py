"""Compare literal4D3F controller and actual4F92/5022/5446 children, SS FLAGS included."""

import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys

from collections import Counter

from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))

from validate_line_draw import Registers,StateRegisters,require,values

from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE

from unicorn.x86_const import *

class Result(C.Structure):

 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','child_iterations','bus_writes','flag_words_written']]+[(n,C.c_uint16) for n in ['defined_flags','defined_mask','last_pop_flags','first_return_site']]+[('returned',StateRegisters)]



def main():

 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--alias-only',action='store_true');p.add_argument('--profiles',type=int,default=64);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint16,C.c_uint32,C.c_uint32,C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==60,'Result layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=['06C9:4D3F','06C9:4F92','06C9:5022','06C9:5446'];fence={ip for f in g['functions'] if f['entry'] in entries for ip in f['instructions']};call_sites={0x4e1d,0x4e55,0x4e7b,0x4e9d,0x4ed1,0x4ef9,0x4f16,0x4f51,0x4f6d,0x4f8a};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()

 for load in [0x1000,0x2345]:

  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)

  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)

  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}

  def word(seg,off):return int.from_bytes(u.mem_read(((seg<<4)+off)&0xfffff,2),'little')

  def code(cpu,address,size,unused):

   if active.get('executing_return'):return

   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Controller escaped '+hex(address))

   if ip in [0x4f91,0x4fa9,0x5016,0x5021,0x50a0,0x54f3]:active['return_kind']='root' if ip==0x4f91 else 'child';u.emu_stop();return

   if ip in [0x4d41,0x4da3] or ip in call_sites:

    if active['steps']==active['limit']:active['prefix']='root';u.emu_stop();return

    active['steps']+=1

   if ip in call_sites:active['calls']+=1;active['child_iterations']=0;active['site']=ip;active['expected_sp']=u.reg_read(UC_X86_REG_SP)

   if ip in [0x4fda,0x5026,0x5477,0x54aa]:

    if active['child_iterations']==active['child_limit']:active['prefix']='child';u.emu_stop();return

    active['child_iterations']+=1;active['iterations']+=1

   if ip==0x4e27:

    # AF1 is a synthetic ISA-undefined-bit stimulus only on the XOR path.

    if active['af'] and active['first_return_site']==0x5016:u.reg_write(UC_X86_REG_EFLAGS,u.reg_read(UC_X86_REG_EFLAGS)|0x10);active['synthetic_af']=True

    active['flag_words']+=1

   if ip==0x4e58:

    active['last_pop_flags']=word(u.reg_read(UC_X86_REG_SS),u.reg_read(UC_X86_REG_SP))

    if active['last_pop_flags']&0x7100:active['prefix']='cpu';u.emu_stop();return

   active['instructions']+=1;active['sites'].add(ip)

  def written(cpu,access,address,size,value,unused):active['writes']+=1

  def interrupt(*unused):raise RuntimeError('No platformINT or CPU-event execution admitted')

  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)

  cases=list(itertools.product(range(a.profiles),[0,1],[2,0x603],[20,0xe000],[0,8,64],[0,1,128],[0,1]))

  # Optional5446 explicit supported and unsupported actualSS flag-slot aliases.

  cases +=[(10000,1,flags,sp,64,128,af) for flags,sp,af in itertools.product([2,0x203,0x402,0x603],[0xe000,0x52de,0x3350,0x52e0,0x33ba,0x334e,0x3356],[0,1])]

  cases +=[(profile,same,flags,sp,64,256,af) for profile,same,flags,sp,af in itertools.product([10001,10002,10003],[0,1],[2,0x203,0x402,0x603],[20,0xe000],[0,1])]

  cases +=[(10004,1,flags,0x52da,64,128,af) for flags,af in itertools.product([2,0x203,0x402,0x603],[0,1])]
  if a.alias_only:cases=[v for v in cases if v[0] in [10000,10004]]
  for profile,same,flags,sp,limit,child_limit,af in cases:

   rng=random.Random(0x4d3f0000+profile);data=bytearray(base);ss=ds if same else 0x9000

   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)

   def wb(o,v):data[ds*16+o]=v&255

   count=[8,16,24,32,33,0][profile%6];origin=[0,8,16,1,0xfff8][profile%5];ax=[0,1,0xffff,0x8000,0x7fff,0xa55a][profile%6];dx=[0,1,0x3b50,0x3b51,0x7fff,0x8000,0xffff,60][profile%8];delta=[0,1,255,256,0xffff,0x8000][profile%6];period=[0,1,100,0x3b51,0x8000,0xffff,360][profile%7]

   if profile in [10000,10004]:count=16;origin=ax=dx=delta=0;period=100

   for o,v in [(0x380d,period),(0x3811,[0,1,0x3b51,0x8000,0xffff][profile%5]),(0x5354,count),(0x5356,count),(0x8432,delta),(0x3332,0),(0x52d4,180),(0x52dc,360),(0x52da,0),(0x331c,0xffff)]:put(o,v)

   for o in [0x330c,0x330e,0x3310,0x3312,0x3314,0x3316]:put(o,origin)

   for o in [0x52c8,0x52d0,0x52d8]:put(o,ax)

   for o in [0x52ca,0x52d2]:put(o,dx)

   for o,v in [(0x3379,profile%2),(0x3375,(profile//2)%2),(0x33b5,profile%3),(0x33b8,(profile//2)%2),(0x33b7,[0,1,7][profile%3]),(0x33ba,profile%2),(0x37f6,profile%2),(0x52cf,0x47),(0x5490,0)]:wb(o,v)

   for record in [0x3813,0x39a3]:

    for k in range(6):

     hi=(dx+[-5,-4,-3,0,1,26,0x7fff,0x8000][(profile+k)%8])&65535;lo=(ax+[-1,0,1,255,256,0x7fff,0x8000,0xffff][(profile+k)%8])&65535;angle=[0,180,200,360,600,0x7fff,0x8000,0xffff,0xfd94,0xfdbd,0xff24][(profile+k)%11];typ=[4,6,0,0xffff][(profile+k)%4]

     if profile in [10000,10004]:typ=4;hi=lo=angle=0

     put(record+8*k,typ);put(record+8*k+2,hi);put(record+8*k+4,lo);put(record+8*k+6,angle)

     wb((hi-8)&65535,0x80 if profile%2 else 0);wb(hi,0x80 if profile%2 else 0)

   if profile in [10000,10004]:put(0x3811,0x3b51);wb(0x3379,0);wb(0x33b8,0)

   if profile in [10001,10002,10003]:

    for o,v in [(0x5354,16),(0x5356,16),(0x380d,100),(0x3811,0x3b51),(0x8432,0),(0x3332,0xff38),(0x52d4,0xff38 if profile==10001 else 200),(0x52c8,0),(0x52ca,0),(0x52d0,0),(0x52d2,0),(0x52da,1)]:put(o,v)

    for o in [0x330c,0x330e,0x3310,0x3312,0x3314,0x3316]:put(o,0)

    for base_offset in [0x3813,0x39a3]:

     for k in range(6):

      for field,v in [(0,6),(2,0),(4,0),(6,0)]:put(base_offset+8*k+field,v)

    for o,v in [(0x3379,1),(0x3375,0),(0x33b5,0),(0x33b8,0),(0x33b7,7),(0x37f6,0)]:wb(o,v)

   if profile==10004:
    put(0x52c8,0x40)
    for base_offset in [0x3813,0x39a3]:
     for k in range(6):put(base_offset+8*k+4,0x40)
   struct.pack_into('<H',data,ss*16+sp,0 if profile==10004 else 0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))

   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x4d3f),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)

   active.update(limit=limit,child_limit=child_limit,steps=0,calls=0,iterations=0,child_iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_kind=None,first_return_site=0,flag_words=0,last_pop_flags=0,af=af,synthetic_af=False);u.emu_start(cs*16+0x4d3f,0,count=2000000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{child_limit}/{af}'

   while active['return_kind']:

    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['return_kind']=None

    if kind=='child' and active['site']==0x4e1d:active['first_return_site']=ip

    active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False

    if kind=='root':root=True;break

    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,active['site']+3,active['expected_sp']):raw=True;break

    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=2000000)

   require(active['prefix'] or root or raw,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),af,limit,child_limit,C.byref(out));expected_status=5 if active['prefix']=='cpu' else 3 if active['prefix'] else 1 if raw else 0;actual_counts=(out.status,out.current_sp,out.steps,out.calls,out.child_iterations,out.bus_writes,out.flag_words_written,out.last_pop_flags,out.first_return_site);expected_counts=(expected_status,u.reg_read(UC_X86_REG_SP),active['steps'],active['calls'],active['iterations'],active['writes'],active['flag_words'],active['last_pop_flags'],active['first_return_site']);require(actual_counts==expected_counts,'Status/count '+label+str((actual_counts,expected_counts)));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.defined_flags&out.defined_mask)==(f&out.defined_mask),'DefinedFLAGS '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+str(active['prefix']) if active['prefix'] else 'raw_child_return' if raw else 'root_near_return']+=1;coverage['actual_near_CALLs']+=out.calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP20_cases']+=int(sp==20);coverage['DS_equals_SS_cases']+=same;coverage['synthetic_undefined_AF1_cases']+=active['synthetic_af'];coverage['literal_PUSHF_words']+=out.flag_words_written;coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111);coverage['optional5446_CALLs']+=int(0x4e55 in active['sites']);coverage['supported_flag_slot_alias_cases']+=int(profile==10004 and sp==0x52da and active['last_pop_flags']==0x40);coverage['unsupported_flag_slot_alias_cases']+=int(profile==10000 and active['prefix']=='cpu')

   if a.alias_only:print(json.dumps({'profile':profile,'sp':hex(sp),'flags':hex(flags),'status':out.status,'calls':out.calls,'last_pop':hex(out.last_pop_flags),'next':hex(out.next_ip)}),flush=True)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)

 require(sites==fence and coverage['supported_flag_slot_alias_cases']>0 and coverage['unsupported_flag_slot_alias_cases']>0 and coverage['synthetic_undefined_AF1_cases']>0,'Coverage '+str((fence-sites,dict(coverage))));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000387'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_controller.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual4D3F plus actual frozen4F92/5022/5446 C bodies, literalnearCALL/RET frames and actualSSPUSHF/POPFword aliases. NoSSscratch exclusions/ABI-valuemock. CPUanalysisprofile bit1set TF/IOPL/NT/reservedhigh0; explicitcallerundefinedAF input, AF1syntheticoriginalstimulus onlyafterXORAFundefined, nothistoricalCPUpolicy. UnsupportedTF/IOPL/NT overwrittenflagword stopsbeforePOPF/native5, noexception/modeeffect delivery. Fullbus/GPR/BP/CFIFDF/normaldefinedFLAGS/control/counts/prefixes. Allcallers/writers/lifetime/capacity/CPUprofile binding/exclusion/IRQs/fullstate/core/device/DOSsession/gameplay/fidelity remainseparate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))

if __name__=='__main__':main()

