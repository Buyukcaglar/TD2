"""Compare installed69B7 actualSS saves, pending aliases and IRET versus RETF2."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_sample_adjust import Registers,StateRegisters,require,values
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[('bus_writes',C.c_uint32)]+[(n,C.c_uint16) for n in ['zero_flag','flags_valid','return_kind','reserved']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:69B7')['instructions']);require(len(fence)==27,'Fence')
 fn=C.CDLL(str(lib)).td2ega_keyboard_bios_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.POINTER(Result)];fn.restype=None;require(C.sizeof(Result)==44,'Layout')
 saved_flags=[2|cf|(zf<<6)|(iff<<9)|(df<<10) for cf,zf,iff,df in itertools.product([0,1],repeat=4)]
 def case(**kw):
  c=dict(ah=0,low=0xa5,pending=0x1234,left=1,right=0,same=False,ss=None,ds=None,sp=0xe000,flags=2,saved=0x643);c.update(kw);return c
 cases=[case(ah=ah,low=ah^0xa5,pending=ah*257,same=same,flags=0x643 if ah&1 else 2,saved=flags,left=ah,right=ah^255) for ah,same,flags in itertools.product(range(256),[False,True],[2,3,0x642,0x643])]
 cases += [case(ah=ah,pending=pending,ds=ds,same=same,sp=sp,flags=flags,saved=0x643 if pending&1 else 2) for ah,pending,ds,same,sp,flags in itertools.product([0,1,2,255],[0,1,0xff,0x100,0x7fff,0x8000,0xffff],[None,0,0xffff],[False,True],[0xe000,0x62b2,0x62b4,0x62b6,0x62b8,0x62ba,0x62bc],[2,0x643])]
 cases += [case(ah=ah,pending=0x8000,same=True,sp=field+delta,ds=ds,flags=flags,saved=saved) for ah,field,delta,ds,flags,saved in itertools.product([0,1,2,3],[0x62b6,0x62e4,0x62f0],[-4,-2,0,2,4,6],[None,0x5000],[2,0x643],saved_flags)]
 cases += [case(ah=ah,ss=ss,sp=sp,flags=flags,saved=saved,pending=0xffff) for ah,ss,sp,flags,saved in itertools.product([0,1,2,3],[None,0,0xffff],[0,1,2,0xfffa,0xfffb,0xfffc,0xfffd,0xfffe,0xffff],[2,0x643],saved_flags)]
 rng=random.Random(0x69b7)
 for _ in range(128):cases.append(case(ah=rng.randrange(256),low=rng.randrange(256),pending=rng.randrange(65536),left=rng.randrange(256),right=rng.randrange(256),same=rng.choice([False,True]),flags=rng.choice([2,3,0x202,0x402,0x643]),saved=rng.choice(saved_flags)))
 vectors=instructions=0;sites=set();coverage=Counter();pattern=bytes((i*29+17)&255 for i in range(65536))
 for load in [0x1000,0x2345]:
  principal,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(image)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=cpu.reg_read(UC_X86_REG_IP);require(cpu.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Fence '+hex(address))
   if ip in [0x69d1,0x69e6]:active['return']=ip;cpu.emu_stop();return
   active['instructions']+=1;active['sites'].add(ip)
  def write(cpu,access,address,size,value,unused):active['writes']+=1
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
  for c in cases:
   data=bytearray(base);ds=principal if c['ds'] is None else c['ds'];ss=principal if c['same'] else 0x9000
   if c['ss'] is not None:ss=c['ss']
   sp=c['sp'];ef=c['flags'];data[principal*16:principal*16+65536]=pattern
   def put(sg,o,v,width=2):
    at=((sg<<4)+(o&65535))&0xfffff;data[at]=v&255
    if width==2:data[(at+1)&0xfffff]=(v>>8)&255
   put(principal,0x62b6,c['pending']);put(principal,0x62e4,c['left'],1);put(principal,0x62f0,c['right'],1);put(ss,sp,0x1111);put(ss,sp+2,0x2222);put(ss,sp+4,c['saved'])
   incoming=StateRegisters(Registers((c['ah']<<8)|c['low'],0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(ef>>9)&1,(ef>>10)&1),0x5678,ef&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x69b7),(UC_X86_REG_EFLAGS,ef)]:u.reg_write(reg,v)
   active.update(instructions=0,writes=0,sites=set(),executing_return=False,**{'return':None});label=str((load,c));u.emu_start(cs*16+0x69b7,0,count=100);require(active['return'],'Return '+label);ret=active['return'];kind=int(ret==0x69e6);boundary=u.reg_read(UC_X86_REG_SP)>(0xfffc if kind else 0xfffa)
   if not boundary:active['instructions']+=1;active['sites'].add(ret);active['executing_return']=True;u.emu_start(cs*16+ret,0,count=1);active['executing_return']=False
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),C.byref(r));observed=u.reg_read(UC_X86_REG_EFLAGS);require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.return_kind)==(5 if boundary else 0,u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['writes'],kind),'Result '+label)
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'GPR '+label+str((values(r.returned.registers)[:8]+[r.returned.bp],[u.reg_read(reg) for reg in REGS]+[u.reg_read(UC_X86_REG_BP)])));require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(observed&1,(observed>>9)&1,(observed>>10)&1),'CFIFDF '+label);require((r.flags_valid,r.zero_flag)==(int(not boundary),(observed>>6)&1 if not boundary else 0),'NormalZF '+label)
   vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['AH_'+str(c['ah'])]+=1;coverage['pre_return_boundary' if boundary else 'RETF2' if kind else 'IRET']+=1;coverage['CPU_bus_writes']+=r.bus_writes;coverage['principalDS_equals_SS']+=int(ss==principal);coverage['changed_root_coordinates']+=int(not boundary and (r.next_segment,r.next_ip)!=(0x2222,0x1111));coverage['changed_saved_BX_or_DS']+=int((r.returned.registers.bx,r.returned.registers.ds)!=(incoming.registers.bx,incoming.registers.ds));coverage['AH0_saved_FLAGSword_cleared']+=int(c['ah']==0 and ss==principal and sp==0x62b2);coverage['AH1_forces_IF1_despite_saved_IF0']+=int(kind and not boundary and not (c['saved']&0x200))
   if vectors%4096==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'load':hex(load)}),flush=True)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites)}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and all(coverage[v] for v in ['IRET','RETF2','pre_return_boundary','changed_root_coordinates','changed_saved_BX_or_DS','AH0_saved_FLAGSword_cleared','AH1_forces_IF1_despite_saved_IF0']),'Coverage '+str(sorted(fence-sites)))
 records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records'];ident=next(f['id'] for f in records if any(e.get('segment')==0x6c9 and e.get('segment_offset')==0x69b7 for e in f['entries']));deps=['tools/validate_sample_adjust.py','tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validation/twenty_bit_bus.py','docs/recovery/evidence/td2ega-twenty-bit-bus-v1.json','docs/recovery/evidence/td2ega-keyboard-validation-v1.json'];record={'schema':1,'result':'pass','function_ids':[ident],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_keyboard_bios_bus.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':27,'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'AdditionalactualSS69B7/27sites/PUSHBX-PUSHDS-beforeprincipalDSread/orderedpendingword-clear-savedwords-actualreturnaliases/full1MiB20bitRAM/GPR-BP-CFIFDF-normalZF. AH1ORAX/IF1/RETF2 ignoresstackFLAGS; othersIRETrestoreactualSSFLAGSword. Native5beforeRETF2SP>FFFC orIRETSP>FFFA isqualifiedanalysisboundary/nohistoricalfault-returnclaim. OtherFLAGS/traps/actualINT-IRQdelivery/PIC/installerownership/caller-allwriters-lifetime-exclusion/whole420A-403B-core remainopen; oldAPI-C-DLLreceiptsfrozen/sameentrycountedonce. NoDOSsession/device/renderer/audio/fullresources/complete-state-machine/gameplay/fidelity;physical086Cunassigned/CGAbehindEGAclosure.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','original_instructions_executed','instruction_sites_exercised']},indent=2))
if __name__=='__main__':main()
