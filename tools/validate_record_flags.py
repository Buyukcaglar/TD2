"""Compare4F92 defined return FLAGS, all INC DX words and raw return paths."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_record_math import Registers,StateRegisters,Result as BodyResult,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[('body',BodyResult)]+[(n,C.c_uint16) for n in ['defined_flags','defined_mask','return_site']]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_flags;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence=set(next(f for f in g['functions'] if f['entry']=='06C9:4F92')['instructions']);regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load,fast_flags in [(0x1000,0x603),(0x2345,2)]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Recordflags escaped '+hex(address))
   if ip in [0x4fa9,0x5016,0x5021]:active['return_site']=ip;u.emu_stop();return
   if ip==0x4fda:
    if active['iterations']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['iterations']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No platformINT in recordflags')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  def execute(incoming,ss,sp,flags,limit):
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x4f92),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,iterations=0,writes=0,instructions=0,sites=set(),executing_return=False,prefix=False,return_site=0);u.emu_start(cs*16+0x4f92,0,count=10000);require(active['prefix'] or active['return_site'],'Outcome')
   if active['return_site']:active['sites'].add(active['return_site']);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+active['return_site'],0,count=1);active['executing_return']=False
  def compare(bus,incoming,ss,sp,limit,label):
   result=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(result));r=result.body;require(r.status==(3 if active['prefix'] else 0) and r.current_sp==u.reg_read(UC_X86_REG_SP) and r.iterations==active['iterations'] and r.bus_writes==active['writes'],'Body/status '+label);require([u.reg_read(reg) for reg in regs]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR '+label);require((r.next_segment,r.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);expected_mask=0x603 if active['prefix'] else 0xec7 if active['return_site']==0x5016 else 0xed7;require(result.defined_mask==expected_mask and result.return_site==active['return_site'],'Mask/returnpath '+label);flags=u.reg_read(UC_X86_REG_EFLAGS);require((result.defined_flags&result.defined_mask)==(flags&result.defined_mask),'DefinedFLAGS '+label+str((hex(result.defined_flags),hex(flags),hex(result.defined_mask))));return result
  # Exhaustive INC DX cases have no source/native writes. Update only the
  # matching input highword in both buses; check zero write events per case
  # and compare the entire buses at each profile end, avoiding redundant
  # 1MiB snapshots for every unchanged-memory arithmetic fixture.
  for count in [8,16]:
   data=bytearray(base);ss=0x9000;sp=0xe000;struct.pack_into('<H',data,ss*16+sp,0x1111);struct.pack_into('<H',data,ds*16+0x3817,0);data[ds*16+0x33b4]=1;data[ds*16+0x33b9]=0;u.mem_write(0,bytes(data));bus=(C.c_uint8*len(data)).from_buffer_copy(data);incoming=StateRegisters(Registers(0,0xb123,count,0,0,0,ds,0x5432,(fast_flags>>9)&1,(fast_flags>>10)&1),0x3813,fast_flags&1)
   for dx in range(65536):
    incoming.registers.dx=dx;u.mem_write(ds*16+0x3815,struct.pack('<H',dx));bus[ds*16+0x3815]=dx&255;bus[ds*16+0x3816]=dx>>8;execute(incoming,ss,sp,fast_flags,128);result=compare(bus,incoming,ss,sp,128,f'INC/{load:x}/{count}/{dx:x}');require(active['writes']==0 and result.return_site==0x5021,'INC forcedskip/noeffects');vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['exhaustive_INC_DX_cases']+=1;coverage['AX0_ZF0_discriminators']+=int(result.body.returned.registers.ax==0 and (result.defined_flags&0x40)==0);coverage['defined_AF_cases']+=1
   require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus unchanged INC profile');coverage['wholebus_profile_end_checks']+=1
  cases=[(profile,same,flags,sp,limit,False) for profile,same,flags,sp,limit in itertools.product(range(64),[0,1],[2,0x203,0x402,0x603],[16,0xe000,0x381b],[0,1,4,128])];cases +=[(seed,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,[0,1,4,128][seed%4],True) for seed in range(2000)]
  for profile,same,flags,sp,limit,randomized in cases:
   rng=random.Random(0x4f920000+profile);data=bytearray(base);ss=ds if same else 0x9000;ax=[0,1,0xffff,0x7fff,0x8000,0xa55a][profile%6];dx=[0,1,0x3b50,0x3b51,0x7fff,0x8000,0xffff,0xfffe][profile%8];si=[0,8,16,1,0xfff8][profile%5];bp=[0x3813,0x39a3,0xdffc,0,0xfff8][profile%5];count=[8,16,24,33,0,0xffff][profile%6];di=[0,180,360,0x7fff,0x8000,0xffff][profile%6]
   if randomized:ax,dx,di=[rng.randrange(65536) for _ in range(3)]
   def put(o,v):at=ds*16+(o&65535);data[at]=v&255;data[at+1]=(v>>8)&255
   put(0x380d,[0,1,100,0x3b51,0x8000,0xffff][profile%6]);put(0x3811,[0,1,0x3b51,0x8000,0xffff][profile%5]);data[ds*16+0x33b9]=profile%2;data[ds*16+0x33b4]=[0,1,0x7f,0x80,0xff][profile%5]
   for k in range(5):
    at=(bp+si+8*k)&65535;put(at+4,(ax+[-1,0,1,0xffff][(profile+k)%4])&65535);put(at+2,(dx+[-5,-4,-3,0,1,0x7fff,0x8000,0xffff][(profile+k)%8])&65535);put(at+6,[0,180,360,0x7fff,0x8000,0xffff][(profile+k)%6])
   # Explicit nonzeroAX/zeroDX-afterINC discriminator.
   if profile==63:ax=0xa55a;dx=0xffff;si=0;bp=0x3813;put(bp+4,ax);put(bp+2,dx);data[ds*16+0x33b9]=0;data[ds*16+0x33b4]=1
   struct.pack_into('<H',data,ss*16+sp,0x1111);incoming=StateRegisters(Registers(ax,0xb123,count,dx,si,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),bp,flags&1);u.mem_write(0,bytes(data));bus=(C.c_uint8*len(data)).from_buffer_copy(data);execute(incoming,ss,sp,flags,limit);result=compare(bus,incoming,ss,sp,limit,f'general/{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{limit}/{randomized}');require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Generalwholebus/SS');vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['general_cases']+=1;coverage['budget_prefix' if active['prefix'] else f'return_{active["return_site"]:04X}']+=1;coverage['undefined_AF_excluded_cases']+=int(result.defined_mask==0xec7);coverage['AX_nonzero_ZF1_discriminators']+=int(result.body.status==0 and result.body.returned.registers.ax!=0 and bool(result.defined_flags&0x40));coverage['raw_near_returns']+=int(result.body.status==0 and result.body.next_ip!=0x1111);coverage['minimumSP16_cases']+=int(sp==16);coverage['bus_write_events']+=result.body.bus_writes
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['undefined_AF_excluded_cases']>0 and coverage['AX_nonzero_ZF1_discriminators']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000388'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_flags.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_record_math.py','tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Actual4F92 instructions against frozenrecord_math C plus read-onlyserialized pathclassifier/definedreturnFLAGS view. ThreeactualRETsites distinguished; rejectCMP/skipINCDX/fullstatusFLAGS, updateXORZF1/PF1/CF0/OF0/SF0 withundefinedAF excludedmask. Prefixmask onlyCF/IF/DF/bit1. ExhaustiveINC65536words/twoCFsetups/twoload-IFDFprofiles, zero source/native writeevents percase andwholebus atprofileend; generalcases fullbus/SS/GPR/BP/CFIFDF/definedFLAGS/control. Definedflags/mask isnot rawPUSHF image; CPUreserved/undefinedflags/stackwordownership andactual4D3F PUS H F/POPF/wholeparent stillopen beforecore. No actualIRQ/reset/writer/lifetime/device/session/gameplay/fidelity acceptance.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
