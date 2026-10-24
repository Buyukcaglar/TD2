"""Compare five raw record arithmetic roots, SS saves and bounded loop prefixes."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['iterations','bus_writes']]+[('returned',StateRegisters)]
ENTRIES=[0x5299,0x5022,0x5446,0x4f92,0x5b5a]
IDS=['FN-EGA-000391','FN-EGA-000389','FN-EGA-000396','FN-EGA-000388','FN-EGA-000128']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_record_math;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fences=[set(next(f for f in g['functions'] if f['entry']==f'06C9:{ip:04X}')['instructions']) for ip in ENTRIES];exits={int(e['site'][5:],16) for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in ENTRIES] for e in f['exits']};allfence=set.union(*fences);budget_sites={0x52bf,0x5026,0x5477,0x54aa,0x4fda,0x5b87,0x5bf6};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fences[active['entry']],'Record math escaped '+hex(address))
   if ip in exits:active['return']=True;u.emu_stop();return
   if ip in budget_sites:
    if active['iterations']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['iterations']+=1
   if ip in [0x503b,0x546d,0x5490,0x54c3,0x4f9c,0x5006,0x5b6d,0x5bb3,0x5bdc,0x5c22]:
    # All of these instructions read a high word then SBB. A later branch uses its SF/OF pair.
    active['SBB_sites'].add(ip)
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT or division in record math')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=[]
  for entry in range(5):
   for profile,same,flags,limit in itertools.product(range(48),[0,1],[2,0x603],[0,1,2,5,16,256]):cases.append((entry,profile,same,flags,limit,False))
  for entry in range(5):
   for seed in range(1500):cases.append((entry,seed,seed%2,[2,0x203,0x402,0x603][seed%4],[0,1,2,5,16,128][seed%6],True))
  for entry,profile,same,flags,limit,randomized in cases:
   rng=random.Random(0x52990000+entry*100000+profile);data=bytearray(base);ss=ds if same else 0x9000;sp=[0xe000,16,0x3340,0x52c8][profile%4] if same else [0xe000,16][profile%2];ax=[0,1,0xffff,0x8000,0x7fff,0xfffe][profile%6];dx=[0,1,0x3b50,0x3b51,0x7fff,0x8000,0xffff,60][profile%8];si=[0,8,16,24,1,0xfff8][profile%6];count=[8,16,24,32,33,0,0xffff,1][profile%8];bp=[0x3813,0x39a3,0xdffc,0x5352,0xfff8,0][profile%6];bx=[0x1200,0x3322,0x3340,0xdffe,0xffed,0xfff0][profile%6];di=[0,1,0xff,0x80,0x7fff,0x8000,0xffff,180][profile%8]
   def put(o,v):at=ds*16+(o&65535);struct.pack_into('<H',data,at,v&65535)
   def setbyte(o,v):data[ds*16+(o&65535)]=v&255
   period=[0,1,2,100,0x3b51,0x8000,0xffff,360][profile%8];upper=[0,1,0x3b51,0x7fff,0x8000,0xffff][profile%6]
   if randomized:ax,dx,di,bx=[rng.randrange(65536) for _ in range(4)];period=rng.randrange(65536);upper=rng.randrange(65536)
   for o,v in [(0x380d,period),(0x3811,upper),(0x5356,count),(0x5354,count),(0x330e,si),(0x330c,[0,8,16,24][profile%4]),(0x52c8,ax),(0x52ca,dx),(0x52d0,(ax+profile)&65535),(0x52d2,(dx+[0,1,26,0x7fff,0x8000,0xffff][profile%6])&65535)]:put(o,v)
   setbyte(0x33b4,[0,1,0x7f,0x80,0xff][profile%5]);setbyte(0x33b9,profile%2)
   high=[0,1,3,26,60,0x7fff,0x8000,0xffc2,0xfff6,0xfffc,0xfffd,0xffff][profile%12]
   for base_offset in set([0x39a3,0x3813,bp]):
    for k in range(6):
     lo=(ax+[-1,0,1,0xffff][(profile+k)%4])&65535;hi=(dx+high+([-1,0,1,30][k%4]))&65535
     if randomized:lo,hi=rng.randrange(65536),rng.randrange(65536)
     put(base_offset+8*k+4,lo);put(base_offset+8*k+2,hi);put(base_offset+8*k+6,[0,180,360,0x7fff,0x8000,0xffff][(profile+k)%6])
   if entry==0:
    for k in range(128):setbyte(0x347f+4*k,rng.randrange(256) if randomized else [0,1,0x7f,0x80,0xff,(k*19)&255][profile%6])
    for k in range(129):put(0x32ee+2*k,rng.randrange(65536) if randomized else [0,1,0xff,0x100,0xffff,0x7f][profile%6])
    for k in range(4):setbyte(bx+10*k,(profile*13+k*43)&255)
   frame=struct.pack('<H',0x1111);data[ss*16+sp:ss*16+sp+2]=frame;incoming=StateRegisters(Registers(ax,bx,count,dx,si,di,ds,0x5432,(flags>>9)&1,(flags>>10)&1),bp,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ENTRIES[entry]),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(entry=entry,limit=limit,iterations=0,writes=0,instructions=0,SBB_sites=set(),sites=set(),executing_return=False,prefix=False,**{'return':False});u.emu_start(cs*16+ENTRIES[entry],0,count=20000);label=f'{load:x}/{entry}/{profile}/{same}/{flags:x}/{limit}/{randomized}';require(active['prefix'] or active['return'],'Outcome '+label)
   if active['return']:
    ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
   bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.iterations==active['iterations'] and out.bus_writes==active['writes'],'Status/count '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage[f'entry_{entry}']+=1;coverage['budget_prefix' if active['prefix'] else 'near_returns']+=1;coverage['iterations']+=out.iterations;coverage['bus_write_events']+=out.bus_writes;coverage['raw_near_returns']+=int(active['return'] and out.next_ip!=0x1111);coverage['minimumSP16_cases']+=int(sp==16);coverage['DS_equals_SS_cases']+=same;coverage['seeded_random_cases']+=int(randomized)
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(allfence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(allfence-sites)]}),flush=True)
 require(sites==allfence,'Coverage '+str([hex(ip) for ip in sorted(allfence-sites)]));record={'schema':1,'result':'pass','function_ids':IDS,'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_record_math.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(allfence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'Five actual no-call near roots5299/5022/5446/4F92/5B5A; signed SBB branches use full signed difference with low-word borrow, raw word records/rings and source-order rereads/writes, explicit DS:[BP+SI] overrides, actual SS saves/nearRET. Fullbus/GPR/BP/CFIFDF/control including native before-loop prefixes/raw altered RET target exposed after instruction, never followed. Synthetic fields/tables/unaligned bounds may cycle; no source units/fullformat/caller/writer/bounds/lifetime/exclusion/core/resource-fedP2/P3/device/session/game/fidelity admission.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
