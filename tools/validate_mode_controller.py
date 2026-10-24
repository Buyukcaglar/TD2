"""Compare 53A6 with literal children, mutable near jumps and nonlocal SS return."""
import argparse,ctypes as C,hashlib,itertools,json,random,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_line_draw import Registers,StateRegisters,require,values
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['calls','nested_calls','iterations','bus_writes']]+[(n,C.c_uint16) for n in ['raw_target','dispatch_site','dispatch_offset','exit_kind']]+[('returned',StateRegisters)]
TARGETS=[0x5518,0x5527,0x5531,0x5561,0x556c,0x55a5,0x55b4,0x55be,0x5603,0x560e,0x5620,0x5637,0x5679]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Fresh private paths')
 image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
 fn=C.CDLL(str(library)).td2ega_mode_controller;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(Result)];require(C.sizeof(Result)==56,'Layout');g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());family=['06C9:'+v for v in ['53A6','56ED','5299','5446','52FD','5334','535B','4612']];fence={ip for f in g['functions'] if f['entry'] in family for ip in f['instructions']};md=Cs(CS_ARCH_X86,CS_MODE_16);rets={ip for ip in fence if next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)).mnemonic=='ret'};rootcalls={0x54f4,0x5581,0x5650};leafcalls={0x56fa,0x5715,0x572f,0x5756,0x575d,0x577a,0x5781,0x5787};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def readword(s,o):return int.from_bytes(u.mem_read(((s<<4)+o)&0xfffff,2),'little')
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Escaped '+hex(address))
   if ip in rets:active['return']=True;u.emu_stop();return
   if ip in rootcalls:
    if active['calls']==active['root_limit']:active['prefix']='root_call';u.emu_stop();return
    active['calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP),'leaf' if ip!=0x5650 else 'product'));active['leaf_calls']=0
   if ip in leafcalls:
    if active['leaf_calls']==active['leaf_limit']:active['prefix']='leaf_call';u.emu_stop();return
    active['leaf_calls']+=1;active['nested_calls']+=1;active['frames'].append((ip+3,u.reg_read(UC_X86_REG_SP),'nested'))
   if ip in [0x5299,0x5446]:active['local_iterations']=0
   if ip in [0x52bf,0x5477,0x54aa]:
    if active['local_iterations']==active['iteration_limit']:active['prefix']='iteration';u.emu_stop();return
    active['local_iterations']+=1;active['iterations']+=1
   if ip in [0x5514,0x55a1,0x57a7]:
    active['dispatch_site']=ip;active['dispatch_offset']=(u.reg_read(UC_X86_REG_BX)+{0x5514:0x3456,0x55a1:0x3446,0x57a7:0x3460}[ip])&65535;active['raw_target']=readword(u.reg_read(UC_X86_REG_DS),active['dispatch_offset'])
    if active['raw_target'] not in ([0x57ab,0x57b7,0x57cf] if ip==0x57a7 else TARGETS):active['prefix']='indirect';u.emu_stop();return
   if ip==0x585a:active['exit_kind']=1
   if ip in [0x53e3,0x5505,0x5592] and u.reg_read(UC_X86_REG_EFLAGS)&0x800:active['overflow_sites'].add(ip)
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No INT/faultdelivery admitted')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  cases=list(itertools.product(range(128),[0,1],[2,0x603],[36,0xe000,0x3330,0x2f5d],[0,1],[0,8],[0,4]))
  cases +=[(seed,seed%2,[2,0x203,0x402,0x603][seed%4],0xe000,2,8,8) for seed in range(10000,12000)]
  cases +=[(profile,same,flags,sp,2,8,8) for profile,same,flags,sp in itertools.product(range(20000,20018),[0,1],[2,0x203,0x402,0x603],[36,0xe000,0x3330,0x2f5d])]
  cases +=[(profile,1,flags,sp,2,8,8) for profile,flags,sp in itertools.product(range(20000,20018),[2,0x603],[0x332e,0x3374,0x33b6,0x52da,0x925a])]
  for profile,same,flags,sp,rootlimit,leaflimit,iterationlimit in cases:
   data=bytearray(base);ss=ds if same else 0x9000;rng=random.Random(0x53a60000+profile)
   def put(o,v):struct.pack_into('<H',data,ds*16+(o&65535),v&65535)
   def wb(o,v):data[ds*16+(o&65535)]=v&255
   for k in range(129):put(0x32ee+2*k,k*257+profile*31)
   for k in range(128):wb(0x347f+4*k,(profile*17+k*3)&255)
   for k in range(16):put(0x5636+2*k,k*4093+profile*17)
   data[ds*16+0x3446:ds*16+0x346a]=image[0x178f0+0x3446:0x178f0+0x346a]
   modes=[(0,0)]+[(v,0) for v in range(1,6)]+[(0,v) for v in range(1,9)]+[(3,4),(255,0),(0,255),(128,128)]
   b6,b7=modes[profile%len(modes)];high=[0,1,10,300,301,0xffff,0x8000,0x7fff][profile%8];origin=[0,8,16,1,0xfff8][profile%5];distance=[0,1,0xffff,0x7fff,0x8000,1600,3200,0xfb00][profile%8];period=[0,1,100,360,0x3b51,0x8000,0xffff][profile%7]
   if profile>=10000:high,origin,distance,period=[rng.randrange(65536) for _ in range(4)];b6,b7=modes[profile%len(modes)]
   for o,v in [(0x52da,high),(0x52de,distance),(0x52dc,[0,0xff38,200,1000,0x7fff,0x8000,0xffff,120][profile%8]),(0x3314,origin),(0x3316,origin),(0x330c,origin),(0x330e,origin),(0x331a,[0,255,256,257,1024,0x8000,0xff00,0xffff][profile%8]),(0x380d,period),(0x3811,period+10),(0x52d8,[0,1,0xffff,0xa55a][profile%4]),(0x52c8,[0,1,0xffff,0x8000][profile%4]),(0x52ca,high+[-200,-100,-5,0,1,5,100,200][profile%8]),(0x52ce,[0,0x1dff,0x1e00,0xffff][profile%4]),(0x52d0,[0,1,0xffff,0x8000][profile%4]),(0x52d2,high+[-3,0,3,60][profile%4]),(0x52d4,[-401,-400,0,399,400,800,801][profile%7]),(0x52d6,[0,0x3200,0x3300,0xffff][profile%4]),(0x3332,[0,180,360,0xffff,0x8000,0x7fff][profile%6]),(0x5362,[0,1,100,0xffff,0x8000,0x7fff][profile%6]),(0x5364,[0,1,20,100,0xffff][profile%5]),(0x5366,[0,1,255,0xffff,1600][profile%5]),(0x5368,[0,1,44,0xffff,0x8000,100][profile%6]),(0x5354,[0,8,16,33,0xffff][profile%5]),(0x5356,[0,8,16,33,0xffff][profile%5]),(0x3346,4*(profile%2)),(0x3328,[0,1,0xffff,0x8000][profile%4]),(0x5370,0xffff)]:put(o,v)
   for o,v in [(0x3379,profile%2),(0x33b6,b6),(0x33b7,b7),(0x33bb,[0,1,2,128,255][profile%5]),(0x33ba,0xa5),(0x2f56,profile%2),(0x2f5b,0)]:wb(o,v)
   for base_offset in [0x3813,0x39a3]:
    for k in range(6):put(base_offset+origin+8*k+2,high+[-3,-2,-1,0,1,2,3,59,60,61,0x7fff,0x8000][(profile+k)%12]);put(base_offset+origin+8*k+4,profile*17);put(base_offset+origin+8*k+6,[-401,-400,-1,0,399,400,800,801,0x7fff,0x8000][(profile+k)%10])
   for k in range(4):wb(high+10*k,[0,1,0x7f,0x80,0xff,0x81,0x40,0xc0][(profile+k)%8])
   if 10000<=profile<20000:
    if b6:put(0x3456+2*(b6-1),TARGETS[profile%13] if profile%7 else 0xfffe)
    elif b7:put(0x3446+2*(b7-1),TARGETS[profile%13] if profile%7 else 0)
    mode=b6|b7
    if mode:put(0x3460+2*(mode-1),[0x57ab,0x57b7,0x57cf,0,0xfffe][profile%5])
   if profile>=20000:
    # Explicit branch/overflow/nonlocal and real PUSHAX aliases, independent of random fields.
    for o,v in [(0x52d8,0),(0x52c8,0),(0x52d0,0),(0x52de,0),(0x331a,0),(0x5366,0),(0x380d,1000),(0x52ce,0),(0x5354,8),(0x5356,8),(0x330c,0),(0x330e,0),(0x3314,0),(0x3316,0)]:put(o,v)
    wb(0x3379,0);wb(0x33bb,0);wb(0x33b6,0);wb(0x33b7,0);put(0x52da,1);put(0x52ca,0);put(0x52d2,0)
    if profile in [20000,20001]:put(0x52da,[0x7fff,0x8000][profile-20000]);put(0x52ca,[0x8000,0x7fff][profile-20000])
    elif profile in [20002,20003]:wb(0x33b7,6);put(0x52da,[0x7fff,0x8000][profile-20002]);put(0x52ca,[0x8000,0x7fff][profile-20002])
    elif profile in [20004,20005]:wb(0x33b6,1);put(0x52da,[0x7fff,0x8000][profile-20004]);put(0x52d2,[0x8000,0x7fff][profile-20004])
    elif profile==20006:wb(0x33b7,1);put(0x52ca,201);put(0x3460,0x57b7)
    elif profile in [20007,20008]:wb(0x33b7,7);wb(0x2f56,1);put(0x3328,0xffff);put(0x52da,1 if profile==20007 else 4);put(0x52ce,0xffff)
    elif profile==20009:put(0x52ce,0);put(0x52d6,0x3300)
    elif profile==20010:put(0x52ce,0x3300);put(0x52d6,0x3300)
    elif profile==20011:wb(0x33b7,8);put(0x52da,301);put(0x52dc,0);put(0x3332,0)
    elif profile==20012:put(0x52da,100);put(0x3346,4)
    elif profile in [20013,20014]:
     wb(0x33b6,3 if profile==20013 else 0);wb(0x33b7,3 if profile==20014 else 0);put(0x52da,20);put(0x52d2,0xfffe);put(0x52ca,0xfffe);put(0x3332,0xffff);put(0x3464,0x57b7)
     for k in range(4):wb(20+10*k,1)
    elif profile==20015:wb(0x33b7,1);put(0x52da,400);put(0x52ca,0);put(0x3460,0x57b7)
    elif profile==20016:wb(0x33b6,1);put(0x52dc,360);put(0x3460,0x57b7)
    elif profile==20017:wb(0x33b7,1);put(0x52ca,401);put(0x3460,0x57b7)
   struct.pack_into('<H',data,ss*16+sp,0x1111);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x53a6),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(root_limit=rootlimit,leaf_limit=leaflimit,iteration_limit=iterationlimit,calls=0,nested_calls=0,leaf_calls=0,iterations=0,local_iterations=0,writes=0,instructions=0,sites=set(),overflow_sites=set(),executing_return=False,prefix=False,frames=[],raw_target=0,dispatch_site=0,dispatch_offset=0,exit_kind=0,**{'return':False});u.emu_start(cs*16+0x53a6,0,count=20000);raw=root=False;label=f'{load:x}/{profile}/{same}/{flags:x}/{sp:x}/{rootlimit}/{leaflimit}/{iterationlimit}'
   while active['return']:
    ip=u.reg_read(UC_X86_REG_IP);active['sites'].add(ip);active['instructions']+=1;active['return']=False;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if ip==0x585b:
     require(len(active['frames'])==1 and active['frames'][0][2]=='leaf','Nonlocal frame '+label);root=True;break
    if not active['frames']:root=True;break
    expected_ip,expected_sp,kind=active['frames'].pop()
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,expected_ip,expected_sp):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=20000)
   require(active['prefix'] or raw or root,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),rootlimit,leaflimit,iterationlimit,C.byref(out));expected_status=6 if active['prefix']=='indirect' else 3 if active['prefix'] else 1 if raw else 0
   require((out.status,out.current_sp,out.calls,out.nested_calls,out.iterations,out.bus_writes)==(expected_status,u.reg_read(UC_X86_REG_SP),active['calls'],active['nested_calls'],active['iterations'],active['writes']),'Status/count '+label+str(([getattr(out,n) for n in ['status','current_sp','calls','nested_calls','iterations','bus_writes']],active)))
   require((out.raw_target,out.dispatch_site,out.dispatch_offset,out.exit_kind)==(active['raw_target'],active['dispatch_site'],active['dispatch_offset'],active['exit_kind']),'Dispatch/exit '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['prefix_'+active['prefix'] if active['prefix'] else 'raw_child_return' if raw else 'nonlocal_root_return' if out.exit_kind else 'root_return']+=1;coverage['root_CALLs']+=out.calls;coverage['nested_CALLs']+=out.nested_calls;coverage['bus_write_events']+=out.bus_writes;coverage['minimumSP36_cases']+=int(sp==36);coverage['DS_equals_SS_cases']+=same;coverage['raw_root_returns']+=int(root and out.next_ip!=0x1111)
   for ip in active['overflow_sites']:coverage[f'OF1_before_{ip:04X}']+=1
   if root and active['dispatch_site'] in [0x5514,0x55a1]:coverage[f'parent_target_{active["raw_target"]:04X}']+=1
   if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}));return
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence-{0x5303} and coverage['nonlocal_root_return'] and all(coverage[f'OF1_before_{ip:04X}'] for ip in [0x53e3,0x5505,0x5592]),'Coverage '+str(([f'{ip:04X}' for ip in sorted(fence-sites)],dict(coverage))))
 record={'schema':1,'result':'pass','function_ids':['FN-EGA-000395'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_mode_controller.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'static_site_dispositions':[{'site':'06C9:5303','scope':'52FD entered from actual56ED under53A6','reason':'Adjacent JLE/JG exhaust unchanged ZF/SF/OF; not global dead code.'}],'fixture_coverage':dict(coverage),'limits':'Actual53A6/56ED/5299/5446/52FD/5334/535B/4612 C andliteralSSframes/fullbus/GPR/BP/CFIFDF/control/counts. Known actualnearwordtargets at5514/55A1 union13 and57A7 three; unknownnative6beforeJMP preservesoperand, notdomainclosure. 56EDPOPAX+nearRET consumesleaf/rootwords andexitsparent, noextraRET. Mode7savedAXactualSSreread after4612/post2F5Bwrite. OR-after-SBBwrapped-sign vs immediateJGEwide signedpredicate retained withOF1 witnesses. Nativebudget/rawreturn/unknownprefixes separate; allwriters/modes/actual403Bcaller/DS-SS/IRQ/core/resource/device/session/gameplay/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
