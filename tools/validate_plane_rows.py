"""Compare actual284F+C17 including early discarded-return continuations."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_state_loop import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_ip']]+[(n,C.c_uint32) for n in ['calls','iterations','writes','continuations']]+[('returned',StateRegisters)]


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,output=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_plane_rows;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None
 graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());root=next(f for f in graph['functions'] if f['entry']=='06C9:284F');span=next(f for f in graph['functions'] if f['entry']=='06C9:0C17');ips=set(root['instructions'])|{ip for ip in span['instructions'] if 0xc17<=ip<=0xcfd};call_sites={int(c['site'][5:],16):int(c['site'][5:],16)+c['size'] for c in root['calls']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();cases=[(start,flag,profile,same,target,256 if start!=17 else 8) for start,flag,profile,same,target in itertools.product([0,1,8,16,17,0x8000,0xffff],[0,4,0x20,0x24],range(6),[0,1],[0x28bd,0xb7b,0x1234,0xffff])];cases +=[(0,flag,profile,same,target,budget) for flag,profile,same,target,budget in itertools.product([0,4,0x20,0x24],range(6),[0,1],[0x28bd,0xb7b,0x1234,0xffff],[0,1,4])]
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);active={}
  def code(cpu,address,size,_):
   ip=address-cs*16
   if active['expected_jump'] is not None:
    require(ip==active['expected_jump'],'Actualtarget');active['expected_jump']=None
    if ip!=0x28bd:active['external_jump']=True;u.emu_stop();return
   if active['expected_call'] is not None and ip==0xc17:
    require(u.reg_read(UC_X86_REG_SP)==sp-2 and bytes(u.mem_read(active['ss']*16+sp-2,2))==struct.pack('<H',active['expected_call']),'Actualnearframe');active['expected_call']=None
   require(ip in ips,'Actualrowescapedfence '+hex(address))
   if ip in call_sites:
    if active['calls']==active['budget']:active['prefix']=True;u.emu_stop();return
    active['calls']+=1;active['expected_call']=call_sites[ip]
   if ip==0x2863:active['iterations']+=1
   if ip==0xcfd:active['continuations']+=1;active['target']=struct.unpack('<H',u.mem_read(ds*16+0x702,2))[0];active['expected_jump']=active['target']
   active['instructions']+=1;active['sites'].add(ip)
  def write(cpu,access,address,size,value,_):
   if u.reg_read(UC_X86_REG_IP) in [0xc7d,0xc80,0xc87,0xc8a,0xc91,0xc94,0xc9b,0xc9e,0xcb5,0xcc1,0xccd,0xcd9]:active['writes']+=1
  def interrupt(*_):raise RuntimeError('Unexpectedinterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_INTR,interrupt)
  for start,flag,profile,same,target,budget in cases:
   data=bytearray(base);ss=ds if same else 0x9000
   def put(at,v):struct.pack_into('<H',data,ds*16+(at&65535),v&65535)
   valuesets=[[8,16,32,48,64],[80,16,32,48,64],[0,0,0,0,0],[81,0x8000,0xffff,79,80],[0x7fff,0x8000,1,2,3],[7,8,9,80,79]];fields=[0x9c4,0xa7c,0xb34,0xbec,0xca4]
   for i in range(18):
    for at,v in zip(fields,valuesets[profile]):put(at+2*i,v)
    put(0xd5c+2*i,flag)
   for at,v in {0x2a26:0x5000,0x2a28:0xb000,0x2c2a:start,0x2c86:[0,80,0x8000,0xffff,16,32][profile],0x2c88:[80,0,0xffff,0x8000,32,16][profile],0x2c2e:[0,80,16,0xffff,1,79][profile],0x2c68:[80,0,64,0x8000,0x7fff,79][profile],0x5348:80,0x702:target}.items():put(at,v)
   for i in range(5):put(0x534a+2*i,i*3+profile)
   for i in range(4):put(0x5420+2*i,ds if profile==5 else 0x5000+i*0x1000)
   for i in range(64):data[ds*16+0x5428+i]=(i*37+profile*13)&255
   for i in range(8):data[ds*16+0x5468+i]=255>>i
   for si in list(range(0,36,2))+[0xfffe]:struct.pack_into('<H',data,cs*16+((0xb000+si)&65535),0x100)
   frame=struct.pack('<H',0x100);data[ss*16+sp-32:ss*16+sp+6]=b'\xa5'*32+frame+b'\xa5'*4;u.mem_write(0,bytes(data));flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x284f),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   active.update(ss=ss,budget=budget,calls=0,iterations=0,writes=0,continuations=0,expected_call=None,expected_jump=None,external_jump=False,prefix=False,instructions=0,sites=set());u.emu_start(cs*16+0x284f,cs*16+0x100,count=500000);label=f'{load:x}/{start:x}/{flag:x}/{profile}/{same}/{target:x}/{budget}';require(active['external_jump'] or active['prefix'] or (u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x100,sp+2),'Originalnormal/jump/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),budget,C.byref(out));require(out.status==(1 if active['external_jump'] else 3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and (out.calls,out.iterations,out.writes,out.continuations)==tuple(active[k] for k in ['calls','iterations','writes','continuations']),'Nativeoutcome/counts '+label);require(not active['external_jump'] or out.next_ip==active['target'],'RawexternalnextIP '+label);actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-32:ss*16+sp]=expected[ss*16+sp-32:ss*16+sp];require(actual==expected,'Fullnonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearrootframeguard '+label);coverage['external_jump' if active['external_jump'] else 'prefix' if active['prefix'] else 'normal']+=1;coverage['calls']+=out.calls;coverage['row_iterations']+=out.iterations;coverage['plane_writes']+=out.writes;coverage['discarded_return_continuations']+=out.continuations;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 missing=sorted(ips-sites);require(not missing,'Everyownedrow/helperlocation '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_id':'FN-EGA-000094','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_plane_rows.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_state_loop.py','sha256':hashlib.sha256((ROOT/'tools/validate_state_loop.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'Actual284F+C17body, earlydiscardnearreturn/JMP28BD skipsremainingrowcalls, otherrawDS0702targets explicitnonlocaloutcomes, normalRET2/nativecallbudget separate. CurrentDS/SSmask/CSlookup/RAMplanes/wordwrap/sharedaliases andGPR/BP/CFIFDF/fullnonframebus compared. No ABI-value leafmocks. Syntheticplanes/targets notactualwriterdomain/capacity/SS-DS/producer/resourceformat/IRQ/core/renderer/game/fidelity. Native diagnostics separate.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
