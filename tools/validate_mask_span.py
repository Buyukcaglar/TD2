"""Compare six RAM/device mask helpers, byte-count overflow and DF/LOOP edges."""
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
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,receipt_path=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and receipt_path.is_relative_to(ROOT/'docs/recovery/evidence') and not receipt_path.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_mask_span;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;entry_ips=[0x82d0,0x8336,0x839c,0xad22,0xad8b,0xadf4];g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{ip:04X}' for ip in entry_ips]];require(len(fs)==6,'Sixhelperfences');ips={ip for f in fs for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];heads={0x82d9,0x8307,0x831c,0x832e,0x833f,0x836d,0x8382,0x8394,0x83a5,0x83a7,0x83d7,0x83dd,0x83f0,0x8402,0xad2b,0xad2d,0xad4f,0xad5a,0xad75,0xad94,0xad96,0xadb8,0xadc3,0xadde,0xadfd,0xadff,0xae23,0xae2e,0xae4b};reps={0x82db,0x830d,0x8341,0x8373};reads={0xad2d:'ah',0xad4f:'cl',0xad5a:'ah',0xad63:'cl',0xad75:'dl',0xad7e:'dl',0xad96:'ah',0xadb8:'cl',0xadc3:'ah',0xadcc:'cl',0xadde:'dl',0xade7:'dl',0xadff:'ah',0xae23:'cl',0xae2e:'ah',0xae39:'cl',0xae4b:'dl',0xae54:'dl'};device_writes={0xad30:'al',0xad54:'cl',0xad5d:'ah',0xad68:'cl',0xad7a:'dl',0xad83:'dl',0xad99:'al',0xadbd:'cl',0xadc6:'ah',0xadd1:'cl',0xade3:'dl',0xadec:'dl',0xae04:'al',0xae28:'cl',0xae33:'ah',0xae3e:'cl',0xae50:'dl',0xae59:'dl'};ram_writes={0x82db,0x8307,0x830d,0x830f,0x831c,0x8320,0x832e,0x8341,0x836d,0x8373,0x8375,0x8382,0x8386,0x8394,0x83a7,0x83d7,0x83dd,0x83e3,0x83f0,0x83f4,0x8402};sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();alignments=list(range(8))+[0xffff];cases=[(entry,align,width,rows,flags,256,False) for entry,align,width,rows,flags in itertools.product(range(6),alignments,[0,1,2,3,7,127,128,255],[0,1,2,0x8000],range(4))];cases +=[(entry,align,width,2,flags,budget,False) for entry,align,width,flags,budget in itertools.product(range(6),[0,1],[0,1,3],range(4),[0,1,2,4,16])];cases +=[(0,1,1,0,3,200000,True),(2,0,0,1,3,200000,True)]
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def read_regs():
   f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
  def event(q):return [q.kind,q.site,q.stack_segment,q.stack_sp,q.port,q.value,q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
  def tick(iteration):
   if active['work']==active['budget']:active['prefix']=True;u.emu_stop();return False
   active['work']+=1;active['iterations']+=int(iteration);return True
  def byte_reg(name):
   reg={'al':UC_X86_REG_AX,'ah':UC_X86_REG_AX,'cl':UC_X86_REG_CX,'dl':UC_X86_REG_DX}[name];v=u.reg_read(reg);return (v>>8)&255 if name=='ah' else v&255
  def code(cpu,address,size,_):
   ip=address-cs*16;require(ip in ips,'Maskspanescapedfence '+hex(address))
   if (ip in heads or (ip in reps and u.reg_read(UC_X86_REG_CX)!=0)) and not tick(True):return
   if ip in reads or ip in device_writes:
    if not tick(False):return
    rr=read_regs();kind=2 if ip in reads else 3;physical=((rr.registers.es<<4)+rr.registers.di)&0xfffff;v=bytes(u.mem_read(physical,1))[0] if kind==2 else byte_reg(device_writes[ip]);q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.registers.dx,v,(C.c_uint16*5)(),physical,rr);active['events'].append(event(q))
   active['instructions']+=1;active['sites'].add(ip)
  def memory_write(cpu,access,address,size,value,_):
   if u.reg_read(UC_X86_REG_IP) in ram_writes|device_writes.keys():active['writes']+=1
  def interrupt(*_):raise RuntimeError('Unexpectedmaskspaninterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,memory_write);u.hook_add(UC_HOOK_INTR,interrupt)
  for entry,align,width,rows,flags,budget,full in cases:
   data=bytearray(base);ss=0x9000;stride=0 if full else [0,1,16,0xffff][(vectors>>1)%4];di=0 if full else [0,1,0xffff][vectors%3];incoming_dx=width if full or align else width|([0,0x8000][vectors&1]);maskoffset=(align-(0x7d38 if entry<3 else 0x52e6))&65535;data[cs*16+maskoffset]=[0xff,0x7f,0x3f,0x1f,15,7,3,1,0x55][alignments.index(align)] if entry<3 else [0,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe,0xaa][alignments.index(align)];frame=struct.pack('<H',0x100);data[ss*16+sp: ss*16+sp+6]=frame+b'\xa5'*4;u.mem_write(0,bytes(data));cpu_flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa500|flags,align,stride,incoming_dx,rows,di,ds,0x5000,(cpu_flags>>9)&1,(cpu_flags>>10)&1),0x5678,cpu_flags&1)
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,entry_ips[entry]),(UC_X86_REG_EFLAGS,cpu_flags)]:u.reg_write(reg,val)
   active.update(ss=ss,budget=budget,work=0,iterations=0,writes=0,prefix=False,events=[],instructions=0,sites=set());u.emu_start(cs*16+entry_ips[entry],cs*16+0x100,count=3000000);label=f'{load:x}/{entry}/{align:x}/{width:x}/{rows:x}/{flags}/{budget}/{full}';require(active['prefix'] or (u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x100,sp+2),'OriginalnearRET/prefix '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:
     q=q.contents;events.append(event(q));require(q.kind in [2,3],'OnlydevicebyteRead/Write')
     if q.kind==2:r.contents.value=bus[q.address]
     else:bus[q.address]=q.value
     return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn(bus,len(bus),load,ss,sp,entry,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.fault_site==0 and (out.work,out.iterations,out.calls,out.writes)==(active['work'],active['iterations'],len(active['events']),active['writes']) and events==active['events'],'Nativework/outcome/trace '+label+str(errors)+str((out.status,out.work,out.iterations,out.calls,out.writes,active['work'],active['iterations'],len(active['events']),active['writes'])));require(bytes(u.mem_read(0,len(data)))==bytes(bus),'Fullbus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,6))==frame+b'\xa5'*4,'Nearreturnguard '+label);coverage[f'{entry_ips[entry]:04X}']+=1;coverage['prefix' if active['prefix'] else 'normal']+=1;coverage['byte_writes']+=out.writes;coverage['device_reads']+=sum(e[0]==2 for e in events);coverage['device_writes']+=sum(e[0]==3 for e in events);coverage['full_zero_LOOP_cases']+=int(full);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 missing=sorted(ips-sites);require(not missing,'Unexercisedmaskspanlocations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000212','FN-EGA-000213','FN-EGA-000214','FN-EGA-000238','FN-EGA-000239','FN-EGA-000240'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_mask_span.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_exercised':len(sites),'instruction_sites_in_fence':len(ips),'fixture_coverage':dict(coverage),'limits':'SixcompleteRAM/device maskhelpers nearRET2, implicitGPR/BP/CFIFDF/fullbus, rawBXexternalCSmask/index/byteDL-DECoverflowJL/wordstride/DIwrap, REP0versusLOOP0/DECSIrow distinction andDFSTOSBversusexplicitINC retained. DeviceAH-lastreadclobber andXORAHbutSTOSBAL preserved, explicitbyteRead/Write traces syntheticflatbus only. Nativeworkprefix separate, noactualspritecaller/bounds/writers/device/renderer/resourcefed/IRQ/core/game/fidelity; native diagnostics separate.'};receipt_path.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
