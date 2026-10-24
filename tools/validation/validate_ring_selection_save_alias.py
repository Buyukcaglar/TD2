"""Scoped original/native saved-SI alias discriminator, excluded helper totals."""
import argparse,ctypes as C,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_ring_selection import Registers,StateRegisters,Result,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(lib)).td2ega_ring_selection;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={(int(f['entry'][:4],16),ip) for f in g['functions'] if f['entry'] in ['019E:0004','06C9:780E'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=changed=0;categories=set()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x19e;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   pair=(u.reg_read(UC_X86_REG_CS)-load,u.reg_read(UC_X86_REG_IP));require(pair in fence,'ScopedSIalias escaped')
   if pair==(0x19e,0x9a):active['root_return']=True;u.emu_stop();return
   active['instructions']+=1
  def written(cpu,access,address,size,value,unused):active['writes']+=1
  def interrupt(*unused):raise RuntimeError('NoINT/actualIRQ in scopedSIalias')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  for high in range(256):
   for flags in [2,0x203,0x402,0x603]:
    data=bytearray(base);sp=0x67f4;struct.pack_into('<H',data,ds*16+0x66e6,0);struct.pack_into('<2H',data,ds*16+sp,0x1111,0x2222);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,(high<<8)|0x56,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
    for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ds),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,4),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
    active.update(writes=0,instructions=0,executing_return=False,root_return=False);u.emu_start(cs*16+4,0,count=1000);require(active['root_return'],'Actual root return reached');active['executing_return']=True;u.emu_start(cs*16+0x9a,0,count=1);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ds,sp,C.byref(incoming),1,C.byref(r));require(r.status==0 and r.calls==1 and r.bus_writes==active['writes'] and r.current_sp==sp+4,'Status');require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Fullbus/SIsave');require([u.reg_read(reg) for reg in regs]==values(r.returned.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.returned.bp,'GPR');f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction),'CFIFDF');require((r.next_segment,r.next_ip)==(0x2222,0x1111),'Rootfarframe');after=((high<<1)|(high<128))&255;require(r.returned.registers.si==(after<<8)|0x56,'ActualPOPSI reads transformed highbyte');categories.add(after&7);changed+=int(after!=high);vectors+=1;instructions+=active['instructions']+1
 record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':'tools/validate_ring_selection.py','sha256':hashlib.sha256((ROOT/'tools/validate_ring_selection.py').read_bytes()).hexdigest()}],'original_instructions_executed':instructions,'changed_saved_SI_cases':changed,'categories':sorted(categories),'limits':'Scoped source/native discriminator only, excluded main helper-suite/vector totals. SP67F4/DS=SS/cursor0 means child PUSHSI highbyte atDS67E7 is selected by actualringDEC toFFFF; update thenactualPOPSI changes returnedSI. All256incomingSIhighbytes/fourIFDFprofiles/twoloads, actual019E0004/780E/fullbus/GPR/BP/CFIFDF/farframe. No actualIRQ/exclusion/seed/reset/writer/lifetime/core/session/gameplay/fidelity proof.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors,'changed_saved_SI_cases':changed,'instructions':instructions}))
if __name__=='__main__':main()
