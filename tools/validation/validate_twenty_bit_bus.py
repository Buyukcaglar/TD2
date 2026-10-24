"""Verify shared low/high Unicorn views without a memory-read hook."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validation.twenty_bit_bus import map_twenty_bit_ram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_AX,UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_IP
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);checks=[];writes=[]
 u.mem_write(0,b'\x34\x12');assert bytes(u.mem_read(0x100000,2))==b'\x34\x12';checks.append('low_api_write_visible_in_high_view')
 u.mem_write(0x100002,b'\x78\x56');assert bytes(u.mem_read(2,2))==b'\x78\x56';checks.append('high_api_write_visible_in_low_view')
 def written(cpu,access,address,size,value,unused):writes.append([address,size,value])
 u.hook_add(UC_HOOK_MEM_WRITE,written)
 def run(code):
  u.mem_write(0x20000,bytes.fromhex(code));u.reg_write(UC_X86_REG_CS,0x2000);u.reg_write(UC_X86_REG_IP,0);u.reg_write(UC_X86_REG_DS,0xffff);u.emu_start(0x20000,0,count=2)
 run('a11000a31200');assert u.reg_read(UC_X86_REG_AX)==0x1234 and bytes(u.mem_read(2,2))==b'\x34\x12' and writes==[[0x100002,2,0x1234]];checks.append('guest_word_read_and_write_high_view_alias_low_bytes');first=list(writes);writes.clear()
 # Distinct opcode forms use distinct Uc instances: shared host mappings do
 # not make rewriting guest code a qualified translation-cache operation.
 u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);u.hook_add(UC_HOOK_MEM_WRITE,written)
 run('b87856a30f00');assert backing[0xfffff]==0x78 and backing[0]==0x56 and bytes(u.mem_read(0xfffff,2))==b'\x78\x56';checks.append('guest_word_write_crosses_physical_20bit_boundary');second=list(writes);assert writes==[[0xfffff,2,0x5678]],writes
 assert bytes(u.mem_read(0,1))==bytes(u.mem_read(0x100000,1))==b'\x56';checks.append('cross_boundary_second_byte_shared_in_both_views')
 deps=['tools/validation/twenty_bit_bus.py','analysis/tools/python/unicorn/unicorn_py3/unicorn.py'];record={'schema':1,'result':'pass','vectors':len(checks),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'checks':checks,'guest_write_observations':[first,second],'limits':'Five private mapping/ISA microchecks, no original game functions or helper-vector count. Two guest mappings shareone1MiBhostallocation, explicitserialized20bitRAMfixtureprofile/noMEM_READhook. Wordwritehookeventcheckedatphysicalboundary; nothardwarebuscycles. HistoricalCPU/A20gate/segmentlimits/IRQ/device/session/core/gameplay/fidelity remainunqualified.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':len(checks),'guest_write_observations':[first,second]}))
if __name__=='__main__':main()
