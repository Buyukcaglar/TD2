"""ObserveprivateUnicorn16farRETversustwoPOPs atwrappedSSoffset boundaries."""
import argparse,ctypes,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validation.twenty_bit_bus import map_twenty_bit_ram
import unicorn
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16
from unicorn.x86_const import *
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'analysis') and not out.exists();observations=[]
 for ss in [0x2000,0xffff]:
  for sp in [0,1,0xfffc,0xfffd,0xfffe,0xffff]:
   for form,code,count in [('farRET',bytes.fromhex('cb'),1),('twoPOPs',bytes.fromhex('585a'),2)]:
    u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);data=bytearray([0xa5])*0x100000;cs=0x3000;ip=0x100;data[(cs<<4)+ip:(cs<<4)+ip+len(code)]=code
    def word_at(at,v):data[at&0xfffff]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
    wrapped=((ss<<4)+((sp+2)&65535))&0xfffff;linear=((ss<<4)+sp+2)&0xfffff;word_at((ss<<4)+sp,0x1111);word_at(wrapped,0x2222)
    if linear!=wrapped:word_at(linear,0xabcd)
    u.mem_write(0,bytes(data))
    for reg,v in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_EFLAGS,2)]:u.reg_write(reg,v)
    u.emu_start((cs<<4)+ip,0,count=count);observations.append({'SS':ss,'initial_SP':sp,'form':form,'code':code.hex(),'wrapped_second_word_address':wrapped,'linear_second_word_address':linear,'final_SP':u.reg_read(UC_X86_REG_SP),'CS':u.reg_read(UC_X86_REG_CS),'IP':u.reg_read(UC_X86_REG_IP),'AX':u.reg_read(UC_X86_REG_AX),'DX':u.reg_read(UC_X86_REG_DX)})
 mismatches=[{'SS':ss,'SP':sp} for ss in [0x2000,0xffff] for sp in [0,1,0xfffc,0xfffd,0xfffe,0xffff] if next(o for o in observations if o['SS']==ss and o['initial_SP']==sp and o['form']=='farRET')['CS']!=next(o for o in observations if o['SS']==ss and o['initial_SP']==sp and o['form']=='twoPOPs')['DX']];assert mismatches==[{'SS':ss,'SP':sp} for ss in [0x2000,0xffff] for sp in [0xfffe,0xffff]]
 record={'schema':1,'result':'observed','script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'unicorn_version':unicorn.__version__,'observations':observations,'different_second_word_sources':mismatches,'limits':'FreshUc peropcodeform/shared20bitRAM/noMEM_READhook. FarRETreadslinearadjacentCSword across16bitSPboundary, twoactualPOPsreadwrappedSPword; finalSPwrapssame. Thisobservesprivatebackendbehavior, doesnotqualifyhistorical8086-286-386/realstacklimits/A20/faultdelivery or chooseoneasarchitecturaltruth.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'observed','microcases':len(observations),'different_second_word_sources':mismatches}))
if __name__=='__main__':main()
