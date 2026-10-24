"""Compare actual C838/C701 segmented member transpose and incoming DF."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['steps','calls','byte_transfers','bus_writes']]+[('returned',StateRegisters)]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_member_reorder;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());fence={ip for f in g['functions'] if f['entry'] in ['06C9:C838','06C9:C701'] for ip in f['instructions']};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();coverage=Counter()
 for load in [0x1000,0x2345]:
  ds,cs=load+0x178f,load+0x6c9;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={};executing_bytes=set()
  # Source instruction sizes are decoded directly; neither caller nor child
  # admits writes to executing instructions under this serialized profile.
  sys.path.insert(0,str(ROOT/'analysis/tools/python'))
  from capstone import Cs,CS_ARCH_X86,CS_MODE_16
  md=Cs(CS_ARCH_X86,CS_MODE_16)
  for ip in fence:
   ins=next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1));executing_bytes.update(range(cs*16+ip,cs*16+ip+ins.size))
  def code(cpu,address,size,unused):
   if active.get('executing_return'):return
   ip=u.reg_read(UC_X86_REG_IP);require(u.reg_read(UC_X86_REG_CS)==cs and ip in fence,'Member reorder escaped '+hex(address))
   if ip in [0xc89e,0xc75f]:active['return_kind']='root' if ip==0xc89e else 'child';u.emu_stop();return
   if ip in [0xc856,0xc8b9,0xc8d4] or (ip==0xc8ef and u.reg_read(UC_X86_REG_CX)!=0):
    if active['steps']==active['limit']:active['prefix']=True;u.emu_stop();return
    active['steps']+=1
   if ip==0xc864:active['calls']+=1;active['expected_sp']=u.reg_read(UC_X86_REG_SP)
   if ip==0xc8d6 or (ip==0xc8ef and u.reg_read(UC_X86_REG_CX)!=0):active['byte_transfers']+=1
   if ip==0xc862:active['principal_selects']+=1
   active['instructions']+=1;active['sites'].add(ip)
  def written(cpu,access,address,size,value,unused):
   require(not any(at in executing_bytes for at in range(address,address+size)),'Unadmitted executing-code write');active['writes']+=1
  def interrupt(*unused):raise RuntimeError('No platform/divide in admitted member reorder')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
  shapes=[(0,0),(0,1),(1,0),(1,1),(2,3),(3,2),(8,4),(0xffff,2)];profiles=list(itertools.product([0,1,2,0x7fff,0x8000,0x8001,0xffff],shapes,[0,1,5,15]));cases=[]
  for index,(count,shape,mask) in enumerate(profiles):
   for same,flags,limit in itertools.product([0,1],[2,0x603],[0,1,4,16,256]):cases.append((count,shape,mask,0,[0,0x100,0xfff0][index%3],index%4,same,flags,limit,0xe000))
  for mask,skip,scratch,same,flags,limit in itertools.product(range(16),[0,0x10,0xf0],range(6),[0,1],[2,0x603],[0,4,80,1000]):cases.append((1,(2,3),mask,skip,0x100,scratch,same,flags,limit,0xe000))
  for count,shape,mask,same,flags,limit in itertools.product([0,1,0x8000],[(1,1),(2,3)],[0,1,15],[0,1],[2,0x203,0x402,0x603],[0,4,80]):cases.append((count,shape,mask,0,0,0,same,flags,limit,54))
  # Actual root return alias without reaching the argument words.
  cases +=[(1,(1,1),1,0,0,3,1,flags,80,0xe000) for flags in [2,0x603]]
  for count,shape,mask,skip,header_offset,scratch,same,flags,limit,sp in cases:
   if scratch in [2,3] and skip==0 and mask!=0 and shape!=(1,1) and limit>16:continue
   if scratch==3 and skip==0 and mask!=0 and shape!=(1,1) and limit>4:continue
   data=bytearray(base);ss=ds if same else 0x9000;header_segment=0x3000;scratch_segment=[0x6000,0x5000,ss,ss,0x6000,0x6000][scratch];scratch_offset=[0x1200,3,0xdfe4,sp,0xfff0,0][scratch];width,height=shape
   def put(s,o,v):at=((s*16)+(o&65535))&0xfffff;data[at]=v&255;data[(at+1)&0xfffff]=(v>>8)&255
   put(header_segment,header_offset+4,count)
   for index in range(4):
    target=0x50003+index*0x1000;table=(4*count+4*index+6)&65535;base_linear=header_segment*16+((8*count+6)&65535);delta=(target-base_linear)&0xffffffff;put(header_segment,table,delta&65535);put(header_segment,(table+2)&65535,delta>>16);put(0x5000,3+index*0x1000,width);put(0x5000,5+index*0x1000,height);data[target+14]=(mask<<4)&255;data[target+15]=skip
    for k in range(256):data[target+16+k]=(index*31+k*19+7)&255
   args=[header_offset,header_segment,scratch_offset,scratch_segment];frame=struct.pack('<6H',0x1111,0x2222,*args);data[ss*16+sp:ss*16+sp+12]=frame;incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
   for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0xc838),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
   active.update(limit=limit,steps=0,calls=0,writes=0,instructions=0,byte_transfers=0,principal_selects=0,sites=set(),executing_return=False,prefix=False,return_kind=None);u.emu_start(cs*16+0xc838,0,count=1000000);raw=root=False;label=f'{load:x}/{count:x}/{shape}/{mask}/{skip}/{header_offset:x}/{scratch}/{same}/{flags:x}/{limit}/{sp}'
   while active['return_kind']:
    kind=active['return_kind'];ip=u.reg_read(UC_X86_REG_IP);sites.add(ip);active['instructions']+=1;active['return_kind']=None;active['executing_return']=True;u.emu_start(cs*16+ip,0,count=1);active['executing_return']=False
    if kind=='root':root=True;break
    if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=(cs,0xc869,active['expected_sp']):raw=True;break
    u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=1000000)
   require(active['prefix'] or root or raw,'Outcome '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.steps==active['steps'] and out.calls==active['calls'] and out.byte_transfers==active['byte_transfers'] and out.bus_writes==active['writes'],'Status/count '+label+str((out.status,out.steps,out.calls,out.byte_transfers,out.bus_writes,active)));require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/SS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs]+[u.reg_read(UC_X86_REG_BP)],values(r.registers)[:8]+[r.bp])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label+str((f&1,r.carry)));require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label);vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['budget_prefix' if active['prefix'] else 'raw_child_far_return' if raw else 'root_far_return']+=1;coverage['actual_C701_calls']+=out.calls;coverage['byte_transfers']+=out.byte_transfers;coverage['bus_write_events']+=out.bus_writes;coverage['raw_root_returns']+=int(root and (out.next_segment,out.next_ip)!=(0x2222,0x1111));coverage['minimumSP54_cases']+=int(sp==54);coverage['incoming_DF1_cases']+=int(bool(flags&0x400));coverage['SS_scratch_alias_cases']+=int(scratch in [2,3]);coverage['DEC8000_guard_returns']+=int(count==0x8000 and mask==0 and out.status==0 and out.calls==1);coverage['source_CX0_column_prefixes']+=int(width==0 and out.status==3 and out.next_ip==0xc8d4);coverage['nonzero_header_offset_cases']+=int(header_offset!=0);coverage['actual_caller_zero_scratch_offset_cases']+=int(scratch==5)
  print(json.dumps({'load':hex(load),'vectors_completed':vectors,'sites':len(sites),'missing':[f'{ip:04X}' for ip in sorted(fence-sites)]}),flush=True)
 require(sites==fence and coverage['DEC8000_guard_returns']>0 and coverage['source_CX0_column_prefixes']>0,'Coverage '+str(fence-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000252'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_member_reorder.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'fixture_coverage':dict(coverage),'limits':'ActualC838+actualC701, fourSSargs/header-segment/principal/member/scratch DS transitions, nibble-normalizedfar addresses/raw count/shapes/flags, incomingDF STOSB/REP vs explicit forward-stride source, actualSSlocals/saves/near-farframes/fullbus/GPR/BP/CFIFDF/control. Word/bytewrap, zero-CX do-onceLOOP, signedDEC count8000 overflow guard, orderedtranspose/copyback/rereads. Native beforemember/plane/byte/REP budget distinct; executing-code writes excluded and checked. Synthetic table/member payload only, no suppliedresource decoding/fullformat/producer/capacity/allwriters/lifetime/exclusion/newcallerFLAGS/core/realdevice/session/gameplay/fidelity acceptance.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
