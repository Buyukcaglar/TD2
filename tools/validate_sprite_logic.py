"""Compare AND/OR/XOR sprite entries and logic kernels with full SS frames."""
import argparse
import ast
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
from validate_line_draw import Registers,StateRegisters,Request,Response,Service,require,values
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE,UC_HOOK_INSN
from unicorn.x86_const import *
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_MEM,X86_REG_ES


class Result(C.Structure):
 _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['work','iterations','calls','writes','mask_calls','dispatches']]+[('returned',StateRegisters)]


def trusted_set(name):
 tree=ast.parse((ROOT/'tools/validate_mask_span.py').read_text())
 for node in ast.walk(tree):
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):return ast.literal_eval(node.value)
 raise ValueError(name)


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library,receipt_path=a.library.resolve(),a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and receipt_path.is_relative_to(ROOT/'docs/recovery/evidence') and not receipt_path.exists(),'Private/fresh outputs');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];dll=C.CDLL(str(library));draw=dll.td2ega_sprite_logic;resume=dll.td2ega_sprite_logic_kernel
 for fn in [draw,resume]:fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
 g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());entries=[0x7dbc,0xa718,0xbb08];mask_entries=[0x82d0,0x8336,0x839c,0xad22,0xad8b,0xadf4];parent_fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{x:04X}' for x in entries]];mask_fs=[f for f in g['functions'] if f['entry'] in [f'06C9:{x:04X}' for x in mask_entries]];require(len(parent_fs)==3 and len(mask_fs)==6,'Entry/helperfences');owned={ip for f in parent_fs for ip in f['instructions'] if 0x7dbc<=ip<=0x8089 or 0x91f3<=ip<=0x955f or 0x95aa<=ip<=0x95b1 or 0x9835<=ip<=0x9c2e or 0xa718<=ip<=0xa9d0 or 0xbb08<=ip<=0xc130};helper_ips={ip for f in mask_fs for ip in f['instructions']};fence=owned|helper_ips;md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True;ins={ip:next(md.disasm(image[0x6c90+ip:0x6c90+ip+15],ip,count=1)) for ip in fence};ram_families=[[0x7dec,0x7e21,0x7e74,0x7ecc,0x7f28,0x7f85,0x7fe0,0x8037],[0xa748,0xa77d,0xa7cd,0xa822,0xa87b,0xa8d5,0xa92d,0xa981],[0xbb48,0xbb7d,0xbbcd,0xbc22,0xbc7b,0xbcd5,0xbd2d,0xbd81]];hw_targets=[0x9835,0x98bb,0x9935,0x99b3,0x9a35,0x9ab8,0x9b39,0x9bb6];xor_hw=[0x9835,0xbdd1,0xbe55,0xbece,0xbf4b,0xbfc9,0xc045,0xc0bd];known_targets=set(sum(ram_families,[])+hw_targets+xor_hw+[0x9872]);heads={0x9314,0x931b,0x936c,0x93c7,0x9444,0x9450,0x949c,0x9502,0x9841,0x9844,0x9884,0x9887,0x9897};reps=set();device_reads={};device_writes={};pixel_writes=set();out_sites=set()
 for family in ram_families:
  for i,start in enumerate(family):
   end=family[i+1] if i<7 else {0x8037:0x808a,0xa981:0xa9d1,0xbd81:0xbdd1}[start];block=[ins[ip] for ip in sorted(owned) if start<=ip<end];heads.add(next(x.address for x in block if x.mnemonic=='mov' and x.op_str=='si, word ptr [bp - 0x3a]'));heads.add(next(x.address for x in block if x.mnemonic=='mov' and x.op_str=='cx, word ptr [bp - 0xc]'));heads.add(next(x.address for x in block if x.mnemonic=='lodsb' if i==0) if i==0 else next(x.address for x in block if x.mnemonic=='xor' and x.op_str=='ah, ah'))
 for targets in [hw_targets,xor_hw]:
  for i,start in enumerate(targets[1:]):
   end=targets[i+2] if i<6 else 0x9c2f if targets is hw_targets else 0xc131;block=[ins[ip] for ip in sorted(owned) if start<=ip<end];heads.add(next(x.address for x in block if x.mnemonic=='lea' and x.op_str=='bx, [bp - 0x26]'));heads.add(next(x.address for x in block if x.mnemonic=='mov' and x.op_str=='cx, word ptr ss:[bx]'));heads.add(next(x.address for x in block if x.mnemonic=='xor' and x.op_str=='ah, ah'))
 for ip,i in ins.items():
  hw=0x9835<=ip<=0x9c2e or 0xad22<=ip<=0xae60 or 0xbdd1<=ip<=0xc130
  if i.mnemonic.startswith('rep'):reps.add(ip)
  if i.mnemonic=='out':out_sites.add(ip)
  if i.mnemonic.endswith('movsb') or i.mnemonic.endswith('stosb'):pixel_writes.add(ip)
  elif i.operands and i.operands[0].type==X86_OP_MEM and i.operands[0].mem.segment==X86_REG_ES:pixel_writes.add(ip)
  if hw and i.mnemonic=='mov' and len(i.operands)>1 and i.operands[1].type==X86_OP_MEM and i.operands[1].mem.segment==X86_REG_ES:device_reads[ip]=i.op_str.split(',')[0]
  if hw and ip in pixel_writes:
   if i.mnemonic.endswith('movsb'):device_writes[ip]='source'
   elif i.mnemonic.endswith('stosb'):device_writes[ip]='al'
   else:device_writes[ip]=i.op_str.split(',')[-1].strip()
 heads|=trusted_set('heads');reps|=trusted_set('reps');mask_calls={0x9394,0x93ef,0x94d0,0x9536};dispatches={0x9416,0x955c,0x955f};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];cases=[]
 for entry,align,w,h,planes,header,clip in itertools.product(range(3),range(8),[0,1,2,4],[0,1,3],range(3),range(3),[0,1]):cases.append(('entry',entry,align,w,h,planes,header,clip,512))
 for operation,hw,align,w,h,planes,flags,df in itertools.product(range(3),[0,1],range(8),[0,1,3],[1,2],[1,2],range(4),[0,1]):cases.append(('kernel',hw,align,w,h,planes,flags,df,256+operation*10000000))
 for mode in [0,1]:
  for w,h,df in itertools.product([0,1,3],[1,2],[0,1]):cases.append(('kernel',1,0,w,h,2,3,df,256+mode*1000000))
 for entry,align,hw in itertools.product(range(3),range(8),[0,1]):cases.append(('unknown',entry,align,1,1,hw,0,0,512))
 for entry,align,w,h,planes,header,budget in itertools.product([0,1,2],[0,7],[0x101,0x8000],[0x101,0xffff],[0,1],[0,2],[0,1,4,16]):cases.append(('entry',entry,align,w,h,planes,header,0,budget))
 cases +=[(category,entry,align,w,h,planes,header,1,512) for category,entry,align,w,h,planes,header in itertools.product(['entry_top','entry_wide'],range(3),[0,7],[1,4,17,0x101],[1,3,7,0x101],[0,1],range(4))]
 vectors=instructions=0;sites=set();coverage=Counter()
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
  def code(cpu,address,size,_):
   ip=address-cs*16
   if active['expected_target'] is not None:
    require(ip==active['expected_target'],'Actualindirecttarget');active['expected_target']=None
    if ip not in known_targets:active['unknown']=ip;u.emu_stop();return
   require(ip in fence,'Spriteescapedfence '+hex(address))
   if (ip in heads or (ip in reps and u.reg_read(UC_X86_REG_CX)!=0)) and not tick(True):return
   if ip in mask_calls:
    if not tick(False):return
    active['mask_calls']+=1
   if ip in dispatches:
    if not tick(False):return
    active['dispatches']+=1;active['expected_target']=0x9872 if ip==0x955f else struct.unpack('<H',u.mem_read(cs*16+u.reg_read(UC_X86_REG_BX),2))[0]
   if ip in out_sites|device_reads.keys()|device_writes.keys() and (ip not in reps or u.reg_read(UC_X86_REG_CX)!=0):
    if not tick(False):return
    rr=read_regs();kind=1 if ip in out_sites else 2 if ip in device_reads else 3;physical=((rr.registers.es<<4)+rr.registers.di)&0xfffff if kind!=1 else 0
    if kind==2:v=bytes(u.mem_read(physical,1))[0]
    elif kind==1:v=rr.registers.ax&255
    elif device_writes[ip]=='source':v=bytes(u.mem_read(((rr.registers.ds<<4)+rr.registers.si)&0xfffff,1))[0]
    else:
     name=device_writes[ip];whole={'al':rr.registers.ax,'ah':rr.registers.ax,'cl':rr.registers.cx,'dl':rr.registers.dx,'dh':rr.registers.dx}[name];v=(whole>>8)&255 if name in ['ah','dh'] else whole&255
    q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.registers.dx,v,(C.c_uint16*5)(),physical,rr);active['events'].append(event(q))
   active['instructions']+=1;active['sites'].add(ip)
  def memory_write(cpu,access,address,size,value,_):
   if u.reg_read(UC_X86_REG_IP) in pixel_writes:active['writes']+=1
  def out_hook(cpu,port,size,value,_):require(size==1 and active['events'][-1][4:6]==[port,value],'ActualOUTevent');active['outs']+=1
  def interrupt(*_):raise RuntimeError('Unexpectedspriteinterrupt')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,memory_write);u.hook_add(UC_HOOK_INSN,out_hook,None,1,0,UC_X86_INS_OUT);u.hook_add(UC_HOOK_INTR,interrupt)
  for category,entry,align,w,h,planes,header,profile,budget in cases:
   data=bytearray(base);ss=ds if vectors&1 else 0x9000;source=0x6000;is_kernel=category=='kernel';operation=budget//10000000 if is_kernel else entry;budget=budget%10000000;hw=bool(entry) if is_kernel else category=='unknown' and bool(planes) or planes==1;root_sp=0xe000;current_sp=root_sp-76 if is_kernel else root_sp;bp=root_sp-2 if is_kernel else 0x5678;source_offset=0x1000;latched=is_kernel and (budget>1000000 or operation!=2)
   if budget>1000000:budget-=1000000
   def pw(seg,offset,value):struct.pack_into('<H',data,((seg<<4)+(offset&65535))&0xfffff,value&65535)
   def pb(seg,offset,value):data[((seg<<4)+(offset&65535))&0xfffff]=value&255
   plane_segs=[0xa000,0,0,0] if hw else [0,0,0,0] if not is_kernel and planes==2 else [0x5000,0x6000,0x7000,0x8000]
   for i,value in enumerate(plane_segs):pw(cs,0xaf3c+2*i,value)
   for offset,value in {0xaf44:0xb000,0xaf46:0 if profile==0 or is_kernel else 1,0xaf48:10,0xaf4a:0 if profile==0 or is_kernel else 1,0xaf4c:4,0xaf4e:32}.items():pw(cs,offset,value)
   for y in range(-8,520):pw(cs,0xb000+2*y,0x200+32*y)
   for mask in range(16):index=(mask&-mask).bit_length()-1 if mask else 0;pb(cs,0x9144+mask,index);pb(cs,0x9154+mask,1<<index)
   for index in range(4):pb(cs,0x9164+index,255^(1<<index));pb(cs,0x9168+index,1<<index)
   y=0xffff if category=='entry_top' else profile
   for offset,value in [(0,w),(2,h),(4,0),(6,0),(8,align),(10,y)]:pw(source,source_offset+offset,value)
   packed=[[15,0,0,0],[1,2,4,8],[0x1f,0x20,0,0],[15,0,0,0x30]][header if not is_kernel else 0]
   for i,value in enumerate(packed):pb(source,source_offset+12+i,value)
   for i in range(2048):pb(source,source_offset+16+i,(i*37+11)&255)
   frame=struct.pack('<2H',0x100,0x1111);root_args=struct.pack('<2H',source_offset,source) if not is_kernel else struct.pack('<4H',source_offset,source,align,y);data[ss*16+root_sp:ss*16+root_sp+4+len(root_args)]=frame+root_args
   if not is_kernel:data[ss*16+root_sp+8:ss*16+root_sp+16]=struct.pack('<4H',0x5aa5,0xa55a,0x1111,0xeeee)
   if is_kernel:
    def pl(offset,value):pw(ss,bp-offset,value)
    stride=h*(w+1)+3
    for offset,value in {0x28:source_offset+16,0x2a:0x200,12:w,14:h,0x2c:32-w,0x36:1,0x38:stride,0x3a:2*(planes-1),0x32:planes*stride-w,0x3c:bp-0x26+2*planes,0x3e:header,0x42:([8,16,24][operation] if latched else 0),0x41:([1,2,4][operation])}.items():pl(offset,value)
    for i in range(planes):pw(ss,bp+2*i-0x16,0x5000+i*0x1000);pw(ss,bp+2*i-0x1e,source_offset+16+i*stride)
    if hw:
     for i in range(planes):pw(ss,bp+2*i-0x26,(i<<8)|(1<<i));pw(ss,bp+2*i-0x1e,-w if i<planes-1 else stride-w)
    for offset,value in [(-6,0x2345),(-4,0x3456),(-2,ds),(0,0x5678)]:pw(ss,bp+offset,value)
   if category=='unknown':pw(cs,((0xbb38 if operation==2 else 0x9572) if hw else [0x7ddc,0xa738,0xbb28][operation])+2*align,0x7777)
   u.mem_write(0,bytes(data));cpu_flags=2|(vectors&1)|(((vectors>>1)&1)<<9)|(((profile if is_kernel else vectors>>2)&1)<<10);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,(header if not hw else 3) if is_kernel else 0xd789,0x3456,0x2345,source if is_kernel else ds,0xa000 if is_kernel and hw else 0x5432,(cpu_flags>>9)&1,(cpu_flags>>10)&1),bp,cpu_flags&1);start=((xor_hw if operation==2 else hw_targets) if hw else ram_families[operation])[align] if is_kernel else entries[entry]
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,current_sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,start),(UC_X86_REG_EFLAGS,cpu_flags)]:u.reg_write(reg,val)
   active.update(ss=ss,budget=budget,work=0,iterations=0,writes=0,mask_calls=0,dispatches=0,events=[],outs=0,prefix=False,unknown=0,expected_target=None,instructions=0,sites=set());u.emu_start(cs*16+start,0x11210,count=3000000);label=f'{load:x}/{category}/{entry}/{align}/{w:x}/{h:x}/{planes}/{header}/{profile}/{budget}';require(active['prefix'] or active['unknown'] or (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111,0x100,root_sp+4),'Originalfarreturn/prefix/transfer '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[]
   def callback(ctx,m,q,r):
    try:
     q=q.contents;events.append(event(q));require(q.kind in [1,2,3],'Onlyexplicitbytebus')
     if q.kind==2:r.contents.value=bus[q.address]
     elif q.kind==3:bus[q.address]=q.value
     return 1
    except Exception as e:errors.append(str(e));return 0
   cb=Service(callback);out=Result();fn=resume if is_kernel else draw;fn(bus,len(bus),load,ss,current_sp,start if is_kernel else entry,C.byref(incoming),cb,None,budget,C.byref(out));require(not errors and out.status==(3 if active['prefix'] else 1 if active['unknown'] else 0) and out.current_sp==u.reg_read(UC_X86_REG_SP) and (out.work,out.iterations,out.calls,out.writes,out.mask_calls,out.dispatches)==(active['work'],active['iterations'],len(active['events']),active['writes'],active['mask_calls'],active['dispatches']) and events==active['events'],'Nativework/outcome/trace '+label+str(errors)+str((out.status,out.work,out.iterations,out.calls,out.writes,out.mask_calls,out.dispatches,active['work'],active['iterations'],len(active['events']),active['writes'],active['mask_calls'],active['dispatches'])));require(bytes(u.mem_read(0,len(data)))==bytes(bus),'FullbusincludingSSframe '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'Registers '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8],u.reg_read(UC_X86_REG_BP),r.bp)));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(out.status==3 or (out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Rawfarreturn/indirecttarget '+label);coverage[category]+=1;coverage['root_arg_words_2']+=int(not is_kernel);coverage['prefix' if active['prefix'] else 'transfer' if active['unknown'] else 'normal']+=1;coverage['mask_calls']+=out.mask_calls;coverage['OUT_bytes']+=active['outs'];coverage['device_reads']+=sum(e[0]==2 for e in events);coverage['device_writes']+=sum(e[0]==3 for e in events);coverage['byte_writes']+=out.writes;vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
 missing=sorted(owned-sites);allowed=set();require(set(missing)<=allowed,'Unexercisedspriteownedlocations '+str([hex(x) for x in missing]));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000208','FN-EGA-000232','FN-EGA-000440'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_sprite_logic.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':x,'sha256':hashlib.sha256((ROOT/x).read_bytes()).hexdigest()} for x in ['tools/validate_line_draw.py','tools/validate_mask_span.py','tools/validate_state_loop.py']],'original_instructions_executed':instructions,'owned_sprite_instruction_sites':len(owned),'owned_sites_exercised':len(owned&sites),'near_helper_sites_exercised':len(helper_ips&sites),'unexercised_owned_sites':[hex(x) for x in missing],'fixture_coverage':dict(coverage),'limits':'Threeentries7DBC/A718/BB08twoSSwords/headercoords plusstandalonelogic/copykernels, materializedSSsaved/local/near-returnframes/fullbus/GPR/BP/CFIFDF/farRETF4, byteAL-MUL/crop/plane-selection/currentDSversusSS/CS dispatch/actualnearRAM-device maskhelpers andexplicitOUT/MMIO traces matched. Nativeworkprefix andrawunsupportedindirectboundary distinct. Fixedentryflags1/2/4 choose distinct high-mask calls including actual839C/ADF4; maskhelpers separatelyvalidated. Syntheticflatdevicebus/copysourcefixtures only, noactualspritecorpus/allwriter/bounds/IRQ/device/renderer/state/core/game/fidelity acceptance; noallcaller/writer/alias/lifetime/exclusionclosure. Native diagnostics separate.'};receipt_path.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','owned_sprite_instruction_sites','owned_sites_exercised','near_helper_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
