"""Compose actual line/rectangle/edge/fill bodies with explicit synthetic bus."""
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
from validate_draw_sequence import Service as ParentService,Result as ParentResult
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_INSN
from unicorn.x86_const import *


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();receipt_path=a.output.resolve();require(receipt_path.is_relative_to(ROOT/'docs/recovery/evidence') and not receipt_path.exists(),'Fresh public receipt');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image identity');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ identity');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];libraries=['analysis/build/line-draw-repro-v2/td2ega_line_draw.dll','analysis/build/rectangle-draw-repro/td2ega_rectangle_draw.dll','analysis/build/edge-sequence-repro/td2ega_edge_sequence.dll','analysis/build/draw-sequence-repro/td2ega_draw_sequence.dll'];dll=[C.CDLL(str(ROOT/x)) for x in libraries];line=dll[0].td2ega_line_draw;line.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];line.restype=None;rectangle=dll[1].td2ega_rectangle_draw;rectangle.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),Service,C.c_void_p,C.c_uint32,C.POINTER(Result)];rectangle.restype=None;edge=dll[2].td2ega_edge_sequence;edge.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),ParentService,C.c_void_p,C.c_uint32,C.POINTER(ParentResult)];edge.restype=None;fill=dll[3].td2ega_draw_sequence;fill.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),ParentService,C.c_void_p,C.c_uint32,C.POINTER(ParentResult)];fill.restype=None
 g=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text());entries=['06C9:8582','06C9:8A0C','06C9:89A2','06C9:34DC','06C9:26D8'];fs=[f for f in g['functions'] if f['entry'] in entries];require(len(fs)==5,'Fiveentryfence');ips={ip for f in fs for ip in f['instructions']};far_calls={int(c['site'][5:],16):(int(c['target'][5:],16),int(c['site'][5:],16)+c['size']) for f in fs for c in f['calls']};outs={0x882b,0x882f,0x8835,0x8839,0x8872,0x8876,0x8894,0x8898,0x889e,0x88a2,0x8927,0x892b,0x8931,0x8935,0x896e,0x8972,0x8990,0x8994,0x899a,0x899e,0x8b66,0x8b6a,0x8b70,0x8b74,0x8b84,0x8b88,0x8ba6,0x8baa,0x8bb0,0x8bb4,0x8bc4,0x8bc8,0x8be6,0x8bea,0x8c0b,0x8c0f,0x8c2d,0x8c31,0x8c53,0x8c57};reads={0x887a,0x8976,0x8b97,0x8bd7,0x8bfa,0x8c1e,0x8c44,0x8c69};writes={0x887d,0x8979,0x8b9a,0x8bda,0x8bfd,0x8c21,0x8c47,0x8c6c};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];sp=0xe000;vectors=instructions=0;sites=set();coverage=Counter();lines=[(5,10,20,10),(20,10,5,10),(20,3,20,20),(20,20,20,3),(1,1,17,16),(17,16,1,1)];cases=[(0,i,0,plane,same,flags) for i,plane,same,flags in itertools.product(range(6),range(4),[0,1],[2,0x203,0x402,0x603])];cases +=[(1,flag,profile,plane,same,flags) for flag,profile,plane,same,flags in itertools.product([0,1],range(3),range(4),[0,1],[2,0x203,0x402,0x603])];cases +=[(2,flag,profile,plane,same,flags) for flag,profile,plane,same,flags in itertools.product([0,8,0x40,0x48,0x80,0x88,0xc0,0xff],[0,1],range(4),[0,1],[2,0x203,0x402,0x603])]
 def far_event(site,target,ss,current,args,incoming):return ['far',site,target,ss,current,len(args),args,values(incoming.registers),incoming.bp,incoming.carry]
 def io_event(q):return ['bus',q.kind,q.site,q.stack_segment,q.stack_sp,q.port,q.value,q.address,values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
 for load in [0x1000,0x2345]:
  cs,ds=load+0x6c9,load+0x178f;relocated=bytearray(image)
  for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
  base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=bytes(65536);u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
  def read_regs():
   f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(r) for r in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
  def code(cpu,address,size,_):
   ip=address-cs*16
   if active['expected'] and ip==active['expected'][1]:
    site,target,ret=active['expected'];current=u.reg_read(UC_X86_REG_SP);require(bytes(u.mem_read(active['ss']*16+current,4))==struct.pack('<2H',ret,cs),'Actualfarframe');live=5 if site in [0x8611,0x867b] else (sp-current-4)//2;require(live in [5,10,15],'Actualpreparedpool');args=list(struct.unpack('<'+'H'*live,u.mem_read(active['ss']*16+current+4,live*2)));active['events'].append(far_event(site,target,active['ss'],current,args,read_regs()));active['expected']=None
   require(ip in ips,'Drawingcompositionescapedfence '+hex(address));active['instructions']+=1;active['sites'].add(ip)
   if ip in far_calls:target,ret=far_calls[ip];require(target in [0x8582,0x89a2,0x8a0c],'916Cbranchmustremainexcluded');active['expected']=(ip,target,ret)
   if ip in outs|reads|writes:
    rr=read_regs();kind=1 if ip in outs else 2 if ip in reads else 3;physical=((rr.registers.es<<4)+rr.registers.di)&0xfffff if kind!=1 else 0;v=bytes(u.mem_read(physical,1))[0] if kind==2 else rr.registers.ax&255;q=Request(kind,ip,cs,0,active['ss'],u.reg_read(UC_X86_REG_SP),rr.registers.dx,v,(C.c_uint16*5)(),physical,rr);active['events'].append(io_event(q))
  def out_hook(cpu,port,size,value,_):require(size==1 and active['events'][-1][5:7]==[port,value],'ActualOUTbus');active['outs']+=1
  def interrupt(*_):raise RuntimeError('No fault/interrupt in admittednormalcomposition')
  u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INSN,out_hook,None,1,0,UC_X86_INS_OUT);u.hook_add(UC_HOOK_INTR,interrupt)
  for root,choice,profile,plane,same,flags in cases:
   data=bytearray(base);ss=ds if same else 0x9000;planes=[0x5000,0x6000,0x7000,0x8000] if plane==0 else [0,0x6000,0,0x8000] if plane==1 else [0xa000,0,0,0] if plane==2 else [ds]*4
   for i,v in enumerate(planes):struct.pack_into('<H',data,cs*16+0xaf3c+2*i,v)
   for at,v in {0xaf44:0xb000,0xaf46:0,0xaf48:10,0xaf4a:0,0xaf4c:32,0xaf4e:32}.items():struct.pack_into('<H',data,cs*16+at,v)
   for i in range(8):data[cs*16+0x857a+i]=128>>i;data[ds*16+0x6838+i]=255>>i;data[ds*16+0x6840+i]=(255<<(7-i))&255
   for y in range(-32,65):struct.pack_into('<H',data,cs*16+((0xb000+2*y)&65535),(0x200+32*y)&65535)
   def put(at,v):struct.pack_into('<H',data,ds*16+at,v&65535)
   si=profile*2
   if root==1:
    put(si+0x2b26,8+profile*4);put(si+0x275a,16);put(si+0x2a5e,10+profile*2);put(si+0x2ac2,30+profile*2);put(0x2c2a,8);data[ds*16+0x37f7]=choice
   if root==2:
    for at,v in {0x2c2a:8,0x2c34:10,0x2c84:70,0x2c7a:3,0x2c7c:7,0x2c7e:5,0x2c2c:80,0x2c66:0,0x5350:0x5a0f}.items():put(at,v)
    data[ds*16+0x2c98]=choice;data[ds*16+0x2c97]=128 if profile else 0;data[ds*16+0x37f7]=0;data[ds*16+0x37f8]=1
   root_ip=[0x8582,0x34dc,0x26d8][root];frame=struct.pack('<2H',0x100,0x1111) if root==0 else struct.pack('<H',0x100);args=list(lines[choice])+[0x5a0f] if root==0 else [];tail=struct.pack('<'+'H'*len(args),*args)+b'\xa5'*4;data[ss*16+sp-128:ss*16+sp+len(frame)+len(tail)]=b'\xa5'*128+frame+tail;u.mem_write(0,bytes(data));incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,si,0x2345,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1)
   for reg,val in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,root_ip),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,val)
   active.update(ss=ss,expected=None,events=[],outs=0,instructions=0,sites=set());end=0x11210 if root==0 else cs*16+0x100;u.emu_start(cs*16+root_ip,end,count=1000000);label=f'{load:x}/{root}/{choice:x}/{profile}/{plane}/{same}/{flags:x}';require((u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))==(0x1111 if root==0 else cs,0x100,sp+len(frame)),'Originalrootreturn '+label);bus=(C.c_uint8*len(data)).from_buffer_copy(data);events=[];errors=[];children=Counter()
   def materialize(q,args):C.memmove(C.byref(bus,((q.stack_segment<<4)+q.stack_sp+4)&0xfffff),struct.pack('<'+'H'*len(args),*args),len(args)*2)
   def adapter_callback(ctx,m,q,response):
    try:
     q=q.contents
     if q.kind==0:
      args=list(q.arguments);events.append(far_event(q.site,q.offset,q.stack_segment,q.stack_sp,args,q.incoming));materialize(q,args);child=Result();rectangle(m,len(bus),load,q.stack_segment,q.stack_sp,1,C.byref(q.incoming),adapter,None,100000,C.byref(child));require(child.status==0 and child.current_sp==q.stack_sp+4,'Actualrawrectangle childnormal');C.memmove(C.byref(response.contents.returned),C.byref(child.returned),C.sizeof(StateRegisters));children['rectangles']+=1
     else:
      events.append(io_event(q));require(q.kind in [1,2,3],'Explicitbytebusonly')
      if q.kind==2:response.contents.value=bus[q.address]
      elif q.kind==3:bus[q.address]=q.value
     return 1
    except Exception as e:errors.append(str(e));return 0
   adapter=Service(adapter_callback)
   def parent_callback(ctx,m,q,response):
    try:
     q=q.contents;require(q.kind==1 and q.argument_count==5,'Actualparentfar5words');args=list(q.arguments)[:q.live_argument_count];events.append(far_event(q.site,q.offset,q.stack_segment,q.stack_sp,args,q.incoming));materialize(q,args);child=Result()
     if q.offset==0x8582:line(m,len(bus),load,q.stack_segment,q.stack_sp,C.byref(q.incoming),adapter,None,100000,C.byref(child));children['lines']+=1
     elif q.offset==0x89a2:rectangle(m,len(bus),load,q.stack_segment,q.stack_sp,0,C.byref(q.incoming),adapter,None,100000,C.byref(child));children['rectangles']+=1
     else:raise RuntimeError('Unadmittedparentleaf')
     require(child.status==0 and child.current_sp==q.stack_sp+4,'Actualparentchildnormal');C.memmove(response,C.byref(child.returned),C.sizeof(StateRegisters));return 1
    except Exception as e:errors.append(str(e));return 0
   parent=ParentService(parent_callback)
   if root==0:out=Result();line(bus,len(bus),load,ss,sp,C.byref(incoming),adapter,None,100000,C.byref(out));children['lines']+=1
   elif root==1:out=ParentResult();edge(bus,len(bus),load,ss,sp,C.byref(incoming),parent,None,16,C.byref(out))
   else:out=ParentResult();fill(bus,len(bus),load,ss,sp,0,C.byref(incoming),parent,None,16,C.byref(out))
   require(not errors and out.status==0 and out.current_sp==sp+len(frame) and events==active['events'],'Nativebodychain/events '+label+str(errors));actual=bytearray(u.mem_read(0,len(data)));expected=bytearray(bus);actual[ss*16+sp-128:ss*16+sp]=expected[ss*16+sp-128:ss*16+sp];require(actual==expected,'Fullnonframebus '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'ReturnedGPR/BP '+label);f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require(bytes(u.mem_read(ss*16+sp,len(frame)+len(tail)))==frame+tail,'Rootreturn/args/guard '+label);coverage.update(children);coverage[['line_root','edge_root','fill_root'][root]]+=1;coverage['far_boundaries']+=sum(e[0]=='far' for e in events);coverage['OUT_bytes']+=active['outs'];coverage['device_reads']+=sum(e[0]=='bus' and e[1]==2 for e in events);coverage['device_writes']+=sum(e[0]=='bus' and e[1]==3 for e in events);vectors+=1;instructions+=active['instructions'];sites.update(active['sites'])
  print(json.dumps({'load':hex(load),'vectors_completed':vectors}))
 deps=['tools/validate_line_draw.py','tools/validate_rectangle_draw.py','tools/validate_draw_sequence.py','tools/validate_state_loop.py'];record={'schema':1,'result':'pass','vectors':vectors,'image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_libraries':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in libraries],'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'entry_fence':entries,'instruction_sites_in_fence':len(ips),'instruction_sites_exercised':len(sites),'original_instructions_executed':instructions,'fixture_coverage':dict(coverage),'limits':'Actual8582+8A0C,34DC+8582+8A0C,26D8+89A2 bodies withexplicitfarboundary/poolmaterialization andorderedOUT/MMIOtrace, fullnonframebus/GPR/BP/CFIFDF/near-vs-farrootreturns matched. NoABI-value leafmocks withinadmittedchains.26D8optional916Cbranchesgatedout byfixture37F8=1/flagprofiles; normalchildoutcomesonly, fault/budgetprefixes remainindividualhelperreceipts.128privateSSscratchbytes excluded, actualproducer/caller/alias/exclusion/capacity/resourcefed/realdevice/renderer/fullstate/core/game/fidelity remainopen. Fence notall-pathcoverage; scopedvectors separatefromhelper totals.'};receipt_path.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))


if __name__=='__main__':main()
