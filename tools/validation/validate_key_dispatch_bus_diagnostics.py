"""Native-only stack-guard/budget/service/retired-control diagnostics for6528."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_key_dispatch_bus import Registers,StateRegisters,Request,Response,Service,Result,require
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshprivatepaths');fn=C.CDLL(str(lib)).td2ega_key_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*3+[C.POINTER(StateRegisters),C.c_uint32,Service,C.c_void_p,C.POINTER(Result)];fn.restype=None;bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x5000,0x5432,0,1),0x5678,0);r=Result();vectors=0;null=Service()
 for memory,count,state in [(None,len(bus),C.byref(s)),(bus,len(bus)-1,C.byref(s)),(bus,len(bus),None)]:fn(memory,count,0x1000,0x9000,0xe000,state,1,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidbeforeeffects');vectors+=1
 for field in ['carry','interrupts_enabled','direction']:
  target=s if field=='carry' else s.registers;old=getattr(target,field);setattr(target,field,2);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,null,None,C.byref(r));require(r.status==2 and r.bus_writes==0 and not any(bus),'Invalidboolean');setattr(target,field,old);vectors+=1
 fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,null,None,None);require(not any(bus),'Nulloutput');vectors+=1
 def put(sg,o,v):
  at=((sg<<4)+(o&65535))&0xfffff;bus[at]=v&255;bus[(at+1)&0xfffff]=(v>>8)&255
 def word(memory,sg,o):
  at=((sg<<4)+(o&65535))&0xfffff;return memory[at]|(memory[(at+1)&0xfffff]<<8)
 def prepare(ss=0x9000,sp=0xe000,key=1,target=0x645a):
  bus[0x56252]=0;put(0x5000,0x604a,target);put(ss,sp,0x1111);put(ss,sp+2,0x2222);put(ss,sp+4,key)
 prepare(0x5000,0x6254);fn(bus,len(bus),0x1000,0x5000,0x6254,C.byref(s),1,null,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.carry,r.zero_flag)==(0,0x6258,0x2222,0x1111,0,1,0xa55a,0xb123,0,0),'PUSHBPbeforeguard forcesbusy');require(bus[0x56252]==0x78 and r.returned.registers.interrupts_enabled==1,'Busyactualguard/IF1');vectors+=1
 prepare(key=0x7f,target=0);put(0x5000,0x6146,0);fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,null,None,C.byref(r));require((r.status,r.current_sp,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.bx,r.returned.carry,r.zero_flag)==(0,0xe004,0,4,0x7f,0,0,1),'Missingtarget ZF1 despiteAXnonzero');vectors+=1
 prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),0,null,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.callback_target,r.returned.registers.ax)==(3,0xdff8,0x16c9,0x6559,0,6,0x645a,0x16c9),'BeforeCALLafterPUSHDI-SI-CS');require(word(bus,0x9000,0xdff8)==0x16c9 and word(bus,0x9000,0xdffa)==0x3456 and word(bus,0x9000,0xdffc)==0x4567,'Actualsavedwordorder');vectors+=1
 prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,null,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes)==(4,0xdff6,0x16c9,0x645a,1,7),'Missingservice afteractualCALL');require(word(bus,0x9000,0xdff6)==0x655b and bus[0x56252]==1,'Farcallbackframe/raisedguardretained');vectors+=1
 mode={'value':'normal'}
 def service(ctx,memory,qptr,rptr):
  q=qptr.contents;response=rptr.contents;response.returned=q.incoming;response.returned.registers.si=0x1111;response.returned.registers.di=0x2222;response.returned.bp=0xaaaa;response.returned.registers.interrupts_enabled=0;response.returned.registers.direction=1;response.returned.carry=1;response.status=0;response.current_sp=(q.stack_sp+4)&65535;response.next_ip=word(memory,q.stack_segment,q.stack_sp);response.next_segment=word(memory,q.stack_segment,q.stack_sp+2)
  if mode['value']=='invalid_status':response.status=2
  elif mode['value']=='invalid_bool':response.returned.carry=2
  elif mode['value']=='raw':response.next_ip=0x4444
  elif mode['value']=='changed_DS':response.returned.registers.ds=0x6000
  elif mode['value']=='savedwords':
   for delta,value in [(4,0xcafe),(6,0xbabe),(8,0xf00d),(10,0x3333),(12,0x4444)]:put(q.stack_segment,q.stack_sp+delta,value)
   response.bus_writes=5
  elif mode['value'] in ['budget','boundary']:
   response.status=3 if mode['value']=='budget' else 5;response.current_sp=q.stack_sp;response.next_segment=q.target_segment;response.next_ip=q.target_ip
  return 1
 callback=Service(service)
 for value in ['invalid_status','invalid_bool']:
  mode['value']=value;prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require((r.status,r.current_sp,r.next_ip,r.bus_writes)==(4,0xdff6,0x645a,7),'Invalidresponse afterCALL');vectors+=1
 mode['value']='normal';prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.returned.registers.ax,r.returned.registers.si,r.returned.registers.di,r.returned.bp,r.returned.carry,r.zero_flag,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(0,0xe004,0x2222,0x1111,1,8,0,0x3456,0x4567,0x5678,0,1,0,1),'Retiredfarreturn/actualsavedpops/XORflags/IFDFsurvive');vectors+=1
 mode['value']='raw';prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.bus_writes,r.returned.registers.si,r.flags_valid)==(1,0xdffa,0x16c9,0x4444,7,0x1111,0),'Rawchildcontrolneverfollowed/popsnotexecuted');require(bus[0x56252]==1,'Rawchildleavesguard');vectors+=1
 mode['value']='changed_DS';prepare();bus[0x66252]=0xee;fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require(r.status==0 and r.returned.registers.ds==0x6000 and bus[0x56252]==1 and bus[0x66252]==0,'ReturnedDS governsguardclear');vectors+=1
 mode['value']='savedwords';prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require((r.status,r.next_segment,r.next_ip,r.bus_writes,r.returned.registers.si,r.returned.registers.di,r.returned.bp)==(0,0x4444,0x3333,13,0xcafe,0xbabe,0xf00d),'CallbackCPUwrites-forwarded/actualsavedwords-and-rootreturn');vectors+=1
 for value,status in [('budget',3),('boundary',5)]:
  mode['value']=value;prepare();fn(bus,len(bus),0x1000,0x9000,0xe000,C.byref(s),1,callback,None,C.byref(r));require((r.status,r.current_sp,r.next_segment,r.next_ip,r.calls,r.bus_writes,r.flags_valid)==(status,0xdff6,0x16c9,0x645a,1,7,0),'Explicitchildprefixforwarded');vectors+=1
 deps=['tools/validate_key_dispatch_bus.py'];record={'schema':1,'result':'pass','vectors':vectors,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'image_sha256':hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Native-only invalidbeforeeffects/nulloutput/PUSHBPguardalias/nonzeroAX-missingtargetZF/beforeCALLsavedwordprefix/missing-malformedservice/retiredfarcontrol-rawneverfollowed/actualsavedSI-DI-BP-rootcoordinates/returnedDSguardclear/childCPUwritecount-forwarding/budget-boundaryprefixes. Callbackprofilesnotoriginalbodyproof; separatefromoriginalcomparison/IRQ/allwriters-lifetime/wholeinputpoll-420A-403B-core/game-fidelity.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','vectors':vectors}))
if __name__=='__main__':main()
