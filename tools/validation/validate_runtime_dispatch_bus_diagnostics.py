"""Native runtime dispatch pointer, high-word and cleanup boundary diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_dispatch_bus import Result,Limits,Services,Request,Response,Handler,DOSService,CallbackService,Registers,StateRegisters,ww,rw,require
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_runtime_dispatch_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters(Registers(22,0xb123,0xc456,0xd789,0x3456,0x4567,0x278f,0x5432,0,0),0x5678,0);r=Result();caps=Limits(32,8,128,128);calls=[];platform=[];mode={'handler':'normal','dos_cf':0};image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();keys=image[0x13a80+0x2cae:0x13a80+0x2cb4];jumps=image[0x13a80+0x2c10:0x13a80+0x2c1c];checks=0
    def dos(ctx,m,qptr,rptr):q=qptr.contents;platform.append((q.vector,q.site,q.incoming.carry));v=StateRegisters.from_buffer_copy(bytes(q.incoming));v.registers.ax=0x1234 if q.vector==0x23 else 0;v.carry=mode['dos_cf'];rptr[0]=v;return 1
    def handler(ctx,m,n,qptr,rptr):
        q=qptr.contents;calls.append(Request.from_buffer_copy(bytes(q)));v=StateRegisters.from_buffer_copy(bytes(q.incoming));v.carry=0;v.registers.interrupts_enabled=0;v.registers.direction=1;o=rptr.contents;o.returned=v;o.flags_word=0x402;o.flags_mask=0xf72b;o.current_sp=q.stack_sp+4;o.next_ip=rw(m,q.stack_segment,q.stack_sp);o.next_segment=rw(m,q.stack_segment,q.stack_sp+2)
        if mode['handler']=='prefix':o.status=3;o.current_sp=q.stack_sp;o.next_segment=q.target_segment;o.next_ip=q.target_ip;o.flags_mask=0xf72a
        if mode['handler']=='raw':ww(m,q.stack_segment,q.stack_sp,0x4444);o.next_ip=0x4444
        if mode['handler']=='invalid':o.flags_mask=0
        return 1
    def finalizer(ctx,m,qptr,rptr):rptr[0]=qptr.contents.incoming;return 1
    dsrv=DOSService(dos);hsrv=Handler(handler);fsrv=CallbackService(finalizer);services=Services(dsrv,hsrv,fsrv,None)
    def reset(arg=22,kind='ignore',sp=0xe000,ss=0x9000):
        C.memset(bus,0,len(bus));calls.clear();platform.clear();s.registers.ax=arg;s.carry=s.registers.interrupts_enabled=s.registers.direction=0;C.memmove(C.addressof(bus)+0x23a80+0x2cae,keys,6);C.memmove(C.addressof(bus)+0x23a80+0x2c10,jumps,12);bus[0x278f0]=0x55
        cursor=0x82c4
        for key in [0xa,0xfc,0xff,1]:ww(bus,0x278f,cursor,key);cursor+=2;bus[0x278f0+cursor]=65;bus[0x278f0+cursor+1]=0;cursor+=2
        ww(bus,0x278f,cursor,0xffff)
        for i in range(6):ww(bus,0x278f,0x7058+4*i,0x100 if kind=='custom' else 1 if kind=='ignore' else 0);ww(bus,0x278f,0x705a+4*i,0xa000 if kind=='custom' else 0)
        ww(bus,ss,0x707e,0x100);ww(bus,ss,0x7080,0xa000);ww(bus,ss,sp,0x1111);ww(bus,ss,sp+2,0x2222);ww(bus,ss,sp+4,arg)
    def run(entry=1,sp=0xe000,ss=0x9000,flags=2,mask=65535):fn(bus,len(bus),0x1000,ss,sp,entry,flags,mask,C.byref(s),C.byref(caps),C.byref(services),C.byref(r))
    reset();before=bytes(bus)
    for kw in [dict(entry=3),dict(entry=0,sp=1),dict(sp=91),dict(entry=2,sp=99),dict(sp=0xffe1),dict(entry=2,sp=0xffe1),dict(mask=0),dict(mask=1),dict(mask=0x600),dict(flags=0),dict(flags=3),dict(flags=0x1000)]:run(**kw);require(r.status==2 and not r.bus_writes and bytes(bus)==before,'Invalidbeforeeffects');checks+=1
    caps.steps=0
    for entry in range(3):run(entry=entry,mask=0xf72a);require((r.status,r.current_sp,r.flags_word,r.flags_mask,r.bus_writes)==(3,0xe000,2,0xf72a,0) and bytes(bus)==before,'Beforebodypartialmask');checks+=1
    caps.steps=32
    for i,key in enumerate(keys):reset(arg=key);run(entry=0);require((r.status,r.returned.registers.ax,r.returned.registers.bx,r.returned.registers.cx,r.returned.carry,r.flags_mask)==(0,4*i,0x7058+4*i,i,0,65535),'SixcurrentCSlookupslots');checks+=1
    reset(arg=0x78,sp=0x2cb0,ss=0x23a8);run(entry=0,sp=0x2cb0,ss=0x23a8);require(r.status==0 and r.returned.registers.bx==0x7058 and bus[0x23a80+0x2cae]==0x78,'PUSHBPalterscurrentCSkeybeforelookup');checks+=1
    for arg in [8,0x108]:
        reset(arg=arg,kind='custom');ww(bus,0x278f,0x7076,0x100);run();require(r.status==0 and calls[0].incoming.registers.cx==arg and rw(bus,0x9000,calls[0].stack_sp+4)==arg and rw(bus,0x9000,calls[0].stack_sp+6)==0x8c and (rw(bus,0x278f,0x7060)!=0)==(arg==8),'Fullwordcallbackandresetguard');checks+=1
    reset(kind='custom');mode['handler']='prefix';run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.flags_mask,r.callbacks)==(3,2,0xe000-22,0xa000,0x100,0xf72a,1),'HandlerprefixretainsunknownCFmask');checks+=1
    reset(kind='custom');mode['handler']='raw';run();require((r.status,r.stage,r.next_ip,r.flags_mask,r.callbacks)==(1,2,0x4444,0xf72b,1),'Rawhandlerretiredtargetnotfollowed');checks+=1
    reset(kind='custom');mode['handler']='invalid';run();require((r.status,r.stage,r.current_sp,r.next_segment,r.next_ip,r.callbacks)==(4,2,0xe000-22,0xa000,0x100,0),'InvalidresponseafteractualCALLframe');checks+=1;mode['handler']='normal'
    reset(kind='custom',sp=0x7072,ss=0x278f);run(sp=0x7072,ss=0x278f);require(calls and (calls[0].target_segment,calls[0].target_ip)==(0,0),'ResetcaneraseSSfaroperandbeforeCALL');checks+=1
    reset(arg=8,kind='default',sp=0x7088);ww(bus,0x278f,0x7076,0x100);caps.calls=2;run(sp=0x7088);require(calls and (calls[0].kind,calls[0].target_segment,calls[0].target_ip)==(1,0x23a8,0x2c47) and rw(bus,0x9000,0x707e)==0x2c98 and r.status==3 and r.next_ip==0x2c9c,'SSoperandcapturebeforefarCALLwrites');checks+=1;caps.calls=8
    reset();ww(bus,0x278f,0x706c,0);ww(bus,0x23a8,0x2c1a,0);run();require((r.status,r.next_ip,r.raw_target,r.raw_segment)==(6,0x2c5f,0,0x23a8),'UnknownliteralnearwordstopbeforeJMP');checks+=1
    for cf in [0,1]:
        reset(arg=2);mode['dos_cf']=cf;run();require(platform[0]==(0x23,0x2c2b,0) and r.status==(5 if cf else 0),'CLC-and-INT23profile');
        if cf:require((r.exit_request.vector,r.exit_request.site,r.exit_request.incoming.registers.ax)==(0x21,0x2c31,0x4c34),'PreparedAH4CfromreturnedAL')
        checks+=1
    mode['dos_cf']=0;reset();caps.calls=1;run(entry=2);require((r.status,r.next_ip,r.current_sp,r.calls)==(3,0x2a06,0xdffc,1) and rw(bus,0x9000,0xdffc)==0x16,'MessageRETF2cleanupbeforesecondargument');checks+=1
    reset();caps.calls=3;run(entry=2);require((r.status,r.next_ip,r.current_sp,r.calls)==(3,0x2a0f,0xdffa,3) and rw(bus,0x9000,0xdffa)==3 and rw(bus,0x9000,0xdffc)==0x16,'PlainfarRETleavessecondwordbeforefinalexit');checks+=1
    reset();caps.calls=8;run(entry=2);require((r.status,r.stage,r.next_ip,r.exit_request.incoming.registers.ax)==(5,7,0x5de,0x4c03),'Actualhelperchainpreparedexit-notrootreturn');checks+=1
    deps=['tools/validate_runtime_dispatch_bus.py','analysis/history/runtime-dispatch-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-runtime-dispatch-bus-context-v1.json'];record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256(image).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_dispatch_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in deps],'limits':'Nativeonlyinvalid/budget/currentCSlookup/highwords/SSfaroperandliveness-beforeCALL/retiredhandlerprefix-rawresponse/unknownCSJMP/RETF2-vsplainfarcleanup/preparedexit diagnostics. Typedhandlers/DOS arenotactualbodies/devices/process exit; no B0FEfallthrough-pruning/core/P1-GATE/gameacceptance.'};out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
