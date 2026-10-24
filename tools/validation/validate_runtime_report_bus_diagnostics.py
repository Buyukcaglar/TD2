"""Native report-parent admission, late SS arguments and cleanup diagnostics."""
import argparse,ctypes as C,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from validate_runtime_report_bus import Services,Limits,Result,Registers,StateRegisters,DOSService,DeviceService,PortService,Handler,RuntimeServices,RuntimeLimits,CallbackService,DOSRequest,require,ww,rw

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    fn=C.CDLL(str(lib)).td2ega_runtime_report_bus;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32]+[C.c_uint16]*6+[C.POINTER(StateRegisters),C.POINTER(Limits),C.POINTER(Services),C.POINTER(Result)];fn.restype=None
    bus=(C.c_uint8*0x100000)();s=StateRegisters();r=Result();caps=Limits();services=Services();mode={};ports=[];bios_events=[];formatter_events=[];checks=0;image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();ss=0x9000;sp=0xe000
    def bios(ctx,m,qptr,rptr):
        q=qptr.contents;bios_events.append(q.site);v=StateRegisters.from_buffer_copy(bytes(q.incoming))
        if mode['bp']:v.bp=sp-16
        rptr[0]=v;return 1
    def device(ctx,m,qptr,rptr):
        q=qptr.contents;rptr.contents.returned=q.incoming
        if q.kind==3:m[q.address]=q.value
        return 1
    def port(ctx,qptr,value):
        q=qptr.contents;ports.append((q.operation,q.port,q.value,q.interrupts_enabled));value[0]=mode['pic'] if q.port==0x21 else 0xa7
        if len(ports)==1 and mode['mutate']:ww(bus,ss,sp,0xabcd)
        return int(len(ports)!=mode['fail_port'])
    def formatter(ctx,m,n,qptr,rptr):
        q=qptr.contents;formatter_events.append((q.kind,q.site,q.stack_sp,[rw(m,q.stack_segment,q.stack_sp+4+2*i) for i in range(5)]));v=StateRegisters.from_buffer_copy(bytes(q.incoming));o=rptr.contents;o.returned=v;o.flags_word=2|v.carry|(v.registers.interrupts_enabled<<9)|(v.registers.direction<<10);o.flags_mask=0xf72b;o.current_sp=q.stack_sp+4;o.next_ip=rw(m,q.stack_segment,q.stack_sp);o.next_segment=rw(m,q.stack_segment,q.stack_sp+2)
        if mode['fmt']=='raw':o.next_ip=0x4444
        if mode['fmt']=='sp':o.current_sp+=2
        if mode['fmt']=='prefix':o.status=3;o.current_sp=q.stack_sp;o.next_segment=q.target_segment;o.next_ip=q.target_ip;o.flags_mask=0xf72a
        if mode['fmt']=='invalid':o.returned.carry=2
        if mode['fmt']=='invalid_status':o.status=6
        if mode['fmt']=='flags':o.returned.carry=1;o.returned.registers.interrupts_enabled=1;o.returned.registers.direction=1;o.flags_word=0x643
        return 1
    def dos(ctx,m,qptr,rptr):v=StateRegisters.from_buffer_copy(bytes(qptr.contents.incoming));v.registers.ax=0;v.carry=0;rptr[0]=v;return 1
    def finalizer(ctx,m,qptr,rptr):rptr[0]=qptr.contents.incoming;return 1
    bios_cb=DOSService(bios);device_cb=DeviceService(device);port_cb=PortService(port);fmt_cb=Handler(formatter);dos_cb=DOSService(dos);handler_cb=Handler();final_cb=CallbackService(finalizer)
    def reset(key=1,stack=0xe000,segment=0x9000):
        nonlocal ss,sp,s,r,caps,services
        ss,sp=segment,stack;C.memset(bus,0,len(bus));s=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,0x278f,0x5432,0,0),0x5678,0);r=Result();caps=Limits(7,5,3,1,8008,1,8,RuntimeLimits(32,8,128,128));services=Services(bios_cb,device_cb,port_cb,fmt_cb,RuntimeServices(dos_cb,handler_cb,final_cb,None),None);ports.clear();bios_events.clear();formatter_events.clear();mode.update(pic=0xa5,fail_port=0,mutate=False,bp=False,fmt='normal')
        for off,value in [(0x62ae,key),(0x62b0,0x2345),(0x62b2,0x3456),(0x62b4,0x4567),(0x5e88,0x9876),(0x5e8a,0x8765)]:ww(bus,0x278f,off,value)
        bus[0x417]=0xab;ww(bus,0x40,0x10,0x30);ww(bus,0,0x20,0x4321);ww(bus,0,0x22,0x5678)
        for off,length in [(0x2cae,6),(0x2c10,12)]:C.memmove(C.addressof(bus)+0x23a80+off,image[0x13a80+off:0x13a80+off+length],length)
        bus[0x278f0]=0x55;cursor=0x82c4
        for key in [0xa,0xfc,0xff,1]:ww(bus,0x278f,cursor,key);cursor+=2;bus[0x278f0+cursor]=65;bus[0x278f0+cursor+1]=0;cursor+=2
        ww(bus,0x278f,cursor,0xffff)
        for slot in range(6):ww(bus,0x278f,0x7058+4*slot,1)
        for i,v in enumerate([0x1111,0x2222,0x1357,0x2468,0x369c,0x48ad,0x5bce]):ww(bus,ss,sp+2*i,v)
    def run(entry=1,stack=None,flags=2,mask=65535,memory=None,size=None,stateptr=True,limitsptr=True,serviceptr=True,outptr=True):
        fn(bus if memory is None else memory,len(bus) if size is None else size,0x1000,ss,sp if stack is None else stack,entry,flags,mask,C.byref(s) if stateptr else None,C.byref(caps) if limitsptr else None,C.byref(services) if serviceptr else None,C.byref(r) if outptr else None)
    reset();before=bytes(bus)
    for kw in [dict(entry=2),dict(entry=0,stack=105),dict(entry=0,stack=0xffe1),dict(mask=0),dict(mask=1),dict(flags=0),dict(flags=3),dict(flags=0x1000),dict(size=0xfffff),dict(stateptr=False),dict(limitsptr=False),dict(serviceptr=False),dict(memory=C.POINTER(C.c_uint8)())]:
        run(**kw);require(r.status==2 and not r.bus_writes and not r.ports and bytes(bus)==before,'Invalidbeforeeffects');checks+=1
    run(outptr=False);require(bytes(bus)==before,'Nulloutbeforeeffects');checks+=1
    for field in ['carry','if','df']:
        reset()
        if field=='carry':s.carry=2
        elif field=='if':s.registers.interrupts_enabled=2
        else:s.registers.direction=2
        before=bytes(bus);run();require(r.status==2 and bytes(bus)==before,'Invalidstate');checks+=1
    for entry in [0,1]:
        for mask in [65535,0xffef,0xf72b,0xf72a]:
            reset();caps.steps=0;before=bytes(bus);run(entry=entry,mask=mask);require((r.status,r.current_sp,r.next_ip,r.flags_mask,r.bus_writes)==(3,sp,2 if entry==0 else 0x68c4,mask,0) and bytes(bus)==before,'Beforeentrybudget');checks+=1
    for key in [0,1]:
        reset(key=key);run();require((r.status,r.current_sp,r.next_ip,r.next_segment,r.ports,r.bus_writes,r.returned.registers.ax,r.flags_mask)==(0,sp+4,0x1111,0x2222,3,5 if key else 0,0xa5a5,0xffef),'Cleanupguard-retirement');require([q[2] for q in ports if q[0]]==[0xa7,0xa5],'PICrestoreAH');checks+=1
    for n,site in [(0,0x68c4),(1,0x68ca),(2,0x6904)]:
        reset();caps.keyboard_ports=n;run();require((r.status,r.next_ip,r.ports,r.current_sp)==(3,site,n,sp),'Keyboardportbudget');checks+=1
    for n,site in [(1,0x68c4),(2,0x68ca),(3,0x6904)]:
        reset();mode['fail_port']=n;run();require((r.status,r.next_ip,r.ports)==(4,site,n),'Keyboardportfailure');checks+=1
    reset();services.port=PortService();run();require((r.status,r.next_ip,r.ports)==(4,0x68c4,1),'Missingport');checks+=1
    reset();mode['mutate']=True;run();require((r.status,r.next_ip,r.next_segment)==(0,0xabcd,0x2222),'Portmutationchangesactualrootwords');checks+=1
    for stack in [0xfffd,0xffff]:
        reset(stack=stack);run();require((r.status,r.next_ip,r.current_sp,r.ports,r.bus_writes)==(7,0x6906,stack,3,5),'PreRETaftereffects');checks+=1
    reset(segment=0,stack=0x24);run();require((r.status,r.next_ip,r.next_segment)==(0,1,0x2345),'IVTstoresalterrootreturn');checks+=1
    reset(segment=0x40,stack=0x17);run();require((r.status,r.next_ip,r.next_segment)==(0,0x1110,0x2222),'BDAbytealtersrootIP');checks+=1
    reset();caps.calls=0;run(entry=0);require((r.status,r.next_ip,r.current_sp,r.bus_writes,r.returned.bp)==(3,5,sp-2,1,sp-2),'ParentPUSHBPbeforeCALLbudget');checks+=1
    reset();caps.video_events=0;run(entry=0);require(r.status==3 and r.stage==1 and not r.device_events and not formatter_events,'Videochildbudgetpropagates');checks+=1
    reset();services.device=DeviceService();run(entry=0);require(r.status==4 and r.stage==1 and not formatter_events,'Missingdeviceadapter');checks+=1
    reset();mode['bp']=True;caps.runtime.steps=0;run(entry=0);require((r.status,r.stage,r.next_ip,r.calls)==(3,5,0x29f6,5) and formatter_events[0][3]==[0x5678]*5 and r.flags_mask==65535,'LateSSPUSHcascade-callerADD');checks+=1
    for profile,status in [('raw',1),('sp',1),('prefix',3),('invalid',4),('invalid_status',4)]:
        reset();mode['fmt']=profile;run(entry=0);require((r.status,r.stage,r.calls)==(status,4,4),'Formatterqualifiedresponse');
        if profile=='prefix':require(r.flags_mask==0xf72a and r.next_ip==0xb00,'Partialprefixflags')
        checks+=1
    reset();services.formatter=Handler();run(entry=0);require((r.status,r.stage,r.next_ip,r.callbacks)==(4,4,0xb00,0),'MissingformatterafterCALL');checks+=1
    reset();mode['fmt']='flags';caps.runtime.steps=0;run(entry=0);require((r.status,r.stage,r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction,r.flags_mask)==(3,5,0,1,1,65535),'ADDSPregainsCF-preservesIFDF');checks+=1
    reset();run(entry=0);require((r.status,r.stage,r.next_ip,r.exit_request.vector,r.exit_request.incoming.registers.ax)==(5,5,0x5de,0x21,0x4c03),'PreparedDOSexit-notparentreturn');checks+=1
    deps=['tools/validate_runtime_report_bus.py','analysis/history/runtime-report-bus-build-setup-v1.json','docs/recovery/evidence/td2ega-runtime-report-bus-context-v1.json','docs/recovery/evidence/td2ega-runtime-report-bus-alias-validation-v1.json'];record={'schema':1,'result':'pass','vectors':checks,'image_sha256':hashlib.sha256(image).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_report_bus.c').read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Nativeonlyinvalid/budget/adapter/actualSS-IVT-BDA-returnaliases/PICrestoreAH/returnedBP-latefivewordcascade/typedformatterprefix-raw-invalidresponses/callerADDSPFLAGS/preparedDOSexit. Originalcomparisonsseparate; noformatterbody/historicalterminalDOS/arena-pruning/caller-allwriters-lifetime-IRQ-core/P1-GATE/runtime-game-fidelity acceptance.'};out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','native_checks':checks}))
if __name__=='__main__':main()
