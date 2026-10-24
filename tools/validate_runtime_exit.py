"""Compare actual exit helper chain through a prepared DOS4C boundary."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from validate_line_draw import Registers,StateRegisters,require,values
from validate_runtime_message import Request as DOSRequest,Service as DOSService
from validate_finalizer_list import Request as CallbackRequest,Service as CallbackService
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
class Result(C.Structure):
    _fields_=[(n,C.c_uint16) for n in ['status','current_sp','next_segment','next_ip']]+[(n,C.c_uint32) for n in ['operations','rows','services','callbacks','close_iterations','close_requests','bus_writes']]+[('returned',StateRegisters),('exit_request',DOSRequest)]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();library=a.library.resolve();output=a.output.resolve();require(library.is_relative_to(ROOT/'analysis') and output.is_relative_to(ROOT/'docs/recovery/evidence') and not output.exists(),'Private/fresh paths');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','MZ');n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)];fn=C.CDLL(str(library)).td2ega_runtime_exit;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None;g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());selected=[f for f in g['functions'] if f['entry'] in ['13A8:0599','13A8:060D','13A8:066E','13A8:0620','13A8:088C','13A8:08B7','13A8:05E0']];fence={ip for f in selected for ip in f['instructions']};unreachable={0x611,0x614,0x616,0x619,0x61b,0x61d};return_sites={0x61f,0x693,0x643,0x8df,0x8b4,0x60c};call_sizes={0x5a2:3,0x5ab:3,0x5ae:5,0x5d6:3,0x681:5,0x68a:5,0x627:5,0x63b:5,0x8be:5,0x633:4,0x5e9:4};cleanup_calls={0x68a,0x627,0x63b,0x8be};regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES];vectors=instructions=0;sites=set();boundary_sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray([0xa5])*0x100000;base[load*16:load*16+len(relocated)]=relocated;base[ds*16:ds*16+65536]=b'\xa5'*65536;base[0x90000]=base[0x94000]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x100000);active={}
        def snapshot():
            f=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in regs],(f>>9)&1,(f>>10)&1),u.reg_read(UC_X86_REG_BP),f&1)
        def request_row(site,r,qsp):return [0x21,site,cs,active['ss'],qsp,*values(r.registers),r.bp,r.carry]
        def dos_response(r,site,profile,ss,qsp,index):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if profile==0:returned.registers.ax=0;returned.carry=0
            if profile==1:
                returned.registers.ax=0xdead;returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
                if site==0x5d1 and index==0:returned.registers.cx=0;returned.registers.bx=0xffff
            if profile==2:returned.bp=0xd000;returned.carry=1
            if profile==3:
                returned.carry=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
                if site==0x8d9:mutations.append((ss*16+r.bp,struct.pack('<H',0x1357)))
                if site in [0x5f5,0x609]:mutations.append((ss*16+qsp,struct.pack('<H',ds+0x100)))
                if site==0x5d1:mutations.extend([(ss*16+((r.bp+6)&65535),struct.pack('<H',0x1234)),(r.registers.ds*16+((r.registers.bx+1+0x6da4)&65535),b'\0')])
            return returned,mutations
        def callback_response(r,site,mode,ss,qsp):
            returned=StateRegisters.from_buffer_copy(bytes(r));mutations=[]
            if mode==1:returned.registers.ds=ds+0x100;returned.registers.ax=0x1234;returned.registers.bx=0x5678;returned.registers.cx=0x9abc;returned.registers.dx=0xdef0;returned.registers.si=0x3456;returned.registers.di=0x4567;returned.registers.es=0x2468;returned.carry^=1;returned.registers.interrupts_enabled^=1;returned.registers.direction^=1
            if mode==3:mutations.append((ss*16+qsp,struct.pack('<H',0x4444)))
            if mode==4:mutations.append((ss*16+r.bp,struct.pack('<H',0x1357)))
            return returned,mutations
        def apply(returned,mutations):
            for reg,v in zip(regs,values(returned.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,returned.bp);u.reg_write(UC_X86_REG_EFLAGS,2|returned.carry|(returned.registers.interrupts_enabled<<9)|(returned.registers.direction<<10))
            for at,value in mutations:u.mem_write(at,value)
            active['service_write_events']+=len(mutations)
        def code(cpu,address,size,unused):
            if active.get('executing_return'):return
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if segment==0x9000 and ip in [0,0x4000]:
                require(active['call_stack'],'Callbackfarframe owner');site=active['call_stack'][-1][3];r=snapshot();active['callback_requests'].append([site,segment,ip,active['ss'],u.reg_read(UC_X86_REG_SP),*values(r.registers),r.bp,r.carry]);apply(*callback_response(r,site,active['mode'],active['ss'],u.reg_read(UC_X86_REG_SP)));active['return_kind']='callback';u.emu_stop();return
            require(segment==cs and ip in fence and ip not in unreachable,'Exit chain escaped '+hex(address))
            if ip in return_sites:active['return_kind']='original';u.emu_stop();return
            is_operation=ip in [0x677,0x899,0x633,0x5e9,0x8d9,0x5f5,0x609,0x5c8,0x5d1,0x5de] or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX)!=0)
            if is_operation:
                if active['operations']==active['limit']:active['prefix']=True;u.emu_stop();return
                active['operations']+=1
                if ip==0x899:active['rows']+=1
                if ip==0x5c8:active['close_iterations']+=1
            if ip==0x5de:active['exit_request']=request_row(ip,snapshot(),u.reg_read(UC_X86_REG_SP));active['exit']=True;boundary_sites.add(ip);u.emu_stop();return
            if ip in call_sizes:active['call_stack'].append((cs,ip+call_sizes[ip],u.reg_read(UC_X86_REG_SP)+(2 if ip in cleanup_calls else 0),ip))
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,unused):active['writes']+=1
        def interrupt(cpu,number,unused):
            site=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and site in [0x5d1,0x8d9,0x5f5,0x609],'Onlyclose/write/vectorservices, noactualexit');r=snapshot();index=active['close_requests'] if site==0x5d1 else len(active['dos_requests']);active['dos_requests'].append(request_row(site,r,u.reg_read(UC_X86_REG_SP)))
            if site==0x5d1:active['close_requests']+=1
            apply(*dos_response(r,site,active['profile'],active['ss'],u.reg_read(UC_X86_REG_SP),index))
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        cases=list(itertools.product(range(4),range(4),range(4),range(4),[0,1],[0xe000,0x6db0],[0,0xff00],[2,0x603],[0,66,90,128,256]))
        cases +=[(kind,pattern,mode,profile,same,80,arg,flags,limit) for kind,pattern,mode,profile,same,arg,flags,limit in itertools.product([0,2],range(3),range(3),[0,2],[0,1],[0,1,0x1234,0xff00],[2,0x603],[66,128])]
        cases +=[(2,2,4,profile,same,0xe000,0,flags,limit) for profile,same,flags,limit in itertools.product([0,3],[0,1],[2,0x603],[128,256])]
        cases +=[(0,0,0,0,same,0xe000,0,flags,128,last) for same,flags,last in itertools.product([0,1],[2,0x603],range(256))]
        for case in cases:
            kind,pattern,mode,profile,same,sp,arg,flags,limit=case[:9];last=case[9] if len(case)==10 else [0,0x55,0,0x42][kind];data=bytearray(base);ss=ds if same else 0x9000
            for segment in [ds,ds+0x100]:
                cursor=0x82c4
                for key,length in [(0xfc,2),(0xff,1),(1,3)]:struct.pack_into('<H',data,segment*16+cursor,key);cursor+=2;data[segment*16+cursor:segment*16+cursor+length+1]=b'A'*length+b'\0';cursor+=length+1
                struct.pack_into('<H',data,segment*16+cursor,0xffff)
                for k in range(15):data[segment*16+0x6da9+k]=0 if pattern==0 else k%2 if pattern==1 else 0xa5 if pattern==2 else 0xa4
                struct.pack_into('<2H',data,segment*16+0x6dcc,0 if mode==2 else 0x4000,0 if mode==0 else 0x9000);struct.pack_into('<2H',data,segment*16+0x7076,0 if mode==2 else 0x4000,0 if mode==0 else 0x9000);struct.pack_into('<2H',data,segment*16+0x6d89,0x1234,0x7000);struct.pack_into('<2H',data,segment*16+0x6dc8,0x5678,0x7100);data[segment*16+0x6dc6]=0 if segment==ds else 1;data[segment*16+0x6dc7]=0x24
            data[ds*16:ds*16+0x42]=bytes(0x42);data[ds*16+0x41]=last
            if len(case)==10 or kind in [0,1]:data[ds*16]=0x55^last
            if kind==3 and len(case)==9:data[ds*16:ds*16+0x42]=bytes(range(1,67))
            data[ss*16+sp:ss*16+sp+6]=struct.pack('<3H',0x1111,0x2222,arg);data[ss*16+0xd000:ss*16+0xd008]=struct.pack('<4H',0x7777,0x4444,0x5555,0x5a);struct.pack_into('<H',data,ss*16+0x135d,0x66);incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(regs,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x599),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.update(mode=mode,profile=profile,ss=ss,limit=limit,operations=0,rows=0,close_iterations=0,close_requests=0,writes=0,instructions=0,sites=set(),dos_requests=[],callback_requests=[],service_write_events=0,call_stack=[],executing_return=False,prefix=False,return_kind=None,exit=False,exit_request=None);u.emu_start(cs*16+0x599,0,count=100000);raw=False;synthetic_returns=0;label=f'{load:x}/{case}'
            while active['return_kind']:
                kind_ret=active['return_kind'];segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP);active['return_kind']=None;require(active['call_stack'],'Returnowner '+label);expected=active['call_stack'].pop();active['executing_return']=True;u.emu_start(segment*16+ip,0,count=1);active['executing_return']=False
                if kind_ret=='callback':synthetic_returns+=1
                else:sites.add(ip);active['instructions']+=1
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=expected[:3]:raw=True;break
                u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=100000)
            require(active['prefix'] or active['exit'] or raw,'Outcome '+label);native_dos=[];native_callbacks=[];native_close=[0]
            def mutate(memory,mutations):
                for at,value in mutations:
                    for k,b in enumerate(value):memory[at+k]=b
            @DOSService
            def dos(context,memory,q,out):
                request=q.contents;r=request.incoming;index=native_close[0] if request.site==0x5d1 else len(native_dos);native_dos.append([request.vector,request.site,request.segment,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry])
                if request.site==0x5d1:native_close[0]+=1
                returned,mutations=dos_response(r,request.site,profile,ss,request.stack_sp,index);out[0]=returned;mutate(memory,mutations);return 1
            @CallbackService
            def callback(context,memory,q,out):
                request=q.contents;r=request.incoming;native_callbacks.append([request.site,request.target_segment,request.target_ip,request.stack_segment,request.stack_sp,*values(r.registers),r.bp,r.carry]);returned,mutations=callback_response(r,request.site,mode,ss,request.stack_sp);out[0]=returned;mutate(memory,mutations);return 1
            bus=(C.c_uint8*len(data)).from_buffer_copy(data);out=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),dos,callback,None,limit,C.byref(out));require(out.status==(3 if active['prefix'] else 1 if raw else 5) and out.current_sp==u.reg_read(UC_X86_REG_SP) and out.operations==active['operations'] and out.rows==active['rows'] and out.services==len(active['dos_requests']) and out.callbacks==len(active['callback_requests']) and out.close_iterations==active['close_iterations'] and out.close_requests==active['close_requests'] and out.bus_writes==active['writes'],'Status/count '+label+str((out.status,out.operations,out.rows,out.services,out.callbacks,out.close_iterations,out.close_requests,out.bus_writes,active)));require(native_dos==active['dos_requests'] and native_callbacks==active['callback_requests'],'ServiceABI '+label);require(bytes(bus)==bytes(u.mem_read(0,len(data))),'Wholebus/nestedSS '+label);r=out.returned;require([u.reg_read(reg) for reg in regs]==values(r.registers)[:8] and u.reg_read(UC_X86_REG_BP)==r.bp,'GPR '+label+str(([u.reg_read(reg) for reg in regs],values(r.registers)[:8])));f=u.reg_read(UC_X86_REG_EFLAGS);require((f&1,(f>>9)&1,(f>>10)&1)==(r.carry,r.registers.interrupts_enabled,r.registers.direction),'CFIFDF '+label);require((out.next_segment,out.next_ip)==(u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)),'Control '+label)
            if active['exit']:
                q=out.exit_request;e=q.incoming;require([q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(e.registers),e.bp,e.carry]==active['exit_request'],'PreparedDOS4Crequest '+label)
            if len(case)==10:require(out.status==5 and r.registers.ax==(0x4c00 if last==0 else 0x4cff) and out.close_requests==0,'AllbyteAX/exitwordcomposition '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['budget_prefix' if active['prefix'] else 'raw_child_return' if raw else 'prepared_exit_request']+=1;coverage['close_iterations']+=out.close_iterations;coverage['close_requests']+=out.close_requests;coverage['more_than_15_close_iterations_cases']+=int(out.close_iterations>15);coverage['DOSservices']+=out.services;coverage['callbacks']+=out.callbacks;coverage['synthetic_callback_RETF_instructions']+=synthetic_returns;coverage['bus_write_events']+=out.bus_writes;coverage['allbyte_exitword_compositions']+=int(len(case)==10);coverage['minimumSP80_cases']+=int(sp==80)
        print(json.dumps({'load':hex(load),'vectors_completed':vectors}),flush=True)
    expected_executed=fence-unreachable-{0x5de};require(sites==expected_executed and boundary_sites=={0x5de} and coverage['more_than_15_close_iterations_cases']>0 and coverage['allbyte_exitword_compositions']==2048,'Coverage '+str(expected_executed-sites));record={'schema':1,'result':'pass','function_ids':['FN-EGA-000261'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_exit.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['tools/validate_line_draw.py','tools/validate_state_loop.py','tools/validate_runtime_message.py','tools/validate_finalizer_list.py']],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'prepared_exit_boundary_sites':['13A8:05DE'],'unreachable_under_fixed_empty_spans':[f'13A8:{ip:04X}' for ip in sorted(unreachable)],'fixture_coverage':dict(coverage),'limits':'Actual0599/twoempty060Dnearwalks/066E/0620/088C/08B7/05E0 bodies throughpreparedDOS4C boundary, noactualexitINT/delivery orprocess termination. Fullbus/nestedSS/GPR/BP/CFIFDF/serviceABI/control, rawfullAX->SSexitword andservice-mutatedBX/CXcloseLOOP retained. Six060Dbody sites unreachableunderfixedemptyrootspans; helperunitseparatelycoversallnine. 05DEobserved/preparednotexecuted. SyntheticDOS/callbackbodies/RETFseparate. Nativeprefix/rawchild/adapter distinct. Actualcaller/source/targets/writers/lifetime/otherFLAGS/core/resourcefedP2/P3/device/session/game/fidelity open.'};output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['result','vectors','instruction_sites_in_fence','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
