"""Compare0582 prefix and inherited059C tail with actual full-SS children."""
import argparse,ctypes as C,hashlib,itertools,json,struct,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from validate_runtime_exit import Result,Registers,StateRegisters,DOSRequest,DOSService,CallbackRequest,CallbackService,values,require
from validate_timer_handler_bus import ww,rw
from validation.twenty_bit_bus import map_twenty_bit_ram
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DS,UC_X86_REG_ES]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=int,default=0);a=p.parse_args();lib=a.library.resolve();out=a.output.resolve();require(lib.is_relative_to(ROOT/'analysis') and out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists(),'Freshpaths')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Image');mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0];relocs=[struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    g=json.loads((ROOT/'analysis/flow/indirect-v8/direct-flow.json').read_text());names=['13A8:0582','13A8:060D','13A8:066E','13A8:0620','13A8:088C','13A8:08B7','13A8:05E0'];fs=[f for f in g['functions'] if f['entry'] in names];fence={ip for f in fs for ip in f['instructions']};root=set(next(f for f in fs if f['entry']=='13A8:0582')['instructions']);require(len(root)==51,'Root51');md=Cs(CS_ARCH_X86,CS_MODE_16);decoded={ip:next(md.disasm(image[0x13a80+ip:0x13a80+ip+15],ip,count=1)) for ip in fence};returns={ip for ip,i in decoded.items() if i.mnemonic in ['ret','retf']};calls={int(v['site'][5:],16):v['size'] for f in fs for v in f['calls']};calls.update({0x61b:decoded[0x61b].size,0x633:4,0x5e9:4});require(decoded[0x61b].size==2,"LiteralFF1Dtwo-byteCALL");cleanup={0x68a,0x627,0x63b,0x8be};fn=C.CDLL(str(lib)).td2ega_runtime_early_exit;fn.argtypes=[C.POINTER(C.c_uint8),C.c_uint32,C.c_uint16,C.c_uint16,C.c_uint16,C.POINTER(StateRegisters),DOSService,CallbackService,C.c_void_p,C.c_uint32,C.POINTER(Result)];fn.restype=None
    cases=list(itertools.product(range(4),range(6),range(3),[0,1],[80,0x7086,0xe000],[0,1,66,128],[2,0x603]))
    vectors=instructions=synthetic=0;sites=set();coverage=Counter()
    for load in [0x1000,0x2345]:
        cs,ds=load+0x13a8,load+0x178f;relocated=bytearray(image)
        for at in relocs:struct.pack_into('<H',relocated,at,(struct.unpack_from('<H',relocated,at)[0]+load)&65535)
        base=bytearray(0x100000);base[load*16:load*16+len(relocated)]=relocated;base[0xa2010]=0xcb;u=Uc(UC_ARCH_X86,UC_MODE_16);backing=map_twenty_bit_ram(u);active={}
        def snapshot():
            ef=u.reg_read(UC_X86_REG_EFLAGS);return StateRegisters(Registers(*[u.reg_read(reg) for reg in REGS],(ef>>9)&1,(ef>>10)&1),u.reg_read(UC_X86_REG_BP),ef&1)
        def req(q):return [q.vector,q.site,q.segment,q.stack_segment,q.stack_sp,*values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
        def cbreq(q):return [q.site,q.target_segment,q.target_ip,q.stack_segment,q.stack_sp,*values(q.incoming.registers),q.incoming.bp,q.incoming.carry]
        def apply(r,mut=()):
            for reg,v in zip(REGS,values(r.registers)[:8]):u.reg_write(reg,v)
            u.reg_write(UC_X86_REG_BP,r.bp);u.reg_write(UC_X86_REG_EFLAGS,2|r.carry|(r.registers.interrupts_enabled<<9)|(r.registers.direction<<10))
            for sg,off,v in mut:ww(backing,sg,off,v)
        def dos_effect(r,site):
            v=StateRegisters.from_buffer_copy(bytes(r));mut=[];profile=active['profile'];v.registers.ax=0;v.carry=0
            if profile==1:
                v.registers.ax=0xdead;v.carry=1;v.registers.interrupts_enabled^=1;v.registers.direction^=1
                if site==0x5d1:v.registers.cx=1
            if profile==2:
                v.carry=1
                if site==0x8d9:mut.append((active['ss'],r.bp,0x1357))
                if site==0x5d1:mut.append((active['ss'],r.bp+6,0x1234))
            return v,mut
        def callback_effect(r,site,qsp):
            v=StateRegisters.from_buffer_copy(bytes(r));mut=[];mode=active['mode']
            if mode==1:v.registers.ds=ds+0x100;v.registers.ax=0x1234;v.registers.bx=0x5678;v.registers.cx=0x9abc;v.registers.dx=0xdef0;v.registers.es=0x2468;v.carry^=1;v.registers.interrupts_enabled^=1;v.registers.direction^=1
            if mode==2:mut.append((active['ss'],qsp,0x4444))
            if mode==3:mut.append((active['ss'],r.bp,0x1357))
            if mode==4 and site==0x61b:v.registers.di=(v.registers.di+4)&65535
            if mode==5:v.registers.ax=0xffff;v.carry=1;v.registers.interrupts_enabled^=1;v.registers.direction^=1
            return v,mut
        def code(cpu,address,size,_):
            segment,ip=u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP)
            if active.get('synthetic_stepping'):return
            if active.get('stepping'):active['instructions']+=1;active['sites'].add(ip);return
            if active.get('foreign'):
                require((segment,ip)==active['foreign'][:2],'Foreignentry');active['foreign_state']=snapshot();active['ret_kind']='callback';u.emu_stop();return
            require(segment==cs and ip in fence,'Earlyexitfence '+str((segment,ip)))
            operation=ip in [0x611,0x677,0x899,0x633,0x5e9,0x8d9,0x5f5,0x609,0x5c8,0x5d1,0x5de] or (ip in [0x8a8,0x8cf] and u.reg_read(UC_X86_REG_CX))
            if operation:
                if active['operations']==active['limit']:active['status']=3;u.emu_stop();return
                active['operations']+=1
                if ip==0x899:active['rows']+=1
                if ip==0x5c8:active['close_iterations']+=1
                if ip==0x611:active['prefix_records']+=1
            if ip==0x5de:active['exit_request']=DOSRequest(0x21,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),snapshot());active['status']=5;u.emu_stop();return
            if ip in returns:active['ret_kind']='original';active['return_ip']=ip;u.emu_stop();return
            if ip in calls:
                active['frames'].append((cs,ip+calls[ip],(u.reg_read(UC_X86_REG_SP)+(2 if ip in cleanup else 0))&65535))
                if ip in [0x61b,0x633,0x5e9]:
                    d=u.reg_read(UC_X86_REG_DS);off=u.reg_read(UC_X86_REG_DI) if ip==0x61b else 0x6dcc if ip==0x633 else 0x7076;active['foreign']=(rw(backing,d,off+2),rw(backing,d,off),ip)
            active['instructions']+=1;active['sites'].add(ip)
        def written(cpu,access,address,size,value,_):active['writes']+=1
        def interrupt(cpu,number,_):
            ip=u.reg_read(UC_X86_REG_IP)-2;require(number==0x21 and ip in [0x5d1,0x8d9,0x5f5,0x609],'ExplicitDOS');q=DOSRequest(number,ip,cs,active['ss'],u.reg_read(UC_X86_REG_SP),snapshot());active['dos'].append(req(q));active['close_requests']+=int(ip==0x5d1);apply(*dos_effect(q.incoming,ip))
        u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,written);u.hook_add(UC_HOOK_INTR,interrupt)
        for kind,mode,profile,same,sp,limit,flags in cases:
            ss=ds if same else 0x9000;data=bytearray(base)
            for d in [ds,ds+0x100]:data[d*16:d*16+65536]=bytes(65536)
            for d in [ds,ds+0x100]:
                data[d*16]=0x55 if kind<2 else 0x54;cursor=0x82c4
                for key in [0xfc,0xff,1]:ww(data,d,cursor,key);cursor+=2;data[d*16+cursor:d*16+cursor+3]=b'AB\0';cursor+=3
                ww(data,d,cursor,0xffff)
                for k in range(15):data[d*16+0x6da9+k]=(k&1) if kind&1 else 0
                offset,segment=[(0,0),(0,0x9000),(0x4000,0x9000),(0x4000,0)][kind];ww(data,d,0x7082,offset);ww(data,d,0x7084,segment)
                for off in [0x6dcc,0x7076]:ww(data,d,off,0x4000 if kind&1 else 0);ww(data,d,off+2,0x9000 if kind&1 else 0)
                ww(data,d,0x6d89,0x1234);ww(data,d,0x6d8b,0x7000);ww(data,d,0x6dc8,0x5678);ww(data,d,0x6dca,0x7100);data[d*16+0x6dc6]=int(d!=ds);data[d*16+0x6dc7]=0x24
            for i,v in enumerate([0x1111,0x2222,0]):ww(data,ss,sp+2*i,v)
            incoming=StateRegisters(Registers(0xa55a,0xb123,0xc456,0xd789,0x3456,0x4567,ds,0x5432,(flags>>9)&1,(flags>>10)&1),0x5678,flags&1);u.mem_write(0,bytes(data))
            for reg,v in list(zip(REGS,values(incoming.registers)[:8]))+[(UC_X86_REG_BP,incoming.bp),(UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x582),(UC_X86_REG_EFLAGS,flags)]:u.reg_write(reg,v)
            active.clear();active.update(ss=ss,mode=mode,profile=profile,limit=limit,operations=0,rows=0,close_iterations=0,close_requests=0,prefix_records=0,writes=0,instructions=0,sites=set(),frames=[],foreign=None,ret_kind=None,status=0,dos=[],callbacks=[],exit_request=None);u.emu_start(cs*16+0x582,0,count=100000)
            while active['ret_kind']:
                ret_kind=active['ret_kind'];active['ret_kind']=None
                if ret_kind=='callback':
                    sg,ip,site=active['foreign'];qsp=u.reg_read(UC_X86_REG_SP);r=active['foreign_state'];active['callbacks'].append(cbreq(CallbackRequest(site,sg,ip,ss,qsp,r)));apply(*callback_effect(r,site,qsp));active['foreign']=None;u.reg_write(UC_X86_REG_CS,0xa200);u.reg_write(UC_X86_REG_IP,0x10);active['synthetic_stepping']=True;u.emu_start(0xa2010,0,count=1);active['synthetic_stepping']=False;synthetic+=1
                else:active['stepping']=True;u.emu_start(cs*16+active['return_ip'],0,count=1);active['stepping']=False
                require(active['frames'],'Returnowner');expected=active['frames'].pop()
                if (u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),u.reg_read(UC_X86_REG_SP))!=expected:active['status']=1;break
                u.emu_start(cs*16+u.reg_read(UC_X86_REG_IP),0,count=100000)
            require(active['status'],'Qualifiedoutcome');native_dos=[];native_callbacks=[]
            def mutate(m,mut):
                for sg,off,v in mut:ww(m,sg,off,v)
            def dos(ctx,m,qptr,rptr):q=qptr.contents;native_dos.append(req(q));v,mut=dos_effect(q.incoming,q.site);rptr[0]=v;mutate(m,mut);return 1
            def callback(ctx,m,qptr,rptr):q=qptr.contents;native_callbacks.append(cbreq(q));v,mut=callback_effect(q.incoming,q.site,q.stack_sp);rptr[0]=v;mutate(m,mut);return 1
            dos_cb=DOSService(dos);callback_cb=CallbackService(callback);bus=(C.c_uint8*len(data)).from_buffer_copy(data);r=Result();fn(bus,len(bus),load,ss,sp,C.byref(incoming),dos_cb,callback_cb,None,limit,C.byref(r));label=str((load,kind,mode,profile,same,sp,limit,flags))
            observed=(r.status,r.current_sp,r.next_segment,r.next_ip,r.operations,r.rows,r.services,r.callbacks,r.close_iterations,r.close_requests,r.bus_writes);expected=(active['status'],u.reg_read(UC_X86_REG_SP),u.reg_read(UC_X86_REG_CS),u.reg_read(UC_X86_REG_IP),active['operations'],active['rows'],len(active['dos']),len(active['callbacks']),active['close_iterations'],active['close_requests'],active['writes']);require(observed==expected,'Earlyexitcontrol '+label+str((observed,expected)));require(native_dos==active['dos'] and native_callbacks==active['callbacks'],'EarlyexitABI '+label);require(bytes(bus)==bytes(backing),'EarlyexitwholeRAM '+label);require(values(r.returned.registers)[:8]==[u.reg_read(reg) for reg in REGS] and r.returned.bp==u.reg_read(UC_X86_REG_BP),'EarlyexitGPR-BP '+label);ef=u.reg_read(UC_X86_REG_EFLAGS);require((r.returned.carry,r.returned.registers.interrupts_enabled,r.returned.registers.direction)==(ef&1,(ef>>9)&1,(ef>>10)&1),'EarlyexitCFIFDF '+label)
            if active['exit_request'] is not None:require(req(r.exit_request)==req(active['exit_request']),'PreparedAH4C '+label)
            vectors+=1;instructions+=active['instructions'];sites.update(active['sites']);coverage['status_'+str(r.status)]+=1;coverage['prefix_records']+=active['prefix_records'];coverage['callbacks']+=r.callbacks;coverage['CPU_writes']+=r.bus_writes;coverage['minimumSP80_cases']+=int(sp==80)
            if a.probe and vectors>=a.probe:print(json.dumps({'probe':'pass','vectors':vectors,'sites':len(sites),'root_sites':len(root&sites)}));return
            if vectors%1024==0:print(json.dumps({'vectors_completed':vectors,'sites':len(sites),'root_sites':len(root&sites),'load':hex(load)}),flush=True)
    admitted=root-{0x5de};require(admitted.issubset(sites) and coverage['prefix_records'] and coverage['status_5'] and coverage['status_1'] and coverage['status_3'],'Earlyexitroot50coverage '+str(sorted(admitted-sites)))
    deps=['analysis/history/runtime-early-exit-validation-refinement-v2.json','tools/validate_runtime_exit.py','tools/validate_runtime_message.py','tools/validate_finalizer_list.py','tools/validate_timer_handler_bus.py','tools/validation/twenty_bit_bus.py','analysis/history/runtime-early-exit-build-setup-v1.json','analysis/reviews/runtime-formatter-frontier-v1.json'];record={'schema':1,'result':'pass','function_ids':['FN-EGA-000260'],'vectors':vectors,'image_sha256':sha,'library_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'src/recovered/td2ega_runtime_early_exit.c').read_bytes()).hexdigest(),'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'original_instructions_executed':instructions,'instruction_sites_in_fence':len(fence),'instruction_sites_exercised':len(sites),'root_sites_in_fence':51,'root_sites_admitted':50,'root_sites_exercised':len(root&sites),'prepared_exit_boundary_sites':['13A8:05DE'],'synthetic_callback_RETF_instructions':synthetic,'fixture_coverage':dict(coverage),'limits':'Actual0582two060Dprefix/inherited059Ctail/actualmessage-diagnostic-vectorchildren/fullSS-GPR-BP-CFIFDF-wholeRAM-services-CPUwrites. Prefix060Diterationsshareoperationbudget; callbacks applyoutsideCODEhook andgenericRETFs countseparately. PreparedAH4Cnotexecuted/no fakeextraPUSHBP orrootreturn. OtherarithmeticFLAGSunexposed; initial0599->post04A30582hook/actualDS-SSbinding-allwriters-lifetimes/core/fatalformatter-B0FEarena/P1-GATE/DOSsession-game-fidelity open.'};out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({k:record[k] for k in ['result','vectors','root_sites_exercised','instruction_sites_exercised','original_instructions_executed','fixture_coverage']},indent=2))
if __name__=='__main__':main()
