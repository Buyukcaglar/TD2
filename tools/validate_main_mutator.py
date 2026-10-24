"""Fence13A8:002E self-modification with synthetic INT11 equipment responses.

No DOS process, disk I/O or game session executes. Loaded private copies only;
the admitted unrelocated image is never changed. Track live instruction starts
and writes before assigning static-tail effects to a later caller state.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_DX,UC_X86_REG_AX,UC_X86_REG_EFLAGS
from capstone import Cs,CS_ARCH_X86,CS_MODE_16


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();image_sha=hashlib.sha256(image).hexdigest()
    require(image_sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text())
    initial_starts={ip for f in graph['functions'] if f['entry'].startswith('13A8:') for ip in f['instructions']}
    md=Cs(CS_ARCH_X86,CS_MODE_16);rows=[];live={};outcomes=Counter();total_instructions=0
    control_offsets=[0x6c90+v for v in [0x1bf7,0x424a,0x4275,0x42ad]]
    own_offsets=[0x13a80+v for v in [0xbb,0x154,0x3da]]
    for load in [0x1000,0x2345]:
        for drive in list(range(26))+[0x80,0xff,0x100,0xffff]:
            for equipment_index,second_equipment_index in ((first,second) for first in range(4) for second in range(4)):
                for carry in [0,1]:
                    relocated=bytearray(image)
                    for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
                    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000);uc.mem_write(load*16,bytes(relocated))
                    cs=load+0x13a8;group=load+0x178f;sp=0xe000;ss=group;body=cs*16;writes=[];returns=[];instructions=[0];bios_calls=[0]
                    uc.mem_write(group*16+0x5657,struct.pack('<H',drive));uc.mem_write(0x10,struct.pack('<HH',0x1111,0x2222))
                    uc.mem_write(ss*16+sp-0x100,b'\xa5'*0x108);uc.mem_write(ss*16+sp,struct.pack('<HH',0x100,0x8000))
                    preserved=[(UC_X86_REG_DS,group),(UC_X86_REG_SS,ss),(UC_X86_REG_ES,0x4444),(UC_X86_REG_BP,0x1111),(UC_X86_REG_SI,0x2222),(UC_X86_REG_DI,0x3333)]
                    for reg,val in preserved+[(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x2e),(UC_X86_REG_SP,sp),(UC_X86_REG_AX,0xbeef),(UC_X86_REG_DX,0x5555),(UC_X86_REG_EFLAGS,0x202|carry)]:uc.reg_write(reg,val)
                    allowed_writes={0x10,0x11,0x12,0x13,group*16+0x5656}
                    allowed_writes.update(load*16+off for off in control_offsets)
                    allowed_writes.update(body+v for v in [0x24,0x2a,0x2b,0x2c,0x2d,0xbb,0x154,0x3da])
                    def fetch(u,address,size,_):
                        require(u.reg_read(UC_X86_REG_CS)==cs and (0x2e<=address-body<0x1ad or 0x3d3<=address-body<0x3f8),'Mutator escaped body/helper fence')
                        ip=address-body;i=next(md.disasm(bytes(u.mem_read(address,15)),ip,count=1))
                        require(i.size==size,'Live instruction size disagrees with emulator decode')
                        live[(ip,i.mnemonic,i.op_str)]=True;instructions[0]+=1
                        if ip==0x162:
                            target=struct.unpack('<H',bytes(u.mem_read(ss*16+u.reg_read(UC_X86_REG_SP),2)))[0]
                            require(target in (0x6e,0x7b),'Unexpected reconstructednear return');returns.append(target)
                    def memory_write(u,access,address,size,value,_):
                        if ss*16+sp-0x100<=address and address+size<=ss*16+sp+4:return
                        require(all(address+byte in allowed_writes for byte in range(size)),'Unexpected mutator write')
                        writes.append({'module_offset':address-load*16 if address>=load*16 else None,'physical_address':address,'width':size,'value':value&((1<<(size*8))-1)})
                    def interrupt(u,number,_):
                        require(number==0x11 and bios_calls[0]<2,'Unexpected DOS/disk/other interrupt orquerycount')
                        response=equipment_index if bios_calls[0]==0 else second_equipment_index;bios_calls[0]+=1
                        u.reg_write(UC_X86_REG_AX,(response<<6)|0x0211)
                    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_MEM_WRITE,memory_write);uc.hook_add(UC_HOOK_INTR,interrupt)
                    uc.emu_start(body+0x2e,0x80100,count=4096)
                    require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4,'Far return/frame')
                    require(all(uc.reg_read(reg)==val for reg,val in preserved),'Restored caller registers/segments')
                    first_success=(drive&255)<=equipment_index
                    success=first_success and (drive&255)<=second_equipment_index
                    require(uc.reg_read(UC_X86_REG_AX)==(0 if success else drive),'Mutator return condition')
                    require(returns==([0x6e,0x7b] if success else [0x6e] if first_success else []),'Savednear-return path')
                    require(bios_calls[0]==(2 if first_success else 1),'Synthetic equipment call count')
                    require(struct.unpack('<HH',bytes(uc.mem_read(0x10,4)))==(sp-10,0x0201),'Low-memory stackbookmark writes')
                    require(uc.reg_read(UC_X86_REG_EFLAGS)&0x100==0,'TF cleared')
                    final_controls={f'06C9:{off-0x6c90:04X}':uc.mem_read(load*16+off,1)[0] for off in control_offsets}
                    expected={'06C9:1BF7':0xcb if success else 0xf8,'06C9:424A':0x75 if first_success else 0x76,'06C9:4275':0x75 if first_success else 0x76,'06C9:42AD':0x75 if first_success else 0x77}
                    require(final_controls==expected,'Game code/control patch state')
                    require(all(uc.mem_read(load*16+off,1)[0]==0x90 for off in own_offsets),'Ownopcodepatches')
                    require(uc.mem_read(group*16+0x5656,1)[0]==(0 if success else 0x63),'Principalgroup byte flag')
                    total_instructions+=instructions[0];outcomes['both_queries_admit' if success else 'second_query_reject' if first_success else 'first_query_reject']+=1
                    rows.append({'load_segment':load,'selected_drive_word':drive,'equipment_index':equipment_index,'second_equipment_index':second_equipment_index,'initial_carry':carry,
                                 'ax':uc.reg_read(UC_X86_REG_AX),'final_controls':final_controls,'saved_near_return_targets':returns,
                                 'bios_service_mocks':bios_calls[0],'instructions':instructions[0]})
    new=[{'entry':f'13A8:{ip:04X}','mnemonic':mnemonic,'operands':operands} for ip,mnemonic,operands in sorted(live) if ip not in initial_starts]
    require({r['entry'] for r in new}>={'13A8:00BC','13A8:0155','13A8:015E','13A8:0161','13A8:0162'},'Missing live-boundary observations')
    require(hashlib.sha256((ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()).hexdigest()==image_sha,'Admitted image changed')
    result={'schema':1,'result':'pass','image_sha256':image_sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'vectors':len(rows),'original_instructions_executed':total_instructions,'outcomes':dict(outcomes),'new_live_instruction_starts':new,
            'own_opcode_patches':[{'module_offset':off,'new_byte':0x90} for off in own_offsets],
            'game_control_states':{'low_drive_branch':{'1BF7':0xcb,'424A':0x75,'4275':0x75,'42AD':0x75},'high_drive_branch':{'1BF7':0xf8,'424A':0x76,'4275':0x76,'42AD':0x77},'mixed_query_branch':{'1BF7':0xf8,'424A':0x75,'4275':0x75,'42AD':0x75}},
            'cases':rows,'conclusion':'Main-called13A8:002E modifies itsown instructionboundaries and6C9 state/simulation controlbytes. Bothqueryadmission replaces1BF7 CLCbyRETF,bypassingstaticlowmemorywritetail. Firstqueryrejection retainsinitialJBE/JBE/JA plusCLC; secondqueryrejection retainsCLC withJNE/JNE/JNE fromfirstquery. Savednearreturn usesCS2C thenPUSH/RET0162; lowphysical10/12 holdSPbookmark/literal0201 andarenotrestored.',
            'limits':'Only isolatedloadedcopies withsyntheticINT11 responses, DF0 andsuccessfulfencedreturns. No actualBIOS/DOS/disk/session, entiremutablestategraph, supportededition/runtimeprofile, timersemantics, gameplay orfidelity acceptance. Initial-image staticdiscovery/tail tests remainhistoricalevidence, not latercaller-state acceptance.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
