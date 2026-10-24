"""Exercise only6D50 control/stack flow with mocked helper ABIs.

No DOS service, codec instructions, real resource or full game executes.
The result proves named ABI paths only, not packed-loader data semantics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_AX,UC_X86_REG_DX,UC_X86_REG_EFLAGS


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    graph=json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text())
    f=next(f for f in graph['functions'] if f['entry']=='06C9:6D50')
    rows=[]
    for load in [0x1000,0x2345]:
        for mode,selector in [('cache_hit',1),('cache_miss_codec1',1),('cache_miss_codec2',2),('cache_miss_two_pass',1)]:
            for fill in [0xa5,0x3c]:
                uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
                s,ip,end=0x6c9,0x6d50,0x6e4d;begin=s*16+ip
                code=bytearray(image[begin:s*16+end])
                for r in relocs:
                    if begin<=r<begin+len(code):
                        value=(struct.unpack_from('<H',code,r-begin)[0]+load)&65535
                        struct.pack_into('<H',code,r-begin,value)
                cs,ds,ss,sp=load+s,load+0x178f,0x7000,0x8000
                uc.mem_write(cs*16+ip,bytes(code))
                uc.mem_write(ss*16+sp-0x100,bytes([fill])*0x108)
                uc.mem_write(ss*16+sp,struct.pack('<HHH',0x100,0x8000,0x0120))
                uc.mem_write(ds*16+0x120,b'fixture\0')
                # Mock rawreader returns600F:0000 with a synthetic codec selector.
                synthetic=bytes([0x82,0,1,0,selector]) if mode=='cache_miss_two_pass' else bytes([selector,0,0,0])
                uc.mem_write(0x600f0,synthetic)
                for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,ip),(UC_X86_REG_DS,ds),(UC_X86_REG_ES,0x1234),
                                (UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x3333),
                                (UC_X86_REG_SI,0xbbbb),(UC_X86_REG_DI,0xaaaa),(UC_X86_REG_EFLAGS,0x202)]:uc.reg_write(reg,val)
                expected_helpers={cs*16+x:x for x in [0x71b4,0x5e8a,0x70a3,0x5e1c,0x6aa2,0x6b02,0x7c16,0x7030]}
                allowed={cs*16+x for x in f['instructions']}
                stopped=[None];executed=[];calls=[]
                def fetch(u,address,size,_):
                    if address in expected_helpers:
                        stopped[0]=expected_helpers[address];u.emu_stop();return
                    require(address in allowed,'Execution escaped6D50 ABI fence')
                    executed.append(address)
                def interrupt(*_):raise RuntimeError('Unexpected interrupt')
                uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
                for step in range(12):
                    stopped[0]=None
                    current=uc.reg_read(UC_X86_REG_CS)*16+uc.reg_read(UC_X86_REG_IP)
                    uc.emu_start(current,0x80100,count=256)
                    helper=stopped[0]
                    if helper is None:break
                    at=ss*16+uc.reg_read(UC_X86_REG_SP)
                    return_ip,return_cs=struct.unpack('<HH',bytes(uc.mem_read(at,4)))
                    if helper==0x71b4:ax,dx=(0,0x6000) if mode=='cache_hit' else (0,0)
                    elif helper==0x5e8a:ax,dx=0x10,0
                    elif helper==0x70a3:ax,dx=0,0x6000
                    elif helper==0x5e1c:ax,dx=2,0
                    elif helper==0x6aa2:ax,dx=0,0x600f
                    elif helper==0x7030:
                        # Stand-in for the paragraph move: install a valid
                        # synthetic second-pass selector at its derived source.
                        uc.mem_write(0x60010,bytes([selector,0,0,0]));ax,dx=0,0
                    else:ax,dx=0x100,0
                    calls.append({'entry':f'06C9:{helper:04X}','sp_at_call':uc.reg_read(UC_X86_REG_SP),'ax_result':ax,'dx_result':dx})
                    # Mock callee uses a normal RETF, with caller-owned arguments.
                    uc.reg_write(UC_X86_REG_AX,ax);uc.reg_write(UC_X86_REG_DX,dx)
                    uc.reg_write(UC_X86_REG_SP,uc.reg_read(UC_X86_REG_SP)+4)
                    uc.reg_write(UC_X86_REG_CS,return_cs);uc.reg_write(UC_X86_REG_IP,return_ip)
                else:raise RuntimeError('ABI fixture exceeded helper bound')
                require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100,'Far return target')
                require(uc.reg_read(UC_X86_REG_SP)==sp+4 and uc.reg_read(UC_X86_REG_BP)==0x3333,'Frame restoration')
                require(uc.reg_read(UC_X86_REG_DS)==ds,'DS restoration')
                si,di=uc.reg_read(UC_X86_REG_SI),uc.reg_read(UC_X86_REG_DI)
                expected=(0xbbbb,0xaaaa) if mode=='cache_hit' else (0x6001,0xbbbb) if mode=='cache_miss_two_pass' else (fill*257,0xbbbb)
                require((si,di)==expected,'Unexpected SI/DI cleanup result')
                rows.append({'load_segment':load,'path':mode,'stack_fill_byte':fill,'si':si,'di':di,
                             'sp_after_return':sp+4,'helper_mocks':calls,'body_instructions':len(executed)})
    result={'schema':1,'result':'pass','image_sha256':hashlib.sha256(image).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'vectors':len(rows),'cases':rows,
            'conclusion':'Cachehit restoresSI/DI. Uncached ADDSP8 afterthreeword6AA2 arguments shifts pops:DIgets incomingSI;SIgets BP-0A local (untouchedstackword inonepass, derivedsource segment intwo-pass fixture). BP/SP/farreturn remain restored.',
            'scope':'6D50 body control/stack execution only; all listedcallees mocked withnormalRETF, preservedSI/DI and namedAX/DX results. No DOS, codec/data semantics or real resource validated.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
