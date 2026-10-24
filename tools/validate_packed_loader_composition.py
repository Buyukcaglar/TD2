"""Exercise6D50 with actual cache/allocation/copy/codec code and synthetic data.

Only file-size/header helpers and DOS open/read/close services are synthetic.
No supplied resource is decoded; this tests caller/callee return composition,
separate from the earlier all-callee-mocked stack fixtures and real I/O gates.
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
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_IP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_BP,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_EFLAGS


def require(test,message):
    if not test:raise RuntimeError(message)


def make_inner(length,run):
    expected=(b'A'*length) if run else (b'AB'*(length//2)+b'A'*(length%2))
    encoded=bytes([0xff,length,0x41]) if run else expected
    # This bounded synthetic branch has count1/highbit set, so6B02 skips its
    # first block-expansion stage and executes the one-token run/literal stage.
    return bytes([1])+length.to_bytes(3,'little')+len(encoded).to_bytes(4,'little')+b'\x81\xff'+encoded,expected


def make_two_pass(inner,length):
    symbols=sorted(set(inner))
    for byte in range(256):
        if len(symbols)==8:break
        if byte not in symbols:symbols.append(byte)
    require(len(symbols)==8,'Synthetic fixed3bit alphabet too large')
    bits=[]
    for byte in inner:
        code=symbols.index(byte);bits.extend([(code>>2)&1,(code>>1)&1,code&1])
    packed=bytearray((len(bits)+7)//8)
    for index,bit in enumerate(bits):packed[index//8]|=bit<<(index%8)
    # Three code lengths with counts0,0,8; LSB-first physical bits supply the
    # canonical code bits inmost-significant-code-bit order. No realmedia.
    return b'\x82'+length.to_bytes(3,'little')+b'\x02'+len(inner).to_bytes(3,'little')+b'\x03\x00\x00\x08'+bytes(symbols)+bytes(packed)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh output required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    require(hashlib.sha256(image).hexdigest()=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest()=='71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2','Unadmitted MZ')
    n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    flow_path=ROOT/'analysis/flow/indirect-v7/direct-flow.json';graph=json.loads(flow_path.read_text())
    entries={'06C9:'+f'{ip:04X}' for ip in [0x6d50,0x71b4,0x7083,0x70a3,0x6aa2,0x6b02,0x6b97,0x6c6e,0x7c16,0x7030,0x6fe8,0x7147]}
    functions={f['entry']:f for f in graph['functions'] if f['entry'] in entries}
    require(set(functions)==entries,'Missing composed helper entry')
    rows=[];total_instructions=0
    for load in [0x1000,0x3871]:
        for mode in ['one_pass','two_pass']:
            for length,run in [(1,False),(16,False),(1,True),(17,True),(127,True),(255,True)]:
                for fill in [0xa5,0x3c]:
                    inner,expected=make_inner(length,run);raw=inner if mode=='one_pass' else make_two_pass(inner,length)
                    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x100000)
                    relocated=bytearray(image)
                    for r in relocs:struct.pack_into('<H',relocated,r,(struct.unpack_from('<H',relocated,r)[0]+load)&65535)
                    uc.mem_write(load*16,bytes(relocated));cs=load+0x6c9;group=load+0x178f;sp=0xe000;pool=0x6000;pool_bytes=0x2000
                    guard=b'\xa5'*8;uc.mem_write(pool*16-8,guard+b'\xcc'*pool_bytes+guard)
                    arena=bytearray(900);struct.pack_into('<HHH',arena,12,0,pool,2);struct.pack_into('<HHH',arena,49*18+12,0,pool+pool_bytes//16,1)
                    uc.mem_write(group*16+0x68e2,bytes(arena));uc.mem_write(group*16+0x6c66,struct.pack('<HHHH',0x68e2,0x68e2,0x6c54,0x6c54))
                    uc.mem_write(group*16+0x120,b'fixture\0abcdefghijklmnop')
                    uc.mem_write(group*16+sp-0x800,bytes([fill])*0x808);uc.mem_write(group*16+sp,struct.pack('<HHH',0x100,0x8000,0x120))
                    for reg,val in [(UC_X86_REG_CS,cs),(UC_X86_REG_IP,0x6d50),(UC_X86_REG_DS,group),(UC_X86_REG_SS,group),
                                    (UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x3333),(UC_X86_REG_SI,0x2222),(UC_X86_REG_DI,0x4444),(UC_X86_REG_EFLAGS,0x202)]:uc.reg_write(reg,val)
                    allowed={((load+int(f['entry'].split(':')[0],16))*16+ip) for f in functions.values() for ip in f['instructions']}
                    stopped=[None];instructions=[0];dos=[];returns=[];file_cursor=[0];metadata_mocks=[]
                    def fetch(u,address,size,_):
                        if address in (cs*16+0x5e8a,cs*16+0x5e1c):stopped[0]=address-cs*16;u.emu_stop();return
                        require(address in allowed,'Composition escaped named helper fence')
                        instructions[0]+=1
                        if address in (cs*16+0x6b96,cs*16+0x7cd8,cs*16+0x7d3c):returns.append({'entry':'06C9:6B02' if address==cs*16+0x6b96 else '06C9:7C16','ax':u.reg_read(UC_X86_REG_AX),'dx':u.reg_read(UC_X86_REG_DX)})
                    def interrupt(u,number,_):
                        require(number==0x21,'Unexpected nonDOS interrupt')
                        ah=u.reg_read(UC_X86_REG_AX)>>8;dos.append(ah)
                        if ah==0x3d:
                            require(u.reg_read(UC_X86_REG_DS)==group and u.reg_read(UC_X86_REG_DX)==0x120,'Open filename context')
                            u.reg_write(UC_X86_REG_AX,3)
                        elif ah==0x3f:
                            require(u.reg_read(UC_X86_REG_BX)==3,'Read handle')
                            count=min(u.reg_read(UC_X86_REG_CX),len(raw)-file_cursor[0]);at=u.reg_read(UC_X86_REG_DS)*16+u.reg_read(UC_X86_REG_DX)
                            require(pool*16<=at and at+count<=pool*16+pool_bytes,'Read target outside synthetic pool')
                            u.mem_write(at,raw[file_cursor[0]:file_cursor[0]+count]);file_cursor[0]+=count;u.reg_write(UC_X86_REG_AX,count)
                        elif ah==0x3e:
                            require(u.reg_read(UC_X86_REG_BX)==3,'Close handle');u.reg_write(UC_X86_REG_AX,0)
                        else:raise RuntimeError(f'Unmocked DOS service{ah:02x}')
                        u.reg_write(UC_X86_REG_EFLAGS,u.reg_read(UC_X86_REG_EFLAGS)&~1)
                    uc.hook_add(UC_HOOK_CODE,fetch);uc.hook_add(UC_HOOK_INTR,interrupt)
                    for step in range(4):
                        stopped[0]=None;current=uc.reg_read(UC_X86_REG_CS)*16+uc.reg_read(UC_X86_REG_IP)
                        uc.emu_start(current,0x80100,count=1000000)
                        helper=stopped[0]
                        if helper is None:break
                        value=(length+15)//16 if helper==0x5e8a else (len(raw)+15)//16
                        metadata_mocks.append({'entry':f'06C9:{helper:04X}','ax':value})
                        at=group*16+uc.reg_read(UC_X86_REG_SP);rip,rcs=struct.unpack('<HH',bytes(uc.mem_read(at,4)))
                        uc.reg_write(UC_X86_REG_AX,value);uc.reg_write(UC_X86_REG_SP,uc.reg_read(UC_X86_REG_SP)+4);uc.reg_write(UC_X86_REG_IP,rip);uc.reg_write(UC_X86_REG_CS,rcs)
                    else:raise RuntimeError('Metadata mock bound')
                    require(uc.reg_read(UC_X86_REG_CS)==0x8000 and uc.reg_read(UC_X86_REG_IP)==0x100 and uc.reg_read(UC_X86_REG_SP)==sp+4 and uc.reg_read(UC_X86_REG_BP)==0x3333,'Outer far return/frame')
                    require(uc.reg_read(UC_X86_REG_DS)==group and uc.reg_read(UC_X86_REG_AX)==0 and uc.reg_read(UC_X86_REG_DX)==pool,'Final farpointer return')
                    require(bytes(uc.mem_read(pool*16,length))==expected,'Synthetic payload mismatch')
                    require(bytes(uc.mem_read(pool*16-8,8))==guard and bytes(uc.mem_read(pool*16+pool_bytes,8))==guard,'Pool guards')
                    require(dos==[0x3d,0x3f,0x3e] and file_cursor[0]==len(raw),'Synthetic file service sequence')
                    expected_returns=([{'entry':'06C9:7C16','ax':len(inner),'dx':0}] if mode=='two_pass' else [])+[{'entry':'06C9:6B02','ax':0,'dx':pool}]
                    require(returns==expected_returns,'Codec length/farpointer ABI composition')
                    allocation_paragraphs=(length+15)//16+1;expected_si=pool+allocation_paragraphs-(len(inner)+15)//16 if mode=='two_pass' else fill*257
                    require(uc.reg_read(UC_X86_REG_SI)==expected_si and uc.reg_read(UC_X86_REG_DI)==0x2222,'Original uncached popshift')
                    require(struct.unpack('<HH',bytes(uc.mem_read(group*16+0x6c68,4)))==(0x68f4,0x6c54),'Active/cache boundary')
                    total_instructions+=instructions[0]
                    rows.append({'load_segment':load,'mode':mode,'synthetic_output_bytes':length,'run_fixture':run,'stack_fill_byte':fill,
                                 'synthetic_input_bytes':len(raw),'payload_sha256':hashlib.sha256(expected).hexdigest(),
                                 'metadata_helper_mocks':metadata_mocks,'dos_service_mocks':dos,'actual_codec_returns':returns,
                                 'final_ax':0,'final_dx':pool,'final_si':expected_si,'final_di':0x2222,'instructions':instructions[0]})
    result={'schema':1,'result':'pass','image_sha256':hashlib.sha256(image).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'ledger_sha256':hashlib.sha256(flow_path.read_bytes()).hexdigest(),'vectors':len(rows),'original_instructions_executed':total_instructions,
            'actual_helper_entries':sorted(entries),'cases':rows,
            'conclusion':'Synthetic onepass6B02 returns AX0/DXdestination. Twopass7C16->6B02 composes intermediateDX:AX bytecount, roundedparagraphmove, finalAX0/DXdestination. Uncached SI/DI popshift remains withactualcallees. DS=SS required for6B02 initialheadercopy intoSSlocals.',
            'limits':'Only bounded synthetic literal/run andfixed3bit canonical-code fixtures, successful metadata/DOS service mocks. No supplied resource decoding, corpus/format acceptance, malformed/error/wrap coverage, real DOS session, fullcaller ownership, renderer/audio, gameplay orfidelity.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))


if __name__=='__main__':main()
