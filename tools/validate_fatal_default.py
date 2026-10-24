"""Fence fatal wrapper through default runtime abort to termination request.

Video/input/timer cleanup, formatter and diagnostic emitter are ABI mocks.
Actual abort/signal lookup/default dispatch/exit instructions execute; synthetic
DOS services record requests. Termination is fenced, not a process launch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'analysis/tools/python'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


def require(test, message):
    if not test:
        raise RuntimeError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    output = ap.parse_args().output.resolve()
    require(not output.exists() and output.is_relative_to(ROOT/'docs/recovery/evidence'), 'Fresh evidence required')
    image = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes()
    sha = hashlib.sha256(image).hexdigest()
    require(sha == '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4', 'Unadmitted image')
    mz = (ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes()
    require(hashlib.sha256(mz).hexdigest() == '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2', 'Unadmitted MZ')
    n,t = struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    relocs = [struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)]
    graph = json.loads((ROOT/'analysis/flow/indirect-v7/direct-flow.json').read_text())
    entries = ['16A7:0002','13A8:29F6','13A8:2C1C','13A8:2D57','13A8:0599','13A8:05E0','13A8:060D','13A8:066E','13A8:0620']
    starts = {int(f['entry'][:4],16)*16+ip for f in graph['functions'] if f['entry'] in entries for ip in f['instructions']}
    rows = []
    for load in [0x1000,0x2345]:
        data = bytearray(image)
        for r in relocs:
            struct.pack_into('<H',data,r,(struct.unpack_from('<H',data,r)[0]+load)&65535)
        uc = Uc(UC_ARCH_X86,UC_MODE_16)
        uc.mem_map(0,0x100000)
        uc.mem_write(load*16,bytes(data))
        ds,ss,sp = load+0x178f,load+0x178f,0xe000
        active = {}
        mocks = {load*16+0x6c90+0x642e:'video_cleanup',load*16+0x6c90+0x68c4:'input_cleanup',
                 load*16+0x6c90+0x610a:'timer_cleanup',load*16+0x13a80+0xb00:'format',
                 load*16+0x13a80+0x8b7:'diagnostic'}

        def code(u,address,size,_):
            if address in mocks:
                name = mocks[address]
                top = ss*16+u.reg_read(UC_X86_REG_SP)
                if name == 'format':
                    require(list(struct.unpack('<5H',bytes(u.mem_read(top+4,10)))) == active['packet'], 'Five-word formatter forwarding')
                if name == 'diagnostic':
                    active['diagnostics'].append(struct.unpack('<H',bytes(u.mem_read(top+4,2)))[0])
                active['calls'].append(name)
                ip,cs = struct.unpack('<HH',bytes(u.mem_read(top,4)))
                u.reg_write(UC_X86_REG_SP,u.reg_read(UC_X86_REG_SP)+4+(2 if name == 'diagnostic' else 0))
                u.reg_write(UC_X86_REG_CS,cs)
                u.reg_write(UC_X86_REG_IP,ip)
                return
            require(address-load*16 in starts,'Fatal/runtime escaped instruction fence')
            active['instructions'] += 1

        def write(u,access,address,size,value,_):
            require(ss*16+sp-0x100<=address and address+size<=ss*16+sp+14,'Unexpected runtime memory write')

        def interrupt(u,number,_):
            require(number == 0x21,'Unexpected interrupt')
            ax = u.reg_read(UC_X86_REG_AX)
            ah = ax>>8
            if ah == 0x3e:
                active['closed'].append(u.reg_read(UC_X86_REG_BX))
                u.reg_write(UC_X86_REG_AX,0)
                return
            if ah == 0x25:
                active['vectors'].append([ax&255,u.reg_read(UC_X86_REG_DS),u.reg_read(UC_X86_REG_DX)])
                return
            require(ah == 0x4c,'Unexpected DOS operation')
            active['exit'] = ax&255
            u.emu_stop()

        uc.hook_add(UC_HOOK_CODE,code)
        uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.hook_add(UC_HOOK_INTR,interrupt)
        for checksum_ok in [False,True]:
            for extra_vector in [0,1]:
                for handle_mask in [0,1,0x5555,0x7fff]:
                    for packet in [[0x64e0,0x1234,0x5678,0x9abc,0xdef0],[0,0xffff,0,1,2]]:
                        uc.mem_write(ds*16,bytes([0x55 if checksum_ok else 0])+b'\0'*65)
                        uc.mem_write(ds*16+0x7058,b'\0'*44)
                        uc.mem_write(ds*16+0x6dcc,b'\0'*4)
                        uc.mem_write(ds*16+0x6da4+5,bytes((1 if handle_mask&(1<<i) else 0) for i in range(15)))
                        uc.mem_write(ds*16+0x6d89,struct.pack('<HH',0x1111,0x2222))
                        uc.mem_write(ds*16+0x6dc6,struct.pack('<BBHH',extra_vector,0x24,0x3333,0x4444))
                        uc.mem_write(ss*16+sp-0x100,b'\xa5'*0x10e)
                        uc.mem_write(ss*16+sp,struct.pack('<7H',0x100,0x8000,*packet))
                        for reg,value in [(UC_X86_REG_CS,load+0x16a7),(UC_X86_REG_IP,2),(UC_X86_REG_DS,ds),
                            (UC_X86_REG_SS,ss),(UC_X86_REG_SP,sp),(UC_X86_REG_BP,0x5555),(UC_X86_REG_EFLAGS,0x202)]:
                            uc.reg_write(reg,value)
                        active.update(packet=packet,calls=[],diagnostics=[],closed=[],vectors=[],exit=None,instructions=0)
                        uc.emu_start((load+0x16a7)*16+2,0x80100,count=4096)
                        require(active['exit'] == 3 and uc.reg_read(UC_X86_REG_CS) == load+0x13a8 and uc.reg_read(UC_X86_REG_IP) == 0x5e0,'Termination request fence')
                        require(active['calls'][:4] == ['video_cleanup','input_cleanup','timer_cleanup','format'],'Fatal cleanup/format order')
                        require(active['diagnostics'] == ([10] if checksum_ok else [10,0xfc,0xff,1]),'Diagnostic codes, not character output')
                        require(active['closed'] == [i+5 for i in range(15) if handle_mask&(1<<i)],'Runtime flagged-handle close set')
                        require(active['vectors'] == [[0,0x2222,0x1111]]+([[0x24,0x4444,0x3333]] if extra_vector else []),'Vector restore requests')
                        rows.append({'load_segment':load,'checksum_ok':checksum_ok,'extra_vector':extra_vector,
                                     'handle_mask':handle_mask,'packet':packet,'diagnostic_codes':active['diagnostics'],
                                     'closed_handles':active['closed'],'vectors':active['vectors'],'exit_code':active['exit'],
                                     'instructions':active['instructions']})
    result = {'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'vectors':len(rows),'original_instructions_executed':sum(r['instructions'] for r in rows),'cases':rows,
              'conclusion':'Fatal16A7:0002 callsgraphics/input/timercleanup inthatorder andforwardsfivewords toformatter. Defaultsignal22 dispatchesruntimeexitcode3; exitclosesonlyflaggedruntimehandles5..19 andrequestsDOS4C03.08B7 iscallee-cleanRETF2 diagnosticcodeinterface, not acharacteremitter. No return tothe rawloader isobservedbeforeterminationrequest.',
              'limits':'Cleanup/formatter/diagnostic calls areABImocks; onlydefaultnullsignal/hook profile andsyntheticDOSresponses. Actualformattedbytes, drivercleanup, process/handle termination, installedhandlers/hooks andsupportedruntimeprofile remainopen. NoDOSprocess/game/session orfidelity acceptance.'}
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'cases'},indent=2))


if __name__ == '__main__':
    main()
