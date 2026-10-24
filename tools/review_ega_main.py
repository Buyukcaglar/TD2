"""Persist reviewed main-state regions and verify their exact branch/write sites."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16,CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh evidence required')
    flow=json.loads(a.flow.read_text());image=(ROOT/flow['image']).read_bytes()
    require(hashlib.sha256(image).hexdigest()==flow['image_sha256'],'Image mismatch')
    f=next(f for f in flow['functions'] if f['entry']=='0000:07B3');md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True
    decoded={ip:next(md.disasm(image[ip:ip+15],ip,count=1)) for ip in f['instructions']}
    require(len(decoded)==360 and len(f['calls'])==56,'Expanded main body must be reviewed')
    def op(ip,mnemonic,operands=None):
        i=decoded[ip];require(i.mnemonic==mnemonic and (operands is None or i.op_str==operands),f'Instruction mismatch{ip:04X}');return i
    checks=[(0x7c8,'lcall'),(0x7cd,'lcall'),(0x7df,'lcall'),(0x811,'lcall'),(0x81a,'lcall'),(0x82a,'lcall'),
            (0x83b,'lcall'),(0x84e,'lcall'),(0x88d,'lcall'),(0x8f8,'cmp','ax, 1'),(0x92e,'jg','0x942'),
            (0x940,'jne','0x985'),(0x954,'jne','0x959'),(0x96e,'jne','0x98a'),(0x980,'je','0x959'),
            (0x9d5,'cmp','ax, 1'),(0x9d8,'jmp','0x9fb'),(0x9fb,'dec','ax'),(0xa39,'je','0xa3e'),
            (0xa5f,'jne','0xa7a'),(0xa68,'jne','0xa6d'),(0xa8f,'je','0xa61'),(0xaa6,'je','0xaab'),
            (0xac1,'cmp','ax, 0x1b'),(0xb2d,'cmp','ax, 0x1b'),(0xb30,'je','0xb35'),
            (0xb56,'jne','0xb5f'),(0xb5d,'je','0xb6f'),(0xb74,'je','0xb9a'),(0xb7b,'je','0xb9a'),
            (0xba7,'jne','0xbe4'),(0xbb3,'jbe','0xbbb'),(0xbc2,'jne','0xbc7'),
            (0xbcd,'je','0xbd8'),(0xbd3,'je','0xbd8'),(0xbe4,'lcall'),(0xbe9,'lcall'),(0xbf2,'je','0xbfb'),(0xc03,'retf')]
    for check in checks:op(*check)
    regions=[
      ('07B3','07D5','startup_pool_sample','Initializes locals, pool6F86 andsamples externalword5D83; no tick/time unit admitted.'),
      ('07D5','0837','device_and_handlers','Nearargv[1] compared with externalherc string; alternatevideo/device path; inputcallback/vector09/16/timer08 installs andmusic callback registration.'),
      ('0837','089C','persistent_media','Rawvoices/songs farpairs storedin942A/C and8640/2, suppliedtoaudio consumers; B0FE allocates320x200 fourplane-shaped surface into8CA2/4.'),
      ('089C','0928','current_drive_media','Currentdrive query writeslocal, diskid recognizer05C0 onlyadmitsIDs0/4 first; recordsdrive/media tables, requires0477 result1; initializesdrive enumeration.'),
      ('0928','0959','drive_search_sample','Signeddrive loop through922C, stoponmediaID3; externaldifference5D8D storedunscaled inlocalword. ID3 jumpsdirectly toA07.'),
      ('0959','098A','master_play_prompt','Tryopening externaltestdrv2.pes withr mode. Failure callsnear0090 prompt; zero retries, nonzero cleanup. No resourcedecode inthis path.'),
      ('098A','0A07','retry_drive_media','Closesprobe stream, obtainscurrentdrive, recognizesdiskid, updatesmedia/drive tables, calls0477. At09D5 CMPAX1 isfollowedby unconditionalJMP09FB; returnAXminus1 stored5657.'),
      ('0A07','0A3E','media_selection_begin','Resamplesexternalword, storesmediaID8A8C, updatesdrive/media tables andcalls0432:02BF; nonzero returns tocleanup.'),
      ('0A3E','0A91','catalog_selection','Clears8A7A and90AA, calls0432:00A9. Zero8A7A comparesactive/admittedmedia, possibly1D25 thenretriesvia0950. Nonzero calls01B2;90AAzero returns tomedia comparison.'),
      ('0A91','0AB9','selection_bind','Copies8A7A to843C; near0651/0730 bindselection,0645:0000 gatescleanup; addsunscaled externaldifference modulo65536 tolocalaccumulator.'),
      ('0AB9','0B37','menu_exit_prompt','00C0:039C returnsword;1B opensdrawnexitconfirmation usingexternaltext71D3. 6A6A getsinput withlongargument3000; repeated1B rewaits;79/59 confirmswrite/exit,other returns tomenu.'),
      ('0B37','0BAE','session_setup','Zeroresult sets8A9A1, otherwise7C; firstiteration conditionallyvalidatesselectedmedia/scenery, loads1D44, setsfirstiterationlocal.'),
      ('0BAE','0BE4','session_or_menu','Unsignedlocalaccumulator>500 sets7C1; calls019E:06C5. Zero returns tomenuAB9, nonzerocleanup; no complete session contract admitted.'),
      ('0BE4','0C04','cleanup_return','Restorestimer610A thenkeyboard68C4, alternate5FBC or642E cleanup; returnsAXleftbyfinalhelper, notanexplicitconstant0.')]
    branches=[];writes=[]
    for ip,i in decoded.items():
        if i.group(CS_GRP_JUMP):branches.append({'site':f'0000:{ip:04X}','condition':i.mnemonic,'target':i.op_str})
        for operand in i.operands:
            if operand.type==X86_OP_MEM and operand.access&2:
                base=i.reg_name(operand.mem.base);segment=i.reg_name(operand.mem.segment) or ('ss' if base=='bp' else 'ds')
                writes.append({'site':f'0000:{ip:04X}','segment_default_or_override':segment,'base':base,
                               'displacement_word':operand.mem.disp&65535,'width':operand.size})
    require(not any(0x9da<=ip<0x9fb for ip in decoded),'Skipped09DA..09FA unexpectedly reachable')
    cs_writes=json.loads((a.flow.parent/'memory-operands.json').read_text())
    cs_writes=[r for r in cs_writes if r['segment']=='cs' and r['access']&2]
    anomaly_offsets=[(0x1bf7,0x1c02),(0x5d83,0x5d9e)]
    direct_aliases=[r for r in cs_writes if r['site'].startswith('06C9:') and not r['base'] and not r['index'] and any(start<=((r['displacement']&65535)+byte)<end for start,end in anomaly_offsets for byte in range(r['width']))]
    report={'schema':1,'result':'pass','image_sha256':flow['image_sha256'],'ledger_sha256':hashlib.sha256(a.flow.read_bytes()).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'function_entry':'0000:07B3','instruction_locations':len(decoded),'call_sites':len(f['calls']),
            'reviewed_instruction_checks':len(checks),'regions':[{'begin':a,'end_exclusive':b,'name':name,'contract_observation':note} for a,b,name,note in regions],
            'branches':sorted(branches,key=lambda r:r['site']),'explicit_memory_writes':sorted(writes,key=lambda r:r['site']),
            'special_cases':['09D5 CMP flags discardedby09D8 unconditionalJMP;09FB decrementshelper AX ratherthanreloadingdrive.','Localexternalwordaccumulation wraps16bit;literal500 and3000 areobservedvalues withoutclockunit assignment.','Cleanupreturns finalhelperAX, withnoexplicitmainreturncode.','Nearargv[1] unconditionallyread; nearoffset0 remainsmachineaddress, nothostNULL.'],
            'cs_write_review':{'syntactic_prefixed_writes':len(cs_writes),'direct_literal_aliases_at_anomaly_code':direct_aliases,
              'limit':'No direct CS literal alias found doesnotprove immutableanomalybytes. IndexedCS writers, DS/ESaliases andunclassified/indirect paths remainopen.'},
            'limits':'Static mainregions/branch/write review only. Callee contracts, variable/array domains, fullstartup-to-exit state validation, allownership lifetimes andruntime/fidelity remainpending.'}
    out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['regions','branches','explicit_memory_writes']},indent=2))


if __name__=='__main__':main()
