"""Project observed code states into separate static ledgers, never original bytes.

These shadows are conservative snapshots, not a transition-aware whole-program
analysis. The fenced mutator trace supplies observed writes/near-return context.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from map_ega_flow import discover,address


def require(test,message):
    if not test:raise RuntimeError(message)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--revision',required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();private=ROOT/'analysis/flow'/a.revision
    require(a.revision.replace('-','').isalnum() and not private.exists(),'Fresh private revision required')
    require(not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence'),'Fresh evidence required')
    image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest()
    require(sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4','Unadmitted image')
    trace_path=ROOT/'docs/recovery/evidence/td2ega-main-mutator-validation-v2.json';trace=json.loads(trace_path.read_text())
    require(trace['result']=='pass' and trace['vectors']==1920 and trace['image_sha256']==sha,'Mutator trace missing')
    require(trace['script_sha256']==hashlib.sha256((ROOT/'tools/validate_main_mutator.py').read_bytes()).hexdigest(),'Mutator recipe drift')
    review_path=ROOT/'docs/recovery/evidence/td2ega-indirect-review-v8.json';review=json.loads(review_path.read_text())
    roots=[(0x13a8,0x3f8)]+[tuple(int(v,16) for v in r['entry'].split(':')) for r in review['additional_roots']]
    variants={'initial_image':{},'prepared_high_drive':{},'prepared_low_drive':{},'prepared_mixed_query':{}}
    for name,outcome in [('prepared_high_drive','high_drive_branch'),('prepared_low_drive','low_drive_branch'),('prepared_mixed_query','mixed_query_branch')]:
        variants[name].update({p['module_offset']:p['new_byte'] for p in trace['own_opcode_patches']})
        variants[name].update({0x6c90+int(ip,16):value for ip,value in trace['game_control_states'][outcome].items()})
    mz=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.unpacked.exe').read_bytes();n,t=struct.unpack_from('<H',mz,6)[0],struct.unpack_from('<H',mz,24)[0]
    reloc={struct.unpack_from('<H',mz,t+4*i)[0]+16*struct.unpack_from('<H',mz,t+4*i+2)[0] for i in range(n)}
    private.mkdir(parents=True);states=[];union_entries=set();known=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    known_entries={f"{r['entries'][0]['segment']:04X}:{r['entries'][0]['segment_offset']:04X}" for r in known}
    for name,patches in variants.items():
        data=bytearray(image)
        for at,value in patches.items():
            require(at not in reloc and at-1 not in reloc,'Observed byte patch overlaps relocation')
            data[at]=value
        functions,decoded=discover(bytes(data),roots,review['sites']);entries={address(entry) for entry in functions};union_entries.update(entries)
        require(entries<=known_entries,'New mutable-state function entries need IDs: '+str(entries-known_entries))
        require(not any(f['issues'] for f in functions.values()),'Shadow traversal issues')
        byte_owners={};listing=[]
        for pair,i in sorted(decoded.items()):
            at=pair[0]*16+pair[1];listing.append(f'{address(pair)} [{at:05X}] {i.bytes.hex():<30} {i.mnemonic} {i.op_str}')
            for byte in range(at,at+i.size):byte_owners.setdefault(byte,set()).add(at)
        overlaps=[at for at,owners in byte_owners.items() if len(owners)>1]
        require(not overlaps,'Conflicting boundaries within one shadow')
        dest=private/name;dest.mkdir();image_path=dest/'code-state.bin';image_path.write_bytes(data)
        ledger={'schema':1,'image':image_path.relative_to(ROOT).as_posix(),'image_sha256':hashlib.sha256(data).hexdigest(),
                'original_image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'discovery_script_sha256':hashlib.sha256((ROOT/'tools/map_ega_flow.py').read_bytes()).hexdigest(),
                'source_trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),'state':name,
                'roots':[address(r) for r in roots],'function_candidates':len(functions),'instruction_count':len(decoded),
                'instruction_bytes':len(byte_owners),'overlap_byte_count':0,'functions':sorted(functions.values(),key=lambda f:f['entry']),
                'limits':['Snapshot only, no propagation of subsequent code mutations or timing/interleavings.','Call fallthrough and unresolved indirect obligations remain conservative.']}
        ledger_path=dest/'direct-flow.json';ledger_path.write_text(json.dumps(ledger,indent=2)+'\n');(dest/'instructions.txt').write_text('\n'.join(listing)+'\n')
        starts={address(pair) for pair in decoded}
        if name!='initial_image':require({'13A8:00BC','13A8:0155','13A8:015E','13A8:0161','13A8:0162'}<=starts,'Prepared state missing live starts')
        states.append({'name':name,'image_sha256':ledger['image_sha256'],'ledger':ledger_path.relative_to(ROOT).as_posix(),
                       'ledger_sha256':hashlib.sha256(ledger_path.read_bytes()).hexdigest(),'function_candidates':len(functions),
                       'instruction_locations':len(decoded),'syntactic_code_bytes':len(byte_owners),'overlap_byte_count':0,
                       'patches':[{'module_offset':at,'old_byte':image[at],'new_byte':value} for at,value in sorted(patches.items())]})
    result={'schema':1,'result':'pass','original_image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'source_trace':trace_path.relative_to(ROOT).as_posix(),'source_trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),
            'reviewed_explicit_indirect_mechanisms':44,'additional_saved_near_return_mechanisms':1,
            'saved_near_return':{'site':'13A8:0162','targets':['13A8:006E','13A8:007B'],'preconditions':'Onlythetwo002E callsinto007E, CS2Csavedword and1920fencedmutator cases. RETtargets alreadyrepresentedbyconservativecallerfallthrough; notfollowedashelper-bodytail.'},
            'registered_union_entries':len(union_entries),'states':states,
            'limits':'Four conservative code-state snapshots andone reconstructednear-return mechanism, notcomplete mutablegraph/transition/interrupt/caller-domain orportableEGA/CGA/runtime/fidelity acceptance. Initial-image no-conflict metrics cannotbeappliedtoallcode states.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
