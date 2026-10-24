"""Review partial child FLAGS preservation and arithmetic liveness in61BF/6230."""
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert out.is_relative_to(ROOT/'docs/recovery/evidence') and not out.exists()
    old=(ROOT/'src/recovered/td2ega_timer_handler_bus.c').read_text();new=(ROOT/'src/recovered/td2ega_timer_handler_bus_flags.c').read_text()
    expected=old.replace('#include "td2ega_timer_handler_bus.h"','#include "td2ega_timer_handler_bus_flags.h"').replace('void td2ega_timer_handler_bus(', 'void td2ega_timer_handler_bus_flags(').replace('(mask==0xffff || mask==0xffef)','(mask==0xffff || mask==0xffef || mask==0xf72b)');assert new==expected
    prior=json.loads((ROOT/'docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json').read_text());assert prior['result']=='pass' and prior['instruction_sites_in_fence']==71
    mask=(0xffff^0x08d5)|1;assert mask==0xf72b and mask&0x601==0x601 and mask&0x08d4==0 and mask|0x08d5==0xffff and ((mask|0x08d5)&0xffef)==0xffef
    deps=['src/recovered/td2ega_timer_handler_bus.c','src/recovered/td2ega_timer_handler_bus.h','src/recovered/td2ega_timer_handler_bus_flags.c','src/recovered/td2ega_timer_handler_bus_flags.h','src/recovered/td2ega_input_flags.h','analysis/history/timer-handler-bus-flags-preparation-v1.json','analysis/history/timer-handler-bus-flags-build-setup-v1.json','docs/recovery/evidence/td2ega-timer-handler-bus-context-v1.json','docs/recovery/evidence/td2ega-state-tick-bus-context-v2.json','docs/recovery/evidence/td2ega-timer-callback-order-v2.json']
    record={'schema':1,'result':'pass','image_sha256':prior['image_sha256'],'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_sites_in_fence':71,'partial_mask':mask,'same_body_as_reviewed_handler':True,'facts':[
        'New entry has the same71-site source/body/SS/near-far-INT-IRET contract as the frozen handler. Only incoming/retired-service mask validation broadens toF72B; old interface/source/DLL remain unchanged.',
        'F72B retains arithmeticCF andIF/DF plus the explicitly admitted system/reserved-bit profile; PF/AF/ZF/SF/OF may be unexposed. Flagword0ED7/bit1 and StateCFIFDF consistency are still required.',
        'A child prefix retains its actual retired/current coordinates/state/RAM and partial flag mask without following raw control or manufacturing missing arithmetic bits.',
        'On normal far-callback continuation actual621BADDDI4 defines all arithmetic bits before the next ORAXAX. MaskF72B OR08D5 becomesFFFF; subsequent logic masks only AF toFFEF. Unknown child arithmetic bits cannot influence these source operations.',
        'After oldIRQ return, bridge625B..6268 contains no flag consumer. Actualcaller61F3CMP5EFE0 defines arithmetic bits before branch/callback. Standalone6230 may legitimately return a conservative partial mask from its service.',
        'Source rootIRET loads actual SS FLAGS and returns a fully defined named word profile; it does not borrow the unexposed child arithmetic bits. Existing SS-word/corruption/raw-return/backend qualifications remain.',
        'This is a representation/continuation extension for composing actual state-register-only children and diagnostic exits. Actualfull403B simulation/mode/record/FN3 consumer, oldIRQ/nested delivery/writers-reset-lifetime-exclusion/core/P1-GATE remain open. Physical086Cunassigned/CGAbehindEGAclosure.'
    ],'validator_dependencies':[{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in deps],'limits':'Static partial-flags mask/liveness/body-identity review only. New comparison/native diagnostics/registration needed; no new actualIRQ/core/gameplay/fidelity acceptance.'}
    out.write_bytes((json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'result':'pass','sites':71,'partial_mask':hex(mask),'original_handler_unchanged':True}))
if __name__=='__main__':main()
