"""Review raw lookup bounds, word operand widths and shared caller sites."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());targets={'13A8:094A','13A8:2D57','13A3:0012','06C9:5334','06C9:535B'};md=Cs(CS_ARCH_X86,CS_MODE_16);observations=[]
    for f in g['functions']:
        if f['entry'] not in targets:continue
        segment=int(f['entry'][:4],16)
        for ip in sorted(f['instructions']):
            i=next(md.disasm(image[16*segment+ip:16*segment+ip+15],ip,count=1));observations.append({'owner':f['entry'],'site':f'{segment:04X}:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str})
    expected={(0x13a8,0x96e):'d7',(0x13a8,0x96f):'98',(0x13a8,0x2d61):'2e3807',(0x13a3,0x14):'98',(0x13a3,0x1f):'80fb5a',(0x13a3,0x2b):'8b87aa54',(0x6c9,0x5336):'81fb70fe',(0x6c9,0x534a):'81fb2003'}
    for (s,ip),raw in expected.items():assert image[16*s+ip:16*s+ip+len(raw)//2].hex()==raw
    callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];unique=sorted({(c['site'],c['target']) for c in callers});spans=[]
    for s,ip,length,label in [(0x13a8,0x2cae,6,'Six descending CS selector bytes'),(0x178f,0x6dda,20,'XLAT mapped-error bytes, admitted index0..13hex'),(0x178f,0x54aa,258,'Word lookup index0..128; overlaps registered5560 span at5560..55AB')]:
        spans.append({'segment':s,'segment_offset':ip,'offset':s*16+ip,'length':length,'sha256':hashlib.sha256(image[s*16+ip:s*16+ip+length]).hexdigest(),'role':label})
    dep='docs/recovery/evidence/td2ega-sign-extension-context-v1.json';assert json.loads((ROOT/dep).read_text())['result']=='pass';record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'validator_dependencies':[{'path':dep,'sha256':hashlib.sha256((ROOT/dep).read_bytes()).hexdigest()}],'instruction_observations':observations,'direct_caller_candidates':callers,'unique_direct_sites':[{'site':s,'target':t} for s,t in unique],'flow_ledger':graph,'flow_ledger_sha256':hashlib.sha256((ROOT/graph).read_bytes()).hexdigest(),'external_span_candidates':spans,'facts':['094A stores incomingAL atDS6DA0. AHnonzero becomes signedAX directly; otherwise versionbyte6D9D changes raw error-code clamp/remap then XLAT6DDA, word CBW andstore6D95. Near return.','2D57 compares six CS bytes descending2CB3..2CAE, match ->BX7058+4*index/AX4*index/CF0, missing ->CX0/BX2CAD/CF1 withAXunchanged. BPsave/farreturn.','13A3:0012 unprefixed98 signextendsAL; absolute value then signed BL compare5A, raw foldB4-BL onlyifBLsigned>5A. AL80 keepsindex128. ReadsDS54AA+2index, conditionalwordNEG, preservesBX/DXviaactualSSsaves/farreturn.','5334 signedBX<-400 or>800 skipsupdate; signedranges[-400,-1]/[0,399]/[400,800] selectDS333E/3340/3342, updateonlysignedAX<word. Nearreturn.','535B signedmaxof333E/3340 choosesCXFF38/C8; bit80of33BE and3342comparisonmaychooseCX258 withoutDXupdate. SignedAX<-40,[-40,40],[41,359],[360,440],>440 selectDX333E/100/100/3340/3342. Nearreturn.','Shared0939 nearcall appears under multiple graphowners; report unique sites separately from owner records. No gameplay units or C types inferred.'],'limits':'Static raw operand/bounds/caller-site and external span identity only. No table content decoding/publication, actual caller/writers/otherFLAGS/lifetime/exclusion/core or device/session/game/fidelity acceptance.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','sites':len(observations),'caller_records':len(callers),'unique_caller_sites':len(unique),'external_spans':len(spans)}))
if __name__=='__main__':main()
