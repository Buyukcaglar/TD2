"""Review signed guards, byte-DIV range proof and SS-counter label effects."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();assert not out.exists() and out.is_relative_to(ROOT/'docs/recovery/evidence');image=(ROOT/'analysis/derived/td2ega-v1/TD2EGA.image.bin').read_bytes();sha=hashlib.sha256(image).hexdigest();assert sha=='8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4';graph='analysis/flow/indirect-v8/direct-flow.json';g=json.loads((ROOT/graph).read_text());md=Cs(CS_ARCH_X86,CS_MODE_16);targets={'06C9:08CB','06C9:52FD','0432:0061'};observations=[]
    for f in g['functions']:
        if f['entry'] not in targets:continue
        s=int(f['entry'][:4],16)
        for ip in sorted(f['instructions']):
            i=next(md.disasm(image[16*s+ip:16*s+ip+15],ip,count=1));observations.append({'owner':f['entry'],'site':f'{s:04X}:{ip:04X}','bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str})
    for (s,ip),raw in {(0x6c9,0x8cb):'f6063c1388',(0x6c9,0x8f3):'f6063c13c0',(0x6c9,0x52fd):'2bca',(0x6c9,0x52ff):'7ef3',(0x6c9,0x5301):'7f04',(0x6c9,0x5303):'030e0d38',(0x6c9,0x5322):'3ae8',(0x6c9,0x5327):'f6f1',(0x6c9,0x5329):'32e4',(0x432,0x68):'c746fe0000',(0x432,0x6f):'ff46fe',(0x432,0x8a):'837efe12',(0x432,0x8e):'7d0b',(0x432,0x96):'c60020',(0x432,0xa1):'c60000'}.items():assert image[16*s+ip:16*s+ip+len(raw)//2].hex()==raw
    complementary=[]
    for zf,sf,of in itertools.product([0,1],repeat=3):jle=bool(zf or sf!=of);jg=bool(not zf and sf==of);assert jle!=jg;complementary.append({'ZF':zf,'SF':sf,'OF':of,'JLE':jle,'JG':jg})
    guard_cases=passing=0
    for count,denominator in itertools.product(range(3,61),range(256)):
        scaled=((count<<8)&65535)>>1;guard_cases+=1
        if scaled>>8<denominator:assert denominator!=0 and scaled//denominator<=255;passing+=1
    callers=[{'owner':f['entry'],**c} for f in g['functions'] for c in f['calls'] if c['target'] in targets];unique=sorted({(c['site'],c['target']) for c in callers});postcalls=[]
    for site,target in unique:
        c=next(c for c in callers if c['site']==site and c['target']==target);s=int(site[:4],16);ip=int(site[5:],16)+c['size'];postcalls.append({'site':site,'target':target,'following_instructions':[i.mnemonic+' '+i.op_str for i in md.disasm(image[16*s+ip:16*s+ip+12],ip,count=4)],'scope':'Candidatewindow only; MOV/RET/callee chains maycarryflags, fulllivenessnotclosed.'})
    record={'schema':1,'result':'pass','image_sha256':sha,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'instruction_observations':observations,'direct_caller_candidates':callers,'postcall_candidates':postcalls,'flow_ledger':graph,'flow_ledger_sha256':hashlib.sha256((ROOT/graph).read_bytes()).hexdigest(),'complementary_branch_truth_table':complementary,'byte_DIV_guard_proof':{'input_cases':guard_cases,'passing_guards':passing,'domain':'Unsigned3..60CX afterguards; swappedCHCL/SHR givesdividend, CMPCHAL/JAEsuppressesDIV unlessdenominator>dividendhighbyte.','conclusion':'Nonzero byte denominator andquotient<=255, noDIVfault undertheseentryguards. Algebraicchecks separatefromnativevector totals.'},'facts':['08CB twoflagmasks88/C0 atcurrentDS133C, signedAX/SI/fieldcomparisons, rawAXclamps andunsignedlastcomparisonCF. Negative/signedboundaries andflags interactions retained; nofieldunits inferred. NearRET2/noargs.','52FDsignedSUB/JLE usesOFcorrectly beforewrappedCXcompares. AdjacentJLE/JG arecomplementarywithoutflagsetter,5303unreachablefromthisentry (notglobaldead). RawAX-BX/AX+5wordwrap, bytequotientguard, finalXORAHclearsCF; nearRET2.','0432:0061 SSlocalcounter/nearargument: underscore->space whileunboundedscan, thenSIGNEDcounter<18 padding. ReadSScounter andargument again aftereachwrite; aliases maychange count/pointer/returnframe. Long>=18nottruncated; negativecounterwrap retainsrawpadding. AXunchanged, BXfinalcounter, actualSI/BPsaves/farRET4/callerclean.','Labelprefixes before0072/0090/009B, comparisonCF retainedthroughcounterINC. IncomingDFpreserved/unused; explicitwordcounter incrementsnotstringDF operations. SourceCreturntype/capacity/units unassigned.'],'limits':'Static operands/callerwindow andseparate8branchtruth/14848DIVpredicate checks only. Actualcaller/FLAGSpropagation/fields/units/bounds/writers/lifetime/exclusion/core/resourcefedP2/P3/device/session/game/fidelity open. Nohoststring orsigned-overflow normalization.'};out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'pass','ledger_sites':len(observations),'caller_records':len(callers),'unique_sites':len(unique),'branch_truth_cases':8,'DIV_predicate_cases':guard_cases}))
if __name__=='__main__':main()
