"""Verify fresh admission evidence and unchanged custody without rerunning makers."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_reference import verify, DEFAULT_MANIFEST

ROOT=Path(__file__).resolve().parents[1]
EP=ROOT/'docs/recovery/evidence'
CLONE=ROOT/'reference/repos/kylofon-test-drive-2-sdl3'


def require(value, message):
    if not value: raise RuntimeError(message)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve()
    require(out.is_relative_to(EP) and not out.exists(),'Fresh recovery-evidence output required')
    custody=verify(ROOT,DEFAULT_MANIFEST)
    original=json.loads((EP/'custody-baseline.json').read_bytes())
    require(custody['result']=='pass' and custody['files']==original['files'],'Original/reference custody differs')
    before=json.loads((ROOT/'docs/planning/evidence/kylofon-static-crosscheck-v1.json').read_bytes())
    require(sha(ROOT/'docs/recovery/functions.json')==before['our_registry_sha256'],'Existing function registry changed')
    for row in before['our_recovered_source_files']:
        require(sha(ROOT/row['path'])==row['sha256'],'Existing recovered source changed: '+row['path'])
    current_names=['kylofon-address-admission-v1.json','kylofon-source-admission-v1.json','kylofon-candidate-build-v1.json',
                   'kylofon-representative-validation-v1.json','kylofon-admission-support-v2.json','kylofon-candidate-changes-v1.json',
                   'kylofon-gap-dispositions-v2.json']
    receipts={n:json.loads((EP/n).read_bytes()) for n in current_names}
    pins={}
    def inspect(value):
        if isinstance(value,list):
            for item in value: inspect(item)
        elif isinstance(value,dict):
            if 'path' in value and 'sha256' in value:
                path=Path(value['path'])
                if not path.is_absolute():
                    path=ROOT/path
                    if not path.is_file(): path=CLONE/value['path']
                require(path.is_file(),'Missing pinned input: '+str(path))
                key=str(path.resolve());expected=value['sha256']
                if key not in pins: pins[key]=sha(path)
                require(pins[key]==expected,'Pinned hash differs: '+key)
                if 'bytes' in value: require(path.stat().st_size==value['bytes'],'Pinned length differs: '+key)
            for item in value.values(): inspect(item)
    for j in receipts.values(): inspect(j)
    diff=receipts['kylofon-representative-validation-v1.json']
    require(diff['result']=='pass' and diff['vectors']==2233 and not diff['candidate_mismatches'],'Representative result incomplete')
    require(diff['excluded_ss_alias']=={'mismatch':4},'Excluded aliases lost')
    require(sum(v for k,v in diff['baseline_mismatches'].items() if k!='excluded_ss_alias')==291,'Baseline discriminators lost')
    require(diff['original_instructions_executed']==116990,'Instruction scope changed')
    require(sha(ROOT/'tools/validate_kylofon_representative_v1.py')==diff['validator_sha256'],'Differential maker changed')
    require(sha(ROOT/diff['library'])==diff['library_sha256'],'Differential library changed')
    support=receipts['kylofon-admission-support-v2.json'];build=receipts['kylofon-candidate-build-v1.json']
    require(support['result']=='pass' and support['support_cases']==380 and build['result']=='pass','Build/support result incomplete')
    changes=receipts['kylofon-candidate-changes-v1.json']
    for row in changes['changes']:
        require(sha(ROOT/'analysis/candidates/kylofon-r03-v1/candidate'/row['path'])==row['candidate_sha256'],'Final candidate differs')
        if row['baseline_sha256']:
            require(sha(ROOT/'analysis/candidates/kylofon-r03-v1/baseline'/row['path'])==row['baseline_sha256'],'Baseline differs')
    snapshot=json.loads((ROOT/'docs/planning/evidence/kylofon-reference-snapshot-v1.json').read_bytes())
    for row in snapshot['tracked_files']:
        require(sha(ROOT/'analysis/candidates/kylofon-r03-v1/baseline'/row['path'])==row['sha256'],'Baseline not exact upstream')
    audit_path=EP/'p1-kylofon-r02-r03-audit-v1.json';audit=json.loads(audit_path.read_bytes())
    require(audit['result']=='pass','Full recovery audit failed')
    backlog=json.loads((ROOT/'docs/planning/backlog.json').read_bytes());tasks={t['id']:t for t in backlog['tasks']}
    require(tasks['P1-R02']['status']==tasks['P1-R03']['status']=='complete' and tasks['P1-R04']['status']=='pending','Task scopes wrong')
    require(tasks['P1-05']['status']=='in_progress' and tasks['P1-GATE']['status']=='pending','Broader recovery gate changed')
    require(audit['native_summary']==before['accepted_checkpoint']['native_summary'],'Main accepted native counts changed')
    staged=subprocess.check_output(['git','diff','--cached','--name-only'],cwd=ROOT,text=True).splitlines()
    require(not staged,'Unexpected staged files')
    whitespace=subprocess.run(['git','-c','core.whitespace=cr-at-eol','diff','--check'],cwd=ROOT,capture_output=True,text=True)
    require(whitespace.returncode==0,'Whitespace failure')
    for path in [diff['library'],'analysis/candidates/kylofon-r03-v1/native-build-v1/candidate/td2r03_full.exe',
                 'reference/repos/kylofon-test-drive-2-sdl3/README.md']:
        require(subprocess.run(['git','check-ignore','-q',path],cwd=ROOT).returncode==0,'Private artifact not ignored: '+path)
    docs=['README.md','docs/planning/backlog.json','docs/planning/continuation.md','docs/planning/roadmap.md',
          'docs/planning/architecture.md','docs/planning/validation.md','docs/planning/risks-and-estimates.md',
          'docs/planning/tooling-and-sources.md','docs/planning/kylofon-reuse-assessment.md','docs/recovery/README.md','docs/recovery/progress.json',
          'docs/recovery/kylofon-r02-r03-results.md','docs/recovery/kylofon-address-admission.md','docs/recovery/kylofon-source-admission.md','docs/recovery/kylofon-differential-design.md',
          'tools/verify_kylofon_r02_r03_v1.py','tools/admit_kylofon_addresses_v1.py','tools/review_kylofon_admission_v1.py',
          'tools/build_kylofon_candidate_v1.py','tools/validate_kylofon_representative_v1.py','tools/validate_kylofon_admission_support_v1.py']
    docs += ['docs/recovery/evidence/'+n for n in current_names]+[audit_path.relative_to(ROOT).as_posix()]
    result={'schema':1,'date':'2026-10-22','result':'pass','problems':[],
            'scope':'Evidence/hash/custody/dependency verification only; no rerun of accepted makers, compiler or differential fixtures',
            'original_files_unchanged':250,'frozen_clone_files_unchanged':113,'baseline_tracked_files_exact':85,
            'existing_recovered_source_headers_unchanged':len(before['our_recovered_source_files']),'function_registry_unchanged':True,
            'current_pinned_files_verified':len(pins),'candidate_files_changed_or_added':len(changes['changes']),
            'representative_vectors':2233,'baseline_admitted_mismatches':291,'excluded_ss_alias_witnesses':4,'support_cases':380,
            'task_counts':audit['task_counts'],'native_summary_unchanged':audit['native_summary'],'staged_files':0,
            'artifacts':[{'path':name,'bytes':(ROOT/name).stat().st_size,'sha256':sha(ROOT/name)} for name in docs]}
    out.write_bytes((json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps({k:v for k,v in result.items() if k!='artifacts'},indent=2))


if __name__=='__main__': main()
