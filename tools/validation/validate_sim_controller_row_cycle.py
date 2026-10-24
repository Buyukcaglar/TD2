"""Review two long4674 row fixtures; correct the aggregate scan-reset counter.

The immutable full v3 comparison remains selected for its59,202 output checks.
This derives a two-case harness from that exact validator, counts only actual
4742 ADD SI,8 with pre-SI FFF8, and retains its fullbus/GPR/control comparison.
It neither replaces nor relaxes the full comparison's687-site coverage gate.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
source=ROOT/'tools/validate_sim_controller.py'
receipt=ROOT/'docs/recovery/evidence/td2ega-sim-controller-validation-v3.json'
full=json.loads(receipt.read_text());raw=source.read_bytes()
assert full['result']=='pass' and full['vectors']==59202 and full['instruction_sites_exercised']==687
assert hashlib.sha256(raw).hexdigest()==full['validator_sha256']
assert full['fixture_coverage']['actual_8192_source_row_cycles']==366
t=source.read_text()
needle="   if ip==0x4735 and cpu.reg_read(UC_X86_REG_SI)==0 and active['rows']>1:active['source_row_wraps']+=1"
assert t.count(needle)==1
t=t.replace(needle,"   if ip==0x4742 and cpu.reg_read(UC_X86_REG_SI)==0xfff8:active['source_row_wraps']+=1")
needle=' for load in [0x1000,0x2345]:';assert t.count(needle)==1
t=t.replace(needle," cases=[c for c in cases if c['long']=='rows8193'];require(len(cases)==1,'One long fixture perload')\n"+needle)
lines=t.splitlines();matches=[i for i,line in enumerate(lines) if line.startswith(' require(sites==fence,')];assert len(matches)==1
lines[matches[0]]=" require(vectors==2 and coverage['actual_8192_source_row_cycles']==2,'Two exact original ADD-SI wraps')"
t='\n'.join(lines)+'\n'
needle="hashlib.sha256(Path(__file__).read_bytes()).hexdigest()";assert t.count(needle)==1;t=t.replace(needle,'_counter_review_script_hash')
needle=";out.write_text(json.dumps(record,indent=2)";assert t.count(needle)==1
extra=""";record['validator_dependencies'] += [{'path':v,'sha256':hashlib.sha256((ROOT/v).read_bytes()).hexdigest()} for v in ['tools/validate_sim_controller.py','docs/recovery/evidence/td2ega-sim-controller-validation-v3.json']];record['counter_erratum']={'full_comparison':'docs/recovery/evidence/td2ega-sim-controller-validation-v3.json','full_run_legacy_counter_name':'actual_8192_source_row_cycles','full_run_legacy_counter_value':366,'legacy_meaning':'SIzeroatrowheadafteranypriorrow; includesfreshscanstarts inlatercontrolleriterations, notonlyfullcycles. Do notinterpret366asfullcycles.','targeted_exact_ADD_SI_wraps':2,'targeted_fixture_count':2,'exact_event':'06C9:4742 ADD SI,8 withpreinstructionSI=FFF8','per_fixture_required_outcome':'8193rowheads/SI8/before4735budgetprefix, oneactualwrap; fullRAM-GPR-CFIFDF-control-counts matchnativeC.'};record['limits']='Two targetedoriginal-instruction/fullnativeC comparisons atloads1000-2345 forwhole4674source-rowfixture. ActualADD SI8 wrapeventat4742/FFF8,8193heads,SI8,onewrapeach. Supplementalerratumonly: selectedfull59202case/687siteoutputs remainvalid; itslegacy366counterincludesfreshscanresets andisnotafullcyclecount. No newhelper-suitevectors/actualcaller-IRQ-storage-lifetime-core orruntime-game-fidelity acceptance.'"""
t=t.replace(needle,extra+needle)
namespace={'__name__':'_td2ega_row_cycle_review','__file__':str(source),'_counter_review_script_hash':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
exec(compile(t,str(source),'exec'),namespace)
namespace['main']()
