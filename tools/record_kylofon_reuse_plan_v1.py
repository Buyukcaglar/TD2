"""Record the R04 decision in the live plan; preserve exact prior plan bytes."""
from collections import Counter
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads((ROOT / path).read_bytes())


def write(path, value):
    (ROOT / path).write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode())


def main():
    previous = {
        'docs/planning/backlog.json': 'analysis/history/backlog-before-kylofon-r04-v1.json',
        'docs/recovery/progress.json': 'analysis/history/progress-before-kylofon-r04-v1.json',
        'docs/planning/continuation.md': 'analysis/history/continuation-before-kylofon-r04-v1.md',
    }
    if any((ROOT / p).exists() for p in previous.values()):
        raise FileExistsError('R04 plan maker already consumed')
    backlog = load('docs/planning/backlog.json')
    progress = load('docs/recovery/progress.json')
    decision = load('docs/recovery/evidence/kylofon-reuse-decisions-v2.json')
    tasks = {t['id']: t for t in backlog['tasks']}
    assert tasks['P1-R04']['status'] == 'pending'
    assert tasks['P1-05']['status'] == 'in_progress'
    assert Counter(t['status'] for t in tasks.values()) == {'complete': 12, 'in_progress': 1, 'pending': 54}
    for old, target in previous.items():
        (ROOT / target).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / target).write_bytes((ROOT / old).read_bytes())
    report = 'docs/recovery/kylofon-r04-reuse-decision.md'
    register = 'docs/recovery/evidence/kylofon-reuse-decisions-v2.json'
    manifest = 'docs/recovery/evidence/kylofon-reuse-origin-manifest-v2.json'
    effort = 'docs/planning/evidence/kylofon-effort-inputs-v1.json'
    task = tasks['P1-R04']
    task.update(
        title='Select qualified subsystem reuse and revise remaining effort',
        status='complete', completed_on='2026-10-22',
        deliverables=['Per-symbol/branch selection and exact origin manifest',
                      'Native caller profile, transitive dependency limits and raw-contract bridge',
                      'Remaining effort model with measured evidence and human-estimate limits'],
        acceptance='Use actual R03 disagreements and recorded machine validation costs to select only qualified symbols/branches. Distinguish engineering judgment from unlogged human effort. Preserve independent fallback, MIT notices, raw original contracts and existing EGA-before-CGA phase gates.',
        completion_scope='Decision/provenance/planning only: ten groups (six value groups covering eleven already-recovered entries and four support groups), no primary source import, new recovery contract, compiler/game run or phase-gate credit. Larger families deferred; substantial current saving not booked.',
        evidence=[report, register, manifest, effort, 'docs/planning/kylofon-effort-review.md',
                  'docs/recovery/kylofon-reuse-selection-review.md',
                  'docs/recovery/evidence/kylofon-reuse-selection-review-v1.json',
                  'docs/recovery/kylofon-r04-boundary-review.md',
                  'docs/recovery/kylofon-r04-final-review.md'],
        reference_review=report)
    for item in decision['selected']:
        for task_id in item['implementation_tasks']:
            target = tasks[task_id]
            target.setdefault('qualified_reuse_units', []).append(item['id'])
            target['reuse_selection'] = register
            target['reuse_integration_condition'] = 'Source-selection only. Prove the actual caller/lifetime/alias profile, minimal transitive dependency closure and production guards; retain raw fallback and create fresh source/build/comparison evidence. Existing acceptance and phase prerequisites remain unchanged.'
    backlog['last_plan_review_date'] = '2026-10-22'
    backlog['external_reference_review'].update(
        assessment=report, admission_tasks='P1-R01 through P1-R04 complete within their review/admission/selection scopes; existing core gates remain open',
        reuse_register=register, origin_manifest=manifest, remaining_effort_model=effort,
        source_imported=False, source_imported_to_primary_tree=False,
        substantial_current_effort_saving_booked=False, next_core_task='P1-05')
    progress['task_counts'] = dict(Counter(t['status'] for t in tasks.values()))
    progress['external_reference_review'].update(
        assessment=report, status='P1-R01/R02/R03 bounded complete; P1-R04 source-selection/provenance/effort decision complete; no integration or new recovered-function credit',
        next_adoption_task=None, next_core_task='P1-05', reuse_register=register,
        origin_manifest=manifest, remaining_effort_model=effort,
        primary_source_import_performed=False, current_remaining_engineer_days=[203, 461],
        substantial_current_effort_saving_booked=False)
    write('docs/planning/backlog.json', backlog)
    write('docs/recovery/progress.json', progress)
    prefix = '''# 22 October 2026: P1-R04 completed; next work remains P1-05

The latest user request authorized qualified Kylofon subsystem selection, updated
effort estimates and durable findings, keeping originals/reference unchanged.
P1-R04 is complete as a decision, provenance and planning task. Start with
docs/recovery/kylofon-r04-reuse-decision.md and the normative registers:
docs/recovery/evidence/kylofon-reuse-decisions-v2.json and
docs/recovery/evidence/kylofon-reuse-origin-manifest-v2.json. Version1 and its
consumed maker are preserved drafts; v2 explicitly enumerates transitive helpers
without broadening admitted behavior. Read the complete existing continuation
below for P1-05 caller/formatter/terminal/descriptor and early-exit obligations.

Select KRU-01..06: eleven ALREADY recovered original entries, limited native
value/memory projections. R03 supplied2233 admitted original-body cases with no
candidate disagreement. Four actual SS argument aliases remain mismatches outside
the selected native domain. Do not admit RPM bool/output pointers, EGA VRAM,
general brake, skipped RLE sequence/move/paragraph helpers, all caller history,
arbitrary DS/SS/FLAGS/frame aliases, IRQ/timing, full resources or game sessions.
KRU-07..10 select bounded memory/division dependencies, exact-edition EXE loader
and explicit-root Windows profile adapter, with380 separate support checks.
Header/mp/wr8/far-pointer/row_at dependencies are only tested transitive contexts;
future extraction must establish minimal buildable closure and production guards.
No code was extracted/integrated or granted distribution approval in R04.

Whole game/scene, full renderer, codec/archive/cache, SDL/device/audio remain
deferred. Retain original-byte/bus oracle and existing portable-C fallback. Future
extraction/callers/changes need fresh sources, builds and comparisons, within the
named existing task and phase gates. Preserve MIT notices, exact Git blob/file
origins and modifications. host_paths is partly upstream-derived.27 game/runtime
strings and unreviewed media/identity markers still prevent whole-file release.

Effort: docs/planning/kylofon-effort-review.md and
docs/planning/evidence/kylofon-effort-inputs-v1.json cover all54 remaining
implementation/acceptance tasks exactly once. From the shared post-R03 state,
independent reference-aided implementation is205â€“455 engineer-days; the current
qualified subset is203â€“461 days, about41â€“93 five-day weeks BEFORE reserve.
Small2â€“5 day gross credit is offset by3â€“8 day extraction/bridge/provenance costs:
net two days saved to six extra, midpoint two extra. No substantial current saving
is booked. Broader EGA/format/host reuse is conditional185â€“410 days/37â€“82 weeks,
paired4â€“9 weeks saving only after further admission; adverse costs can erase it.
25â€“40% discovery/rework reserve is separate: roughly51â€“130 weeks including it.
These are engineering judgments, not measured human throughput/calendar dates.
CGA/Amiga/scenery/switching/acceptance earn no credit. Re-estimate at actual gates.

Live plan:67 tasks,13complete/1inprogress/53pending. ONLY P1-R04 status changed.
P1-05 remains active and P1-GATE open; EGA -> CGA -> full DOS resources -> native
DOS -> Amiga -> switching/scenery remains mandatory. Main accepted native totals
stay215exports/292entries/164suites/7132350vectors;440 function candidates and
305 resource records unchanged. The early-exit packet remains unregistered.

Custody:250 originals,113 clone files,85 R03 baseline files and331 recovered
source/headers remain unchanged. Frozen upstream commit is
352b56824d8c91e938b8f0794a71afca9a276193. Use only git --no-optional-locks for
clone inspection; no fetch/edit/build/run there. Both R03 source trees, builds,
makers and accepted receipts stay unchanged; do not rerun consumed writers.
Final metadata/custody evidence is p1-kylofon-r04-audit-v1.json and
kylofon-r04-verification-v1.json under docs/recovery/evidence. No compiler/game/
differential rerun, staging, commit, push or global memory update was
performed by this decision task. Stop here unless further work is requested.

The byte-exact prior handoff and plan are in analysis/history/
continuation-before-kylofon-r04-v1.md, backlog-before-kylofon-r04-v1.json and
progress-before-kylofon-r04-v1.json. Older R04-pending statements below are
historical snapshots, superseded by this current decision.

'''
    old = (ROOT / previous['docs/planning/continuation.md']).read_bytes()
    (ROOT / 'docs/planning/continuation.md').write_bytes(prefix.encode() + old)
    print(json.dumps({'task_counts': progress['task_counts'], 'source_imports': 0}))


if __name__ == '__main__':
    main()
