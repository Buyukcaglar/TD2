"""Record P1-R04 decisions and provenance; never import or modify source.

Fresh outputs only. Historical build/comparison makers are not rerun. The
allowlist is symbol/branch and profile specific, never a whole-file approval.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
EP=ROOT/'docs/recovery/evidence'
PRIVATE='analysis/candidates/kylofon-r03-v1/candidate'
UPSTREAM='reference/repos/kylofon-test-drive-2-sdl3'
COMMIT='352b56824d8c91e938b8f0794a71afca9a276193'


def pin(path):
    p=ROOT/path
    return {'path':path,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}


def fresh(path,value):
    if path.exists(): raise FileExistsError(path)
    path.write_bytes((json.dumps(value,indent=2,ensure_ascii=False)+'\n').encode())


def main():
    outputs=[EP/'kylofon-reuse-decisions-v2.json',EP/'kylofon-reuse-origin-manifest-v2.json']
    if any(p.exists() for p in outputs): raise FileExistsError('Decision maker already consumed')
    differential=json.loads((EP/'kylofon-representative-validation-v1.json').read_bytes())
    support=json.loads((EP/'kylofon-admission-support-v2.json').read_bytes())
    baseline=json.loads((EP/'kylofon-r04-baseline-verification-v1.json').read_bytes())
    if differential['result']!='pass' or differential['vectors']!=2233 or support['result']!='pass' or baseline['result']!='pass':
        raise ValueError('Current bounded evidence missing')
    snapshot=json.loads((ROOT/'docs/planning/evidence/kylofon-reference-snapshot-v1.json').read_bytes())
    originals={r['path']:r for r in snapshot['tracked_files']}
    registry=json.loads((ROOT/'docs/recovery/functions.json').read_bytes())['records']
    by_address={f"{e['segment']:04X}:{e['segment_offset']:04X}":r for r in registry for e in r['entries']}
    items=[]
    def choose(id,title,path,symbols,entries,families,observations,domain,excluded,tasks,kind='qualified_value_implementation',dependencies=None,origin=None):
        linked=[]
        for address in entries:
            record=by_address[address]
            linked.append({'address':address,'existing_function_id':record['id'],
                           'existing_portable_source':record.get('portable_source'),
                           'newly_recovered_by_this_decision':False})
        origin_path=origin or path
        upstream=originals.get(origin_path)
        item={'id':id,'title':title,'decision':kind,'candidate_source':pin(PRIVATE+'/'+path),
              'symbols_or_branches':symbols,'original_entries':linked,'fixture_families':families,
              'admitted_observations':observations,'native_domain':domain,'excluded':excluded,
              'implementation_tasks':tasks,'dependencies':dependencies or [],
              'whole_file_copy_authorized':False,'primary_source_import_performed':False,
              'distribution_admitted':False,'independent_fallback':'Existing recovered source and original-byte raw/bus oracle remain canonical; rejected domains use independent recovery.',
              'origin':{'repository':'https://github.com/kylofon/test-drive-2-sdl3','commit':COMMIT,
                        'upstream_path':origin_path,'upstream_git_blob':upstream['git_blob'] if upstream else None,
                        'upstream_file_sha256':upstream['sha256'] if upstream else None,
                        'local_changes':'docs/recovery/evidence/kylofon-candidate-changes-v1.json'}}
        items.append(item)
    choose('KRU-01','Byte-ring value implementation','td2port/src/platform/res.c',['rand8'],['06C9:780E'],['byte_ring'],
           ['Native scalar return and nonframe RAM after 1/17 serialized calls'],
           ['Fixed relocated DGROUP and admitted image; exact 278 deterministic cases from the pinned fixture stream','Owned disjoint code/state/scratch; caller history and initial seed purpose are not inferred'],
           ['Actual SS stores, GPR/FLAGS, IRQ/nesting, all writers/reset/lifetime and historical consumption history'],['P1-06','P3-03'],dependencies=['KRU-07','types/address declarations only'])
    choose('KRU-02','Literal external-word read and subtraction','td2port/src/platform/timer.c',['bios_ticks','bios_ticks_since'],['06C9:5D83','06C9:5D8D'],['literal_reader','literal_subtract'],
           ['Native scalar and nonframe RAM; literal physical086C, modulo16 subtraction'],
           ['270 deterministic cases; physical086C and physical046C varied independently','Function names do not assign BIOS-clock or time-unit semantics'],
           ['Host clock substitution, real time, interrupt scheduling and arbitrary live SS argument aliases'],['P1-07','P3-03'],dependencies=['KRU-07'])
    choose('KRU-03','Input callback-vector value access','td2port/src/platform/input.c',['kbd_set_getkey_fn','kbd_get_getkey_fn'],['06C9:6A17','06C9:6A28'],['input_vector_set','input_vector_get'],
           ['Stored far words, getter scalar DX:AX projection and nonframe RAM'],
           ['256 deterministic cases; fixed DS data and stable C value arguments; disjoint original frame aperture'],
           ['Four observed live-SS argument aliases remain mismatches','Keyboard event processing, BIOS/IRQ delivery, vector ownership and lifetime'],['P1-05','P1-07','P3-03'],dependencies=['KRU-07'])
    choose('KRU-04','Selected simulation memory updates','td2port/src/game/sim.c',['curve_sum','drag_apply','update_rpm(NULL,NULL)','brake: transitive gear-zero path only'],['06C9:448A','06C9:45BF','06C9:4612'],['simulation_curve','simulation_drag','simulation_rpm'],
           ['Memory updates only; update_rpm boolean and host pointer outputs were not compared'],
           ['725 deterministic cases with the exact original state/table inputs from the fixture stream','brake is a dependency reached by drag_apply in neutral gear-zero fixtures; it has no standalone general admission'],
           ['RPM boolean result, non-NULL/aliasing output pointers, neutral-clutch consumers and inherited CX/DX','General brake entry, full vehicle simulation, valid historical caller domain, collision/traffic and timing'],['P1-06','P1-08','P3-04'],dependencies=['KRU-07'])
    choose('KRU-05','Graphics clip and RAM planar point','td2port/src/platform/gfx.c',['gfx_set_clip_current','gfx_plot: RAM branch only'],['06C9:5DFB','06C9:BA3C'],['graphics_clip','graphics_ram_plot'],
           ['Nonframe CS target state and RAM writes'],
           ['128 clip and384 RAM-plot fixtures; declared plane descriptors, bitmask/row table and physical-wrap inputs','Select only actual RAM branch; original return/frame control checked separately from native data API'],
           ['EGA VRAM branch, latch/register/hardware effects, display pixels and visual fidelity','Constructor/full blitters, generic video-segment aliases, rendering schedule and provider switching'],['P1-09','P3-05'],dependencies=['KRU-07'])
    choose('KRU-06','Run-only codec branch','td2port/src/platform/res.c',['rle_decode: header/table and ec>0x80 branch','rle_run_pass: tested dependency only'],['06C9:6B02'],['codec_run_stage'],
           ['Native returned far destination and nonframe RAM'],
           ['192 synthetic cases; ec exactly0x81/0x83/0x8B; escape counts exactly1/3/11','Input8000:0120, destination argument6000:1234, total_paras0400; DS=SS278F/SP E000; fixed byte streams/counts and disjoint source/output from pinned fixtures'],
           ['rle_seq_pass, far_move_up and paras_of are skipped in the tested branch, not admitted dependencies','Sequence-first path, zero/full LOOP, general escape counts, overlapping/malformed streams, full codec/corpus/parser safety'],['P1-05','P2-02'],dependencies=['KRU-07'])
    choose('KRU-07','Scalar memory access and fixed-data view dependencies','td2port/src/mem.h',['lin','rd8','rd16','rd32','wr16','wr32','fixed DGROUP/CS lvalues: dependency only'],[],['support:memory_scalar_read','support:memory_scalar_write','graphics_ram_plot'],
           ['20bit scalar address/read/write state;240 independent support cases; actual plot supplies additional dependency observations'],
           ['Windows little-endian x64; bytewise scalar helpers wrap each physical byte','Direct typed lvalues only in the tested fixed DS/CS native view; they are not a general portable memory API'],
           ['Generic bulk/mp spans across wrap, arbitrary typed alignment/alias portability, second-host proof and CPU ABI'],['P1-07','P3-01'],kind='qualified_support_adapter')
    choose('KRU-08','Guarded signed-division quotient/fault helper','td2port/src/mem.h',['idiv32_16: rem=NULL'],[],['support:division_guard'],
           ['Quotient or explicit trapped fault in77 support cases'],
           ['Remainder pointer is NULL; INT32_MIN/-1 checked before C division','Safe explicit host terminal action; default original runtime message remains distribution blocked'],
           ['Remainder pointer writes/aliases, original x86 fault ABI and runtime message distribution'],['P1-06','P3-01'],kind='qualified_support_adapter',dependencies=['Nonreturning host error adapter must be externally sourced or media-free before distribution'])
    choose('KRU-09','Canonical external EXE admission loader','td2port/src/mem.c',['admitted_exe','mem_load_exe: exact canonical packed EXE','exepack_unpack: dependency for admitted canonical image only'],[],['support:loader_canonical','support:loader_identity_rejection'],
           ['Two native loaded-memory comparisons including1652 relocations/five explicit passed-state assignments;10 identity rejections'],
           ['Exact114421-byte packed EXE SHA256 eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182','Private Windows BCrypt admission path; external file treated as data, not executed'],
           ['Other EXE editions, already-unpacked MZ acceptance, deep malformed-EXEPACK fuzzing and game execution','Removed protection/disk paths are explicit native policy, not original-equivalence claims'],['P3-02'],kind='qualified_windows_integration_candidate',dependencies=['Pinned Windows BCrypt/SDL3; external originals policy'])
    choose('KRU-10','Separate original/user-profile path adapter','td2port/src/host_paths.c',['host_paths_init: explicit profile root','host_game_path','lookup/simple_name/absolute_root/nested: tested dependencies','host_paths_shutdown'],[],['support:profile_init','support:profile_lookup','support:profile_name_rejection','support:profile_hardlink_rejection','support:profile_actual_write','support:profile_root_rejection'],
           ['51 support cases including actual synthetic profile writes and unchanged synthetic originals'],
           ['Windows serialized explicit disjoint original/profile paths and tested names; local adapter derives in part from upstream case-insensitive lookup','Explicit profile parameter only; default preference-directory/CLI/UI integration has not been exercised'],
           ['Adversarial filesystem races, all Win32 path forms/second host, default preference-dir branch and full host event lifecycle','Quiet write return0 is not success evidence; use path/effect/readback'],['P3-02','P3-08'],kind='qualified_windows_integration_candidate',origin='td2port/src/host.c',dependencies=['Retain upstream MIT notice for derived lookup','SDL3/Windows path APIs'])
    # These helpers were observed transitively; no generic standalone API admission.
    transitive={
        'KRU-01':['mp and fixed DSB/DSW lvalues at the tested fixed image addresses'],
        'KRU-03':['setter: ds_far_wr/far_wr/wr16; getter: ds_far/far_rd/rd16; FarPtr/far_make declarations, only tested fixed DS:64DC vector and stable scalar profile'],
        'KRU-05':['row_at/rd16/rd8/wr8 and fixed CS descriptor lvalues, only selected clip/RAM plot branch'],
        'KRU-06':['rle_run_pass/wr8/rd8/rd16/mp and FarPtr/far_make, only readable fixed20byte header and admitted run streams; no sequence/move/paragraph helper admission'],
        'KRU-07':['mp only for fixed admitted spans/lvalues; wr8 observed transitively in RAM plot/run stage, not a separate direct scalar-write support suite','FarPtr/far_make/far_rd/far_wr/ds_far/ds_far_wr only as KRU-03/06 transitive declarations/helpers, never generic arbitrary-pointer APIs']}
    for item in items:
        item['tested_transitive_dependencies_only']=transitive.get(item['id'],[])
        item['dependency_closure_status']='Observed dependencies enumerated; minimal buildable extraction and production guards remain a future import obligation. Source/header hashes pin declarations, not all their behavior.'
        if item['id']=='KRU-07':
            item['symbols_or_branches'] += ['mp: fixed-span dependency only','wr8: RAM plot/run-stage transitive only','FarPtr/far_make/far_rd/far_wr/ds_far/ds_far_wr: tested transitive context only']
    selection_review=json.loads((EP/'kylofon-reuse-selection-review-v1.json').read_bytes())
    for item in items:
        entries={r['address'] for r in item['original_entries']}
        source_ranges=[]
        for rec in selection_review['selected_records']:
            if entries.intersection(rec['entries']):
                source_ranges.append(rec['source'])
        item['selected_source_ranges']=source_ranges
    def selected_lines(path,start,end):
        data=(ROOT/path).read_bytes().splitlines(keepends=True)
        span=b''.join(data[start-1:end])
        return {'path':path,'start_line':start,'end_line':end,'span_sha256':hashlib.sha256(span).hexdigest(),
                'qualification':'Line locators are tied to full file hash; only named branches/functions and observations qualify.'}
    support_ranges={'KRU-07':[(32,40)],'KRU-08':[(85,92)],'KRU-09':[(13,23),(43,195)],'KRU-10':[(9,112)]}
    for item in items:
        if item['id'] in support_ranges:
            item['selected_source_ranges']=[selected_lines(item['candidate_source']['path'],a,b) for a,b in support_ranges[item['id']]]
    deferred=[
        {'id':'KRD-01','area':'Integrated game/scene/score flow','source_globs':['td2port/src/game/*.c'], 'decision':'deferred_candidate','tasks':['P1-05','P1-08','P1-09','P3-03','P3-04'],'reason':'Most called bodies/state/lifetimes/timing/shortDAT/stale-register domains unadmitted;27 media/runtime string blockers across candidate; only KRU-04 selected spans qualify.'},
        {'id':'KRD-02','area':'Full EGA renderer and effects','source_globs':['td2port/src/platform/gfx*','td2port/src/game/scene*'],'decision':'deferred_candidate','tasks':['P1-09','P3-05'],'reason':'Only KRU-05 RAM/clip slices selected; hardware/latches/constructor/full blits/display/complete content require proof.'},
        {'id':'KRD-03','area':'Full formats/archive/cache/loaders','source_globs':['td2port/src/platform/res.c','tools/td2*.py','FORMATS.md'],'decision':'reference_and_deferred_candidate','tasks':['P1-05','P2-01','P2-02','P2-03','P2-04','P2-05','P2-06','P2-07','P2-08'],'reason':'Run-only KRU-06 is not full codec/corpus/ownership acceptance; use schema leads and independent fallback without unconditional estimate credit.'},
        {'id':'KRD-04','area':'SDL host/device/input/audio scheduling','source_globs':['td2port/src/host.c','td2port/src/platform/input.c','td2port/src/platform/timer.c','td2port/src/platform/sound.c'],'decision':'deferred_candidate','tasks':['P1-07','P1-10','P3-01','P3-06','P3-09'],'reason':'Compilation and selected data access do not prove device lifecycle, clock/IRQ/RNG ordering, sequencer/PCM or whole host behavior.'},
        {'id':'KRD-05','area':'CGA/Amiga/Northern Germany/live switching','source_globs':['port/td2cga*','port/td2tdy*'],'decision':'no_implementation_credit','tasks':['P1-12','P1-13','P1-14','P4-04','P4-10','P5-05','P5-06'],'reason':'CGA indexes are reference only; requested native CGA/Amiga/content/switching implementations are absent.'}
    ]
    evidence_names=['kylofon-address-admission-v1.json','kylofon-source-admission-v1.json','kylofon-candidate-build-v1.json','kylofon-representative-validation-v1.json','kylofon-admission-support-v2.json','kylofon-candidate-changes-v1.json','kylofon-r04-baseline-verification-v1.json','kylofon-reuse-selection-review-v1.json']
    license_pin=pin(UPSTREAM+'/LICENSE')
    common={'schema':1,'date':'2026-10-22','task':'P1-R04','upstream_commit':COMMIT,
            'decision_scope':'Approve defined symbols/branches for bounded reuse in their existing phase tasks. This is a source-selection decision, not source integration, new recovery contracts, runtime/game/fidelity or distribution admission.',
            'maker':pin('tools/record_kylofon_reuse_decision_v2.py'),
            'supersedes_draft':{'decision':pin('docs/recovery/evidence/kylofon-reuse-decisions-v1.json'),
                                'origin_manifest':pin('docs/recovery/evidence/kylofon-reuse-origin-manifest-v1.json'),
                                'maker':pin('tools/record_kylofon_reuse_decision_v1.py'),
                                'reason':'Explicit transitive helper/declaration closure; no broadened behavioral admission. Preserve prior draft and consumed maker.'},
            'dependency_policy':'Only enumerated observed transitive helper contexts qualify; extract a minimal buildable dependency closure and production guards under fresh integration evidence.',
            'evidence':[pin('docs/recovery/evidence/'+n) for n in evidence_names]}
    decision=dict(common,selected=items,deferred=deferred,
       effort={'model':pin('docs/planning/evidence/kylofon-effort-inputs-v1.json'),
               'report':pin('docs/planning/kylofon-effort-review.md'),
               'comparison_basis':'Remaining work after R02/R03, all current knowledge/local fixes shared by both routes; no sunk recovery is charged or credited again.',
               'current_qualified_route_days':[203,461],'current_qualified_route_weeks':[40.6,92.2],
               'independent_reference_aided_route_days':[205,455],
               'current_reuse_gross_credit_days':[2,5],'current_extra_adoption_cost_days':[3,8],
               'current_net_effort_change_days':[-2,6],'midpoint_current_net_effort_change_days':2,
               'conditional_expansion_weeks':[37,82],'conditional_matched_savings_weeks':[4,9],
               'engineering_judgment_not_machine_measured_throughput':True,'substantial_current_saving_booked':False},
       bridge={'state':'Fixed LOAD1000/DGROUP278F/CS16C9 admitted relocated image and synthetic profiles; stable owned/disjoint code/state/scratch.',
               'observations':'Scalar only for780E/5D83/5D8D/6A28/6B02; all other sampled entries memory effects only. No native RPM bool/output-pointer promise.',
               'stack':'Original SP-0300 through call-frame aperture excluded from native comparison; four actual live argument aliases remain observed disagreements. Native values never replace raw SS/bus APIs by name alone.',
               'universal_exclusions':['raw GPR/FLAGS/SS-frame/return-alias equivalence','historical caller reachability','all writers/reset/lifetimes','IRQ/device/time history','full corpus/game/pixels/audio/fidelity','second-host portability']},
       import_rules=['No whole-file copying or blind replacement of src/recovered; symbol and tested-branch selection only.',
                     'Target integration must prove its caller/data/lifetime preconditions, add explicit observable projection, retain the raw fallback and create fresh source/build/comparison versions.',
                     'Reusing a header or helper as a dependency grants no admission to its unexecuted functions/branches.',
                     'Preserve upstream MIT notice plus exact origin and local modification record; local-derived host_paths is not upstream-free.',
                     'All game/runtime text and unreviewed media stay external; private source build is not package approval.',
                     'Existing phase order, incomplete tasks, raw helper totals and unregistered early-exit packet remain unchanged.'],
       results={'original_entries_selected':11,'decision_groups':len(items),'original_body_vectors':2233,'support_cases':380,'excluded_ss_alias_disagreements':4,'baseline_admitted_disagreements':291,'observed_corrected_semantic_classes':2,'newly_recovered_functions':0,'primary_source_imports':0,'new_build_or_test_runs_this_task':0},
       next_frontier='P1-05 state/resource ownership and actual caller proofs; selected value candidates may be adapted only within named existing tasks. No move to CGA/resources/native/Amiga before phase gates.')
    source_paths=sorted({i['candidate_source']['path'] for i in items})
    files=[]
    for path in source_paths:
        selected=[i['id'] for i in items if i['candidate_source']['path']==path]
        files.append({'candidate':pin(path),'selected_decision_ids':selected,'whole_file_copy_authorized':False,'license_notice_required':True})
    manifest=dict(common,license={'declared_license':'MIT','copyright':'Copyright (c) 2026 Krzysztof Kania','upstream_notice':license_pin,
                   'candidate_notice':pin(PRIVATE+'/LICENSE'),'retain_notice_on_substantial_copy':True,'original_game_media_rights_not_included':True},
                  files=files,derived_origin_notes=[{'candidate':PRIVATE+'/td2port/src/host_paths.c','origin':UPSTREAM+'/td2port/src/host.c','upstream_lookup_lines':'498-517','classification':'local-derived adapter plus local admission changes; retain upstream notice'}],
                  change_receipt=pin('docs/recovery/evidence/kylofon-candidate-changes-v1.json'),
                  private_patch=pin('analysis/candidates/kylofon-r03-v1/candidate-fixes-v2.patch'),
                  distribution_admitted=False,primary_source_import_performed=False)
    fresh(outputs[0],decision)
    manifest['normative_decision']=pin('docs/recovery/evidence/kylofon-reuse-decisions-v2.json')
    fresh(outputs[1],manifest)
    print(json.dumps(decision['results'],indent=2))


if __name__=='__main__': main()
