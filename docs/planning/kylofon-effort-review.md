# P1-R04 remaining-effort review

22 October 2026. This is a planning estimate for work **remaining after P1-R02/R03**, using the current backlog and validation evidence. It is not a measured development rate, a calendar promise, an estimate of effort already spent, or a gate-completion percentage. The parent P1-R04 decision selects the final reuse scope; this review supplies a consistent comparison and arithmetic.

## Recommendation

Budget the presently qualified small selection at **about 41–93 engineer-weeks remaining before contingency** for the complete requested project. Do not book a substantial total-project saving yet. The selected low-level functions overlap existing recovered contracts; the broad game, scene, audio, complete-codec and ownership work remains unadmitted. Future extraction and bridging may cost more than the small amount of native implementation avoided.

A wider EGA/format/host adoption could produce a meaningful saving after additional admission. A conditional matched-workload model is **37–82 engineer-weeks**, versus **41–91** for continued independent implementation using all already-acquired knowledge. That conditional difference is approximately **4–9 engineer-weeks** in the paired low/high workload scenarios. It is an option for future planning, not credit earned by the 2,233-vector sample. Adverse combinations can eliminate the saving.

The model deliberately retains complete original-semantic, resource, gameplay, visual/audio and packaging acceptance. No reduction is allocated to CGA implementation, Amiga recovery, Northern Germany Challenge mapping or live media switching, because upstream supplies no accepted implementation for those requirements.

## What was actually measured

| Observation | Measured value | Valid inference |
| --- | ---: | --- |
| Direct baseline/candidate compilation and linking | 35.585 seconds; 51 C17 compilations, four links, zero warnings | The pinned Windows compiler/SDL inputs build the selected source tree. This excludes earlier setup stalls and human work |
| Representative original-body comparison | 81.974 seconds; 2,233 admitted vectors; 116,990 original instructions; 259 sites | Selected native data/scalar outcomes agree within the declared fixtures |
| Corrected baseline disagreements | 291 admitted cases | Literal-address and scalar-wrap repairs matter. This is not 291 independent defects or a port-wide defect density |
| Live SS aliases | Four explicit excluded mismatches | Native value arguments cannot inherit broader raw SS/frame/FLAGS contracts |
| Admission support | 380 cases, approximately 5.442 seconds | Canonical loader identity/memory, scalar operations, division guards and profile effects pass the selected checks |
| Static admission | 50 unmatched starts and 76 naming conflicts reconciled; 38 behavior dispositions | Addresses and import decisions are usable. They do not establish semantic completeness or hours per function |

Neither the validation runtime nor the compiler runtime measures investigation, debugging, review, adapter design, fixture construction or user acceptance. Human time was not contemporaneously logged by work package, so an observed engineer-day throughput or a statistically calibrated remaining duration cannot be calculated. The earlier proposed 5–10 engineer-day spike was a proposed work budget; it is not an actual cost receipt.

The following numbers are therefore **engineering judgments informed by the spike**, with uncertainty retained. Existing local profile/scalar fixes, inspection tools, admitted images, maps, schemas and previous recovery evidence are available to every route. They are common sunk inputs and are not counted as a saving available only to the reuse route.

## Unit, scope and assumptions

- One engineer-day is eight engineering hours; one engineer-week is five days or 40 hours.
- The starting point is the current P1-05 frontier, with P0 and the bounded P1-01..04/R01..03 milestones already done. No past task is charged again.
- One experienced full-time reverse engineer/developer supplies the effort. Multiple workers may shorten elapsed time for disjoint tasks, but the ordered phase gates and shared-state ownership constrain parallelism. Do not divide the effort mechanically by worker or agent count.
- The admitted DOS and supplied Amiga inputs remain available. Missing optional inputs, hardware/user access and human review queues add elapsed waiting, not engineering effort measured here.
- The requested result retains exact original semantics on supported paths, external original media, Windows plus a second compiler/host portability qualification, EGA/CGA, PC Speaker, Amiga code/resources, Northern Germany Challenge when inputs validate, and same-session independent media switching.
- New format/media/ownership discoveries and product defects may expand work. The baseline ranges include the known open obligations; an additional reserve covers discoveries beyond them.

## Comparable route I: no additional implementation adoption

Route I continues our independent implementation and broad raw-contract recovery. It can use the entire current upstream review, symbol/address knowledge and documentation as search evidence. It retains all local fixes/tools already created during R02/R03. The difference from reuse is source implementation adoption, not an artificial requirement to rediscover known facts or throw away our own adapters.

The work packages below divide the backlog by deliverable rather than count tasks. Shared work appears once. For example, P1-05 owns lifetime/indirect/caller reasoning; P1-11 owns the final EGA integration/gate review rather than repeating that reasoning. Phase 3 integrates already-recovered rules rather than recovering physics again. Phase 5 owns DOS-core extra-scenery integration while phase 4 owns its source identity and normalization specification.

| Phase / remaining work package | Backlog coverage | Low days | High days |
| --- | --- | ---: | ---: |
| EGA state, ownership, actual callers, indirect/mutable domains | P1-05 | 15 | 30 |
| Remaining arithmetic/RNG and mechanics contracts | P1-06, P1-08 | 10 | 25 |
| Remaining timer/input/filesystem platform contracts | P1-07 | 5 | 15 |
| EGA drawing/menu and PC Speaker contracts | P1-09, P1-10 | 10 | 25 |
| EGA integration and requirement-by-requirement gate | P1-11 | 5 | 10 |
| CGA image/remainder, alignment, graphics and P1 gate | P1-12..P1-GATE | 10 | 25 |
| **Remaining phase 1** | | **55** | **130** |
| DOS consumer registry and bounded wrapper/codec admission | P2-01, P2-02 | 5 | 10 |
| Graphics/animation/car/ordered SS data | P2-03, P2-04 | 8 | 16 |
| Route/progression/sign/font data | P2-05, P2-06 | 7 | 14 |
| DOS audio/catalog/selection/score/embedded-media policy | P2-07, P2-08, P2-09 | 5 | 10 |
| Complete-corpus disposition and resource gate | P2-GATE | 5 | 10 |
| **Remaining phase 2** | | **30** | **60** |
| Native portable host/build/input/device lifecycle | P3-01, P3-09 | 8 | 15 |
| External content and profile/save separation | P3-02, P3-08 | 5 | 10 |
| Canonical state/flow/race integration | P3-03, P3-04 | 8 | 15 |
| EGA/CGA presentation and PC Speaker integration | P3-05, P3-06 | 7 | 15 |
| Complete sessions, content/visual/audio/package acceptance | P3-10..P3-GATE | 12 | 20 |
| **Remaining phase 3** | | **40** | **75** |
| Amiga edition/loader/relocations/patches | P4-01..P4-03 | 10 | 25 |
| Amiga C recovery and platform semantics | P4-04 | 15 | 35 |
| Amiga resources, graphics and replay/audio | P4-05..P4-07 | 15 | 35 |
| Content identities and Northern Germany normalization | P4-08..P4-10 | 5 | 15 |
| Amiga recovery validation and gate | P4-11, P4-GATE | 5 | 10 |
| **Remaining phase 4** | | **50** | **120** |
| Semantic interfaces, capability matrix and providers | P5-01, P5-02, P5-04 | 8 | 18 |
| Atomic graphics and independent audio switching | P5-05, P5-06 | 10 | 22 |
| Northern Germany import and complete route gameplay | P5-03, P5-08 | 5 | 15 |
| Combination/failure/device tests, package/docs and gate | P5-07, P5-09, P5-GATE | 7 | 15 |
| **Remaining phase 5** | | **30** | **70** |
| **All remaining work, route I** | | **205** | **455** |

Conversion: `205 / 5 = 41` and `455 / 5 = 91` engineer-weeks. The historical initial 43–98 week table is a different starting point and scope estimate; its endpoints must not be subtracted from this remaining estimate to claim measured progress or savings.

## Comparable route Q: currently qualified selection only

The 11 sampled entries are small compared with the complete code and caller obligations. Several already have independently recovered C implementations. Thus no fresh semantic-recovery credit is assigned to P1-05..11 merely because a second C implementation passes a subset of data observations. The canonical native EXE-reader implementation and already-tested native value APIs may avoid a small amount of future native-host glue. The new locally authored profile/scalar adapters are common assets, not exclusive upstream-code savings.

| Increment relative to route I | Low days | High days | Reason |
| --- | ---: | ---: | --- |
| Gross future native reader/value-API implementation avoided | 2 | 5 | Canonical external EXE loader and small native value entrypoints have usable C candidates; no large-family credit |
| Symbol-level extraction and dependency/closure review | 1 | 3 | Whole `res.c`, `sim.c`, `gfx.c`, `timer.c` and `input.c` files are not admitted by the samples |
| Explicit native data API / broader bus-contract bridge | 1 | 3 | Preserve SS/FLAGS/return/lifetime domains; avoid replacing raw evidence with a narrower interface |
| Provenance/license and fresh rebuild/fixture hookup | 1 | 2 | Pin selected origins/changes and retain notices; future moved code gets fresh evidence |
| **Additional adoption overhead** | **3** | **8** | Incremental reuse work, not the common baseline acceptance budget |

Net future effort change is `overhead - gross credit`: an optimistic `3 - 5 = -2` days (two days saved), or adverse `8 - 2 = +6` days (six extra days). A midpoint planning reserve is about **two extra days**, not a promised saving. The outer arithmetic envelope is `205 - 2 = 203` through `455 + 6 = 461` days, or **40.6–92.2 engineer-weeks**. Use **about 41–93 weeks** at practical whole-week precision; the low endpoint is approximately 41, not mathematical outward rounding or a claim of meaningful measured acceleration.

This is not an argument against the selection. It reduces technical risk, supplies a concrete native candidate, preserves the independent fallback, and positions a later broader adoption. It is an argument against booking the broad port's possible benefit before that port is admitted.

## Conditional expansion: larger EGA, format and host families

This scenario is available only if later contracts, corpus checks and integration evidence admit substantial game/scene, resource-loader and native-host families. They are currently evaluation candidates or rejected families, not qualified imports. It must not be used as the current unconditional budget.

| Family of implementation avoided | Low days | High days | What remains fully budgeted |
| --- | ---: | ---: | --- |
| EGA manual translation and candidate integration | 15 | 35 | Original contracts, ownership/lifetimes, raw ABI and requirement review; all CGA work |
| DOS format discovery/decoder implementation | 10 | 25 | Bounded readers, exceptional inputs, every-file disposition and full-corpus/original comparison |
| Native EGA game/host/render/input/audio scaffolding | 20 | 35 | Canonical state/provider architecture, CGA integration, complete sessions, human visual/audio and package acceptance |
| **Conditional gross implementation credit** | **45** | **95** | No Amiga, scenery or live-switching credit |

The full conditional adoption overhead, inclusive of the small current selection, is **25–50 days**: roughly 10–20 for expanded source admission/remediation, 3–7 for value/bus bridges, 6–13 for the extra coupling/ownership/portability cost introduced by the port's globals, 3–6 for imported-source/media/provenance handling, and 3–4 for incremental build/test integration. These are *extra* reuse costs; the common baseline already contains final architecture, acceptance and package work.

For a matched workload model, allocate the conditional credit/overhead as follows:

| Phase | Route I low/high days | Conditional gross credit low/high | Extra adoption overhead low/high | Conditional remaining low/high days |
| --- | ---: | ---: | ---: | ---: |
| P1 | 55 / 130 | 15 / 35 | 13 / 26 | 53 / 121 |
| P2 | 30 / 60 | 10 / 25 | 5 / 12 | 25 / 47 |
| P3 | 40 / 75 | 20 / 35 | 7 / 12 | 27 / 52 |
| P4 | 50 / 120 | 0 / 0 | 0 / 0 | 50 / 120 |
| P5 | 30 / 70 | 0 / 0 | 0 / 0 | 30 / 70 |
| **Total** | **205 / 455** | **45 / 95** | **25 / 50** | **185 / 410** |

Matched totals are **37–82 engineer-weeks**. The paired implementation saving is `45 - 25 = 20` days for the low-work scenario and `95 - 50 = 45` days for the high-work scenario: **4–9 weeks**, or about 10% of each paired remaining baseline. A midpoint illustration is 330 baseline days minus 70 gross credit plus 37.5 extra adoption days = 297.5 days, about 59.5 weeks instead of 66. This is a sensitivity illustration, not a point forecast.

The low/high cases pair workload and corresponding effort; they are not statistical bounds. Crossing adverse independent assumptions gives `45 - 50 = -5` days: five days of net cost even after attempting wider reuse. The favorable crossed arithmetic gives `95 - 25 = 70` days (14 weeks saved), but that is not a budgetable maximum without demonstrating that broad acceptance is cheap. Retain the independent route for rejected families rather than allowing adoption sunk costs to determine fidelity decisions.

## Reserve, calendar and re-estimation

Keep the historical 25–40% discovery/rework reserve separate from the base table. The currently qualified route's exact 203–461 day envelope gives 50.75–129.08 weeks, or approximately **51–130 engineer-weeks including reserve** at practical planning precision. It is intentionally broad; the known raw-ABI, corpus and full-session obligations are already in the base rows and must not be charged again as reserve. This reserve covers additional discoveries or rework beyond those named rows, not omitted tests.

No release date follows from these numbers. Required gate order is EGA closure, CGA, all DOS resources, native DOS release, Amiga recovery, then switching/scenery integration. After P1-05, P2 corpus admission, a first complete native session and Amiga media/route identity, replace the relevant judgment rows with actual remaining packages and logged effort. Log human investigation, adapter/remediation, fixture construction, review and defect correction separately from machine execution time.

## Input evidence

- [Current backlog](backlog.json), all 67 task records and dependencies.
- [P1-R02/R03 results](../recovery/kylofon-r02-r03-results.md), with linked address/source/build/differential/support receipts.
- [Game review](kylofon-game-core-review.md), [platform review](kylofon-platform-review.md), and [formats/tools review](kylofon-formats-tools-review.md).
- [Historical risks and effort](risks-and-estimates.md), preserved as a different planning baseline.

The numerical work packages and route arithmetic are persisted separately in [effort inputs](evidence/kylofon-effort-inputs-v1.json). No original, reference clone, source, accepted maker/receipt or existing plan file was changed by this review.
