# P1-R04: qualified reuse decision and remaining effort

22 October 2026. **P1-R04 is complete as a source-selection, provenance and planning decision.** Select the tested native value implementations and support adapters below, retain our recovered bus/ABI implementations as the canonical oracle and fallback, and defer the larger unadmitted families. Source extraction/integration remains work in the existing phase tasks; this decision does not replace recovered code or close a recovery/gameplay/fidelity gate.

The normative [reuse register](evidence/kylofon-reuse-decisions-v2.json) defines ten decision groups covering eleven original entries and four support-component groups. The [origin manifest](evidence/kylofon-reuse-origin-manifest-v2.json) pins upstream Git blobs, candidate files, license, local patch and supporting evidence. Upstream remains `352b56824d8c91e938b8f0794a71afca9a276193`; candidate source and build receipts remain unchanged.

## Selected implementations

| Decision | Selected code | Qualification and intended work |
| --- | --- | --- |
| KRU-01 | `rand8`, original `780E` | Native scalar/nonframe-state transformation and serialized consumption, 278 fixtures. Retain seed/reset/writer/history obligations. Candidate for P1-06 and later native state integration |
| KRU-02 | Repaired `bios_ticks` / `bios_ticks_since`, `5D83/5D8D` | Literal physical `086C` read and modulo subtraction, 270 fixtures. Names supply no BIOS/time-unit semantics; host physical `046C` clock is separate. P1-07/native adaptation |
| KRU-03 | Callback-vector setter/getter, `6A17/6A28` | Stable value arguments and stored/getter far words, 256 fixtures. Four overlapping original SS-argument cases remain mismatches and outside this native interface. P1-05/P1-07 caller work and later input integration |
| KRU-04 | `curve_sum`, `drag_apply`, `update_rpm(NULL,NULL)`, `448A/45BF/4612` | Selected memory effects, 725 fixtures. RPM boolean/pointer outputs were not compared. Drag's transitive brake path has gear zero; no general brake or neutral-clutch admission. P1-06/P1-08 and later native gameplay glue |
| KRU-05 | `gfx_set_clip_current` and **RAM branch only** of `gfx_plot`, `5DFB/BA3C` | CS target words and RAM-plane writes, 512 fixtures. Exclude EGA-register/latch/VRAM branch, constructors/full blitters and display fidelity. P1-09 and later provider integration |
| KRU-06 | **Run-only branch** of `rle_decode`, `6B02`, plus the tested `rle_run_pass` dependency | 192 synthetic cases: control 81/83/8B, escape counts 1/3/11, declared fixed source/destination/paragraph values and DS=SS 278F/SP E000. Sequence-first/zero/full-loop/malformed/overlap/corpus paths remain outside selection. P1 raw contract work, then P2 codec admission |
| KRU-07 | Repaired scalar memory access and fixed-view dependencies | 20-bit scalar access, 240 support checks plus actual RAM-plot dependency observations. Direct typed DS/CS lvalues stay within the tested fixed Windows view; generic bulk spans remain unadmitted |
| KRU-08 | Signed division quotient/fault guard with remainder pointer NULL | 77 support checks. No remainder-pointer/alias or original x86 exception-ABI claim. Original runtime diagnostic remains a release blocker |
| KRU-09 | Exact-edition external EXE loader | Canonical 114,421-byte EXE only; admitted image, 1,652 relocations and five explicit passed-state assignments. Other editions/uncompressed MZ/deep malformed-parser behavior remain unadmitted. Select for P3-02, after prior phase gates |
| KRU-10 | Local-derived original/profile path adapter | Tested serialized Windows disjoint-root/basename policy, 51 support checks including actual writes. Explicit profile root only; default preference-directory/UI/device/concurrent race behavior remains untested. Select for P3-02/P3-08 |

The original-body results total **2,233 admitted vectors at eleven entries**, with zero repaired-candidate disagreements. The baseline had **291 disagreeing fixtures exposing two observed semantic classes**: wrong literal address and physical wrapping. They are not 291 distinct defects. The **380 support checks are separate** from original-body comparisons. No tests or builds were rerun for this decision.

All eleven entries already have passed bounded contracts and recovered source in our registry. Their upstream counterparts provide useful native value APIs and an independently compared implementation; **they add zero newly recovered functions** and do not eliminate already-spent recovery work. Main accepted totals remain 215 exports / 292 original entries / 164 suites / 7,132,350 vectors.

## Import and dependency boundaries

This is a symbol/branch selection, not approval to copy complete `res.c`, `sim.c`, `gfx.c`, `timer.c`, `input.c`, `mem.c`, `mem.h` or the port. The selected files also contain excluded behavior or media. The register ties selected source ranges to file hashes; exact fixture generation and candidate DLL/build/validator identities remain pinned through R03 evidence.

Dependency qualification follows actual execution. The selected RLE high-bit branch does not execute `rle_seq_pass`, `paras_of` or `far_move_up`; the instruction fence containing a helper is not proof that it ran. Drag's brake dependency is limited to the tested gear-zero composition. A macro, header or shared source file does not confer acceptance on its other functions. The v2 register explicitly lists `mp`, `wr8`, far-pointer wrappers and `row_at` as observed transitive dependencies only. Required header/type/address declarations remain pinned by the R03 build record; future extraction must establish its own minimal buildable dependency closure and production guards. The v1 draft and consumed maker remain preserved; this clarification admits no additional behavior.

The native caller bridge is defined as follows; this is an integration contract, not a claim that a checked production facade has been implemented:

1. Admit the exact image/relocations and selected source version, then establish owned live state, tables, descriptors and explicit span capacities for the target caller.
2. Retain the existing raw original context API for real SS-frame, GPR/FLAGS, return-target, writer/lifetime and alias observations. Do not narrow it to fit upstream parameters.
3. Materialize native values only where the caller proof permits that projection. Fixed DGROUP/CS and a disjoint original scratch aperture are explicit profile conditions, not a global historical DS=SS fact.
4. Compare only admitted outputs: scalar results for `780E`, `5D83`, `5D8D`, `6A28`, `6B02`; memory effects for the other sampled entries. Discard unqualified RPM boolean/output-pointer behavior. Support quotient/fault tests are not x86 fault-handler proof.
5. Excluded contexts use independent recovery/fallback until new source/build/composition evidence admits them. New callers, extraction, edits or changed dependencies require fresh versions and meaningful comparisons; saved R03 passes do not transfer automatically.

The original comparison excluded the explicit SP-0300-through-caller-frame scratch aperture. Four live-argument alias witnesses remain observed counterexamples. No general raw whole-RAM/ABI, IRQ/device/history, second-host portability or supported-historical-caller claim follows from the native sample.

## Deferred and rejected families

Retain the integrated game/scene, full renderer, format/archive/cache, SDL host and audio code as strong references and candidates for later admission. They receive **no unconditional implementation-saving credit** now. Whole-family qualification must address the source ledger's short-DAT heap tail, inherited cockpit/traffic/collision registers, neutral-clutch events, mutable code, ownership/lifetimes, constructor/LOOP/blitter edges, scheduling and sequencer/PCM issues.

CGA, Amiga recovery, Northern Germany Challenge and live graphics/music/effects switching retain their entire implementation/acceptance obligations. Upstream indexes are useful references rather than native implementations of those features. Required order remains EGA closure, CGA, complete DOS resources, native DOS sessions, Amiga recovery, then live switching/scenery integration.

The exact-edition loader and profile adapter are selected for their later native phase, not a reason to begin that phase early. The full EXE has build evidence only; no menu/game session, pixel output, audio or complete-content acceptance is added here.

## Provenance and distribution

The manifest retains Krzysztof Kania's 2026 MIT notice and exact upstream/candidate LICENSE hashes. Future substantial copies must retain the notice and record local changes. `host_paths.c` is a local-derived adapter whose case-insensitive lookup comes partly from upstream `host.c:498-517`; it is not wholly upstream-free code.

Distribution is still rejected for whole files/the candidate tree: 27 game/runtime text tokens remain blocked, eight identity markers need review, and payload-bearing specification font bytes stay private. The signed-divide helper's terminal diagnostic is one such dependency. Externalize original text/media or use a separately justified media-free presentation adapter before packaging. MIT code notices do not admit original game resources.

## Updated remaining effort

The [bottom-up effort review](../planning/kylofon-effort-review.md) and [machine-readable model](../planning/evidence/kylofon-effort-inputs-v1.json) cover all 54 remaining implementation/acceptance tasks exactly once, excluding this completed decision task. Each route starts **after R02/R03** and shares our admitted images, recovery work, upstream knowledge and already-created local adapters. Past work is neither charged again nor credited as a future saving.

| Route | Remaining effort before reserve | Meaning |
| --- | ---: | --- |
| Independent implementation with current reference knowledge | 205–455 engineer-days / **41–91 weeks** | Comparable remaining-work baseline, including full acceptance and missing features |
| **Selected qualified subset: current budget** | 203–461 days / **about 41–93 weeks** | Only 2–5 days gross future implementation credit, offset by 3–8 days extraction/bridge/provenance cost; net ranges from two days saved to six extra days, midpoint about two extra days |
| Broader game/format/host reuse, **conditional only** | Matched scenarios 185–410 days / **37–82 weeks** | Requires later broad-family admission. Conditional gross credit 45–95 days minus extra adoption cost 25–50 days gives paired 4–9-week savings; adverse combinations can erase the saving |

One engineer-week is five eight-hour engineering days. These are **engineering judgments**, not measured human throughput or calendar promises. Machine measurements—35.585 seconds for direct builds and 81.974 seconds for the representative run—establish reproducibility and sample feasibility, not days per function. The proposed earlier 5–10 engineer-day spike budget was not a recorded actual human cost.

No substantial total-project saving is booked for the current narrow selection. It reduces implementation uncertainty and preserves a future broader-adoption option. The historical 40–65% family sensitivity assumptions are superseded as a current budget by this remaining-work model; they were never a measured full-project saving.

Keep the 25–40% discovery/rework reserve separate: the current 203–461-day envelope becomes 50.75–129.08 engineer-weeks, approximately **51–130 weeks including reserve**. Known raw-ABI/resource/session/portability obligations already appear in the base rows and must not be counted again in reserve. CGA, Amiga, scenery, switching and independent acceptance receive no reuse credit.

Re-estimate after P1-05 caller/lifetime closure, complete DOS corpus admission, a first accepted native session and Amiga media/route mapping. Record actual human investigation, remediation/bridge, fixture/review and defect costs separately from machine execution time. Admit or reject larger families based on evidence before promoting their conditional savings to the budget.

## Persisted decisions and next frontier

The [selection review](kylofon-reuse-selection-review.md), [independent boundary review](kylofon-r04-boundary-review.md) and [final decision review](kylofon-r04-final-review.md) support the normative register. The updated backlog maps selected groups to existing tasks without changing their gates. P1-R04 completes the adoption decision; P1-05 remains the active core frontier, and the saved continuation retains its formatter/terminal/caller/descriptor and unregistered early-exit obligations.

Originals, the frozen reference clone, both R03 source copies, builds, comparison makers and receipts stay unchanged. No source integration, compiler/game/test execution, staging, commit, push or global memory update is part of this decision task. The final custody/metadata audit and decision verification are saved as `p1-kylofon-r04-audit-v1.json` and `kylofon-r04-verification-v1.json` under `docs/recovery/evidence`.
