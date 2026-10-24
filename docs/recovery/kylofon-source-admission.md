# Kylofon source, data and behavior admission

22 October 2026. Frozen upstream commit: `352b56824d8c91e938b8f0794a71afca9a276193`. Scope: P1-R02 source and embedded-data admission decisions supporting P1-R03 representative testing. The reference clone and original media were read only. No existing recovered source, function status, accepted receipt or phase gate is changed by this report.

The complete machine inventory is [kylofon-source-admission-v1.json](evidence/kylofon-source-admission-v1.json). Its maker is `tools/review_kylofon_admission_v1.py`; the receipt pins the exact maker, every inspected source file, function registry and admitted original image. Candidate patches, compilation and differential outcomes belong to the separate P1-R03 receipts; this static record does not claim those outcomes.

## Admission decision

**Private candidate compilation and bounded representative testing are admitted. General replacement of our recovered implementations and distribution are rejected at this point.** The tests must name the routine, inputs, original image/code state, caller assumptions and observables. A passing scalar/native test cannot inherit our raw SS-frame, register, FLAGS, return-control or whole-RAM guarantees unless it actually compares them.

Fixed DGROUP and synthetic C locals are an implementation profile, not proof that all original callers had DS=SS or disjoint stacks. Use DS=SS only in the specific sample profile that declares it; retain the existing independent-DS/SS bus oracle unchanged. Other samples may bridge through our accepted raw APIs with explicit observable projection. Exclude actual stack aliases, overwritten return words, IRQ nesting, mutable-code transitions, all-writer/reset/lifetime closure and host/device timing until independently admitted.

The normal native profile must establish owned stable memory, exact admitted EXE/image and relocation state, supported data spans, valid callback targets and disjoint scratch. Memory accessors that wrap at 20 bits do not automatically fix direct typed DS lvalues. Windows little-endian x64 compilation is not second-host portability proof. A synthetic resource fixture is not evidence that all supplied files satisfy the fixture's constraints.

## Complete string and initializer inventory

The generator lexically scans **all 41 `.c`/`.h` files**, including inactive preprocessing branches. It counts actual C string tokens, including quoted include names, while excluding strings appearing only in comments and character literals. Adjacent string tokens receive individual records. Each record contains source offset/line, token and decoded hashes, classification, original-image exact-match offsets where meaningful, nearby original DS-comment locators and a distribution decision. No original text bytes appear in this public inventory.

| C string classification | Occurrences | Treatment |
| --- | ---: | --- |
| Quoted include identifiers | 115 | Build dependency metadata |
| Build diagnostics | 2 | Host/build code |
| Algorithm/resource identifiers | 13 | File modes, selectors, extensions and code metadata |
| Host diagnostics/formats | 23 | Native adapter error paths, separately from original resource text |
| Formatting/path syntax | 15 | Structural syntax without original prose |
| Host CLI, path, environment and title identifiers | 17 | Host interface metadata |
| Host keyboard shift mapping string | 1 | Hardware adapter mapping |
| Original/adapted game-display formats | 26 | **Blocked for distribution; load original text externally or explicitly replace under product policy** |
| Original runtime message | 1 | **Blocked for distribution; externalize or explicitly replace** |
| External EXE identity/signature markers | 8 | Review before distribution; pin exact input identity rather than treating English marker text as permitted game media |
| **Total** | **221** | Every occurrence has a locator and decision |

The 26 game-display formats are in `game/flow_stage.c`, `game/flow_scores.c` and `game/flow_screens.c:446`. The last is a rendered scenery disk label with an exact admitted-image match, discovered during this admission pass. Original DS-comment locators and exact string matches are clues of different strength: a modified printf format may not be byte-identical to the original format but still carries original game prose. No such token is automatically accepted because upstream code uses an MIT license.

The initializer pass covers explicit named arrays, constant aggregate descriptors and implicit-zero static/global arrays. It also includes local initialized arrays so scratch buffers cannot escape accounting. There are **26 records**, with **no unclassified initializer**:

| Initializer family | Records | Classification |
| --- | ---: | --- |
| Implicit-zero memory, dispatch, framebuffer, keyboard and silence state | 5 | Mutable/zero state; no copied game payload |
| Original DS/CS address maps and release order | 7 | Algorithm/address mapping; external media remains external |
| Front/mirror view constants and field maps | 2 | Algorithm constants and original address mappings; not sprite/route bytes |
| XT/ASCII host key maps | 4 | Host hardware adapter |
| EXEPACK identity marker string array | 1 | Loader marker; duplicate role is explicitly accounted in string inventory |
| Standard mode0D hardware default palette | 1 | BIOS hardware default; does not admit arbitrary game palettes |
| EGA raster-operation selectors | 1 | Hardware operation constants |
| Blitter control flags | 1 | Algorithm controls |
| Explicit-zero local scratch | 4 | Decoder/directory/name scratch initialized without payload |

`port/spec/platform.md:1280-1297` contains original font hex in the private reference documentation. It is outside the compiled C inventory, remains blocked from distribution, and is not copied into this report/evidence. Future imported documentation and generated headers require the same media check. The current inventory finds text blockers; it does not authorize shipping the frozen reference repository or claim a completed package audit.

## Per-site deviation decisions

The JSON records all 38 sites with pinned source lines, selected-line hashes, relevant original entry addresses, original function IDs and current original code-contract status. Original locators identify the affected body, not independent acceptance of every source annotation. Missing exact-entry IDs remain explicitly missing rather than being fabricated. Source paths below are relative to upstream `td2port/src/`.

| IDs | Site | Selected treatment and remaining boundary |
| --- | --- | --- |
| KAD-01 | `platform/timer.c:207-216`, original `06C9:5D83/5D8D` | Fix candidate to literal `0040:046C` physical `086C` and modulo subtraction. Host BIOS clock physical `046C` remains a separate object; no timing units inferred |
| KAD-02, 06, 07 | `mem.h:10-13`, `platform/input.c:291-297`, `platform/res.c:1116-1135` | Restrict native-value tests; reject global DS/SS, actual-stack and independent-SS equivalence. Raw bus contracts remain authoritative |
| KAD-03, 04 | `mem.h:17-54` | Fix scalar byte accessors or constrain domain; direct typed lvalues remain little-endian/alignment and alias obligations |
| KAD-05 | `mem.h:82-90` | Guard `INT32_MIN / -1` before evaluating C division; zero/quotient-overflow terminal behavior stays explicit |
| KAD-08 | `platform/res.c:302-331`, original `06C9:7866/7874` | Separate writable profile from original lookup or disable I/O in pure-memory samples |
| KAD-09 | `mem.c:26-148` | Harden and pin loader/image/relocations or bypass with an explicitly pinned validated image for a sample; no loader credit from a bypass |
| KAD-10 | `mem.c:158-168` and mutable original entry family | Retain declared passed-state native policy; keep other initial/prepared states and removed protection/runtime paths unadmitted |
| KAD-11, 12 | `game/flow.c:253-263,581-584` | Retain external-file disk and native install adaptations; do not call omitted original paths ported or recovered |
| KAD-13 | `game/flow_stage.c:518-529`, original `0267:16C1` | Reject full stage-loader import until the fixed 7,774-byte copy and short-file heap-tail consumers/lifetimes are proved; no authentic-zero assumption |
| KAD-14, 15 | `game/scene_project.c:388-406`, `game/scene_draw.c:121-140` | Restore selected raw helper or exclude it; full zero/wrapped LOOP domains are not empty spans. Keep existing raw clamp evidence |
| KAD-16, 17 | `game/scene_cockpit.c:207-210,251-260` | Reject steering/instrument subsystem admission pending inherited CH/SI and actual caller/car-field evidence |
| KAD-18 | `game/sim.c:265-273`, original `06C9:4281/4441` | Reject neutral-clutch event fidelity pending inherited CX/DX; unrelated simulation samples do not close it |
| KAD-19 | `game/sim_motion.c:436-439`, original `06C9:4C85` | Reject billboard collision admission until stale BP or a valid bounded native domain is established |
| KAD-20, 21 | `game/sim_traffic.c:360-374,241-247` | Reject inferred DI/CX traffic contracts pending actual caller evidence; preserve full LOOP domains |
| KAD-22 | `game/sim_ai.c:447-451`, original `06C9:56ED` | Retain a declared bounded safety fallback for unsupported police states; no original out-of-table target proof |
| KAD-23, 24 | `game/flow.h:22`, `game/flow_screens.c:237-317` | Treat catalog/frame caps as native safety policies. Valid frame-list and supplied-corpus admission remain separate |
| KAD-25 | `game/flow_scores.c:27-43` | Require complete record-length checking before I/O admission. The bounded read discards actual `fread` count and is insufficient alone |
| KAD-26, 27, 28 | `game/flow.c:184-201`, `game/scene.c:411`, `game/scene_cockpit.c:169-170` | Separate paced/synchronous native presentation from original scheduling/interleavings; reject gate-delay timing admission pending schedule evidence |
| KAD-29 | `platform/timer.c:275-305` | Retain documented host wait adaptation; compare original high/low disjunctive rollover rule separately |
| KAD-30 | `platform/sound.c:54-406` | Reject audio fidelity admission; register/gate/sequencer events, tick-quantized PCM and VOICES heap adjacency are different obligations |
| KAD-31 | `platform/res.c:335-540` | Compare synthetic codec fixtures only within explicit capacity/count domains; raw zero-lowword effects and safe external parser remain distinct |
| KAD-32 | `platform/gfx.c:207-260`, original `06C9:B0FE` | Reject constructor admission; wrapped capacity arithmetic, height-zero LOOP, allocation order and terminal fallthrough remain open |
| KAD-33 | `platform/gfx_blit.c:185-477` | Restrict primitive samples to declared descriptor/dimension/plane domains; no inherited full blitter/latch/overlap/alias credit |
| KAD-34, 35, 38 | Game result/score/scenery text sites above | Block distribution until externally sourced or explicitly replaced; private compilation is not a media gate |
| KAD-36 | `game/flow_stage.c:246-321` | Reject unbounded arithmetic admission; signed 32-bit products/shifts need defined operations or proven state bounds |
| KAD-37 | `platform/input.c:81-150` | Retain host device adapter; pure-memory keyboard tests do not prove IRQ acknowledge/EOI, nesting, vector ownership or lifetime |

The source/spec disagreements in the prior reviews also remain attached to these decisions: the anomaly-reader BIOS-clock label is wrong for the admitted instructions; global Ghidra DS pinning must not touch accepted projects; the failed-tail low-memory write is physical `0086`, not an INT19 vector; callback frequency is distinct from simulation frequency. The address/symbol admission record separately resolves naming and boundary correspondence without importing these labels as facts.

## Reproducibility and preserved attempts

The executed generator first produced two preliminary inventories. Before acceptance, review caught that comment/string masking let whitespace consume string-initialized arrays and that an implicit-zero declaration search also counted two array references. Those were repaired. A rendered scenery disk-label match was then promoted from generic review to the distribution-blocked game-format class. The preliminary receipts and exact executed makers are preserved privately under `analysis/reviews/kylofon-source-admission-preliminary-v1.json` / `preliminary-maker-v1.py` and `preliminary-v2.json` / `preliminary-maker-v2.py`. Maker hashes were checked before archiving. The final public v1 is the corrected source inventory.

A lexical smoke check separately confirmed escaped quotes remain one token, comments do not contribute strings, and source length/newline positions survive masking. Every current tracked upstream file was checked against its saved SHA-256 before the inventory was emitted. No source bytes or original resources were written, decoded or executed by this maker.

The result resolves how each known source conflict is treated for this admission attempt. It does not resolve rejected original caller/register/resource lifetimes by assertion, nor admit their subsystems into a product. P1-R03 representative passing results and P1-R04 subsystem adoption must retain these exclusions and any later evidence that narrows them.

## Native admission-support validation

The finalized private DLLs from [candidate build v1](evidence/kylofon-candidate-build-v1.json) were exercised by `tools/validate_kylofon_admission_support_v1.py`. The selected [support receipt v2](evidence/kylofon-admission-support-v2.json) passes **380 support cases**. These are infrastructure checks and are deliberately separate from original-instruction differential vector totals:

| Support family | Cases | Observed result |
| --- | ---: | --- |
| Canonical EXE loading | 2 | Baseline and candidate each match every byte of the independently admitted 130,240-byte image after 1,652 admitted relocations and exactly five recorded passed-state byte changes; full 1,114,112-byte native memory matches the expected image/zero state |
| Unsupported EXE rejection | 10 | Empty, truncated, altered-header/body/tail and oversized private copies are rejected before changing loaded memory; exact identity rejection is tested, not every deeper parser branch |
| Scalar 20-bit byte-address model | 240 | 144 reads and 96 writes compare independent byte addressing and whole memory; candidate passes. Baseline has 20 read and 15 write disagreements, with a discriminator in all five accessor families |
| Signed division guard | 77 | 45 normal quotient and 32 fault cases match independent integer arithmetic. Baseline `INT32_MIN / -1` is deliberately never executed; candidate rejects it safely |
| Profile/file custody | 51 | Actual synthetic profile write, read-only original fallback, profile override/case lookup, missing reads, disjoint roots, Win32 filename restrictions, directories and hardlink writes behave as declared; two synthetic original files retain content, timestamps and attributes |

The quiet original-style file writer returns zero on both success and error. A rejected hardlink write is therefore established through rejected create-path resolution and unchanged file bytes/metadata, not a fabricated error return. Hardlink reads remain permitted as read-only operations. Existing hardlinks and checked path roots do not prove immunity to adversarial concurrent filesystem replacement; that race remains outside the admitted private fixture domain.

The first [support receipt v1](evidence/kylofon-admission-support-v1.json) is retained. Review found its initial memory pattern repeated every 64 KiB: whole-memory writes exposed wrapping disagreements, but high-address reads were not discriminating. V2 mixes higher address bits and requires baseline disagreement for every scalar accessor family. Each attempt preserves its exact executed maker in `analysis/candidates/kylofon-r03-v1/support-attempt-v1/` or `support-attempt-v2/`; both archived maker hashes match their receipts. No DLL or C source changed between these support attempts.

These support results establish neither original stack/register/FLAGS equivalence nor full parser hardening, a complete session, physical device behavior, graphics/audio fidelity or distribution readiness. They strengthen the bounded source-admission decisions above without closing the explicitly rejected families.
