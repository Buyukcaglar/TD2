# Kylofon SDL3 reference review and adoption decision

Subsequent checkpoint: [P1-R02/R03 results](../recovery/kylofon-r02-r03-results.md) now record bounded address/source admission, private baseline/candidate C17 builds, 2,233 passing original-body comparisons and 380 support checks. Four live-SS aliases remain excluded; P1-R04 and broader gates remain pending. The initial assessment below is preserved as historical evidence, including its then-unbuilt status and conditional savings assumptions.

Assessment date: 22 October 2026. Upstream: [kylofon/test-drive-2-sdl3](https://github.com/kylofon/test-drive-2-sdl3), commit `352b56824d8c91e938b8f0794a71afca9a276193` (18 September 2026). This is a source review and development-plan revision. Upstream's playability/fidelity statements are author claims; no upstream compilation, game execution, complete corpus decode, visual or audio acceptance was performed here.

## Recommendation

Use this repository as the preferred candidate implementation for EGA game integration and DOS format recovery, subject to our original-byte validation. Preserve our recovered functions, differential harnesses and evidence as the independent oracle. A qualified fork could save substantial implementation work. Importing its current HEAD wholesale would also import changed behavior, data writes and assumptions that conflict with our requirements.

This assessment selects an evidence-led adoption path in the plan; it does not merge source or change a phase gate to complete. EGA contracts still precede CGA, full DOS resource closure, native gameplay, Amiga recovery and live switching. We can replace repeated manual translation with reviewing and testing existing candidate C. We cannot treat the reverse-engineering acceptance work as finished simply because candidate source exists.

## Snapshot and inspection coverage

The complete Git repository was cloned to `reference/repos/kylofon-test-drive-2-sdl3`, with all history, normal Git blob bytes (`core.autocrlf=false`) and no submodule dependency. Its 85 tracked files were inventoried and assigned across three complete reviews. Every tracked working file matches its Git blob. All 113 clone files, including Git metadata, have Windows ReadOnly set; the local push URL is disabled. These attributes guard accidental writes and are not an ACL security boundary. Do not fetch, pull, edit, build or run from the reference clone. A future build or fork must use a separate writable workspace and out-of-source outputs.

- [Complete snapshot and per-file hashes/review ownership](evidence/kylofon-reference-snapshot-v1.json)
- [Game, simulation and rendering source review](kylofon-game-core-review.md)
- [Platform, host, resource runtime and build review](kylofon-platform-review.md)
- [Formats, tooling, symbols and all generated indexes](kylofon-formats-tools-review.md)
- [Static compatibility checks and complete address crosswalk](evidence/kylofon-static-crosscheck-v1.json)
- [Original-media and external-reference custody check](evidence/kylofon-reference-custody-v1.json)
- [Actionable gap register](evidence/kylofon-gap-register-v1.json)

The clone is ignored by the parent repository's existing `/reference/` exclusion. The 250-original manifest is unchanged. `external-repositories.json` admits the exact clone inventory separately; the verifier still fails on unknown files anywhere under `reference`, including additions inside the clone. It checks original content plus frozen clone content, modification times, attributes and missing files. Original metadata is additionally compared with the existing custody baseline. Eleven synthetic regression cases verify that the new handling does not hide changed originals, changed/missing clone files, unexpected files or escaping paths, and that inspection outputs cannot write into the reference tree.

## Our actual starting point

The accepted checkpoint remains [report-parent audit](../recovery/evidence/p1-runtime-report-bus-audit-v1.json): 215 native exports, 292 unique original entries, 164 comparison suites and 7,132,350 isolated vectors; 440 function candidates with 293 passed bounded code contracts and 147 pending. There are 305 resource records: 249 DOS identities and 56 embedded raw views. These records are not complete format acceptance or a playable core.

The separately compiled/compared early-exit packet is still unregistered. This review does not promote its expected 216/293 totals, consume its registration writers, rerun old makers, or overwrite accepted source/build/validation receipts. The new review tasks change planning task counts only. The [static crosscheck](evidence/kylofon-static-crosscheck-v1.json) preserves hashes of the function registry and every existing recovered source/header at inspection for later integrity checking.

Compared with our work, upstream supplies the integrated C implementation we lack: startup/menu/selection flow, scene loading, driving and progression, scoring, road/object/cockpit rendering, resource and sprite loading, keyboard/gamepad input, speaker synthesis and an SDL host. Our strength is independently pinned original-image provenance and much deeper instruction/ABI/alias/FLAGS evidence. Combining those strengths is more useful than discarding either side.

## Compatibility and what it proves

Our independently validated image is 130,240 bytes, SHA-256 `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4`, with 1,652 relocations. Upstream expects `0x1FCC0` bytes and DGROUP `178F`. All three string markers used by its native loader match our admitted image at the specified offsets. Its EGA index uses the same unrelocated segmented entry address `13A8:03F8` and DGROUP.

Exact segmented primary starts match for 417 of our 440 candidates and upstream's 444 candidates. There are 27 upstream-only and 23 local-only starts. The JSON crosswalk enumerates every match and difference. These are boundary/reachability investigation inputs; neither count is a completeness measure. Upstream publishes neither an input-image hash nor retained differential receipts proving its index/port was accepted against our exact original bytes. Loader-marker compatibility is strong evidence for applicability and weaker than full image identity.

Its CGA and Tandy indexes contain 440 and 442 candidates respectively. Those are analysis artifacts; the executable port is EGA only. They can guide later alignment without closing CGA code, pixel packing, palettes, timing or `.PCS` handling.

## Confirmed gaps and required tightening

The three reviews supply detailed file/line locators. The machine register links each issue to tasks and an acceptance condition. The principal issues are:

| Issue | Verified source observation | Required treatment |
| --- | --- | --- |
| Literal low-memory read | Upstream `platform/timer.c:207-216`, specs and symbols use `0040:006C`; our original `06C9:5D83/5D8D` reads `0040:046C`, physical `086C` | Keep our literal contract. Prove real caller use and any intentional host adaptation separately; do not rename the original operand a BIOS tick |
| Memory and caller model | `mem.h` fixes DGROUP/SS, retains host little-endian lvalue casts and a `0x110000` buffer without 20-bit wrapping | Admit actual caller domains or bridge to our bus model. Preserve raw alias/FLAGS/return contracts in the reference layer; qualify any narrower native layer |
| Scheduling | Host-paced drawing, timer callbacks, deterministic `780E` call counts and the simulation divisor are integrated using port policies | Compare tick/event/RNG sequences and rendering interactions. Callback frequency is not automatically simulation frequency or physical timing |
| Persistence | Selection and score writes target the selected game directory | Separate immutable originals from user-profile state before any native integration; read originals only and support writable overlays |
| Edition/input validation | Loader uses size and three strings; relocations may be skipped and malformed-input bounds are incomplete | Verify admitted input identities, full unpack/relocation disposition, parser limits and atomic content loading |
| Explicit behavior changes | Protection/disk/install paths are removed; short DAT copies are zero filled; several loop/division/AI/cockpit assumptions differ or remain TODO | Maintain a per-site deviation ledger. Verify supported historical callers; product policy does not retroactively prove original semantics |
| Embedded resource custody | Some game-result text is compiled into C; specs contain original font bytes; code tables also need classification | Keep reference docs private. Classify tables/text and move required original media to external EXE/data reads before release |
| Format confidence | Rich DOS schemas/decoders exist, but no retained all-file corpus receipts; sprite count prose is internally inconsistent | Treat them as candidate specifications. Crosscheck consumers and every supplied file, including exceptional CAMA, VOICES, PCS and short DAT cases |
| Portable core | C11 SDL-required executable uses shared memory globals rather than the planned host-independent C17 state API | Establish a headless C17 target, defined arithmetic/accessors and explicit state/provider boundaries before claiming portability |
| Missing requested features | No CGA native renderer, Amiga recovery, Northern Germany Challenge importer or live provider switching | Retain those tasks and dependencies; EGA reuse gives no acceptance credit for them |
| Verification | `--check` only loads the EGA EXE; no test target or retained original-oracle test suite is present | Transfer our meaningful differential fixtures, then validate complete sessions and human visuals/audio at the authorized later gates |

Our own plan needed tightening as well. Before this review it treated many already-implemented algorithms as entirely undiscovered future work, did not list a reusable EGA integration candidate, and used a verifier that would reject the requested reference clone. Those planning/custody gaps are now repaired. Existing recovery contracts were not weakened to match the port.

## Adoption options

| Route | Benefit | Cost and recommendation |
| --- | --- | --- |
| Continue independent reconstruction; read upstream only | Immediate names, algorithms, formats and cross-platform alignment leads; preserves our current architecture | Lowest integration risk but repeats much of upstream's translation/integration. Keep as fallback if candidate validation fails |
| Selectively adopt implementation, then fork host/game integration | Reuses broad game/renderer/loader source while retaining our oracle, metadata and exact contracts | Preferred. Validate representative subsystems first, maintain provenance and deviation records, then import by subsystem in its authorized phase |
| Replace our project with upstream HEAD or fast-forward Git | Earliest access to an author-reported playable EGA program | Not a Git fast-forward: histories and structures differ. Also fails our custody, evidence, CGA/Amiga/switching and fidelity requirements. Do not replace the current tree |

Upstream labels its port and tools MIT and includes Krzysztof Kania's 2026 notice. Any imported code/documentation must retain the relevant notice/license and a pinned origin/change manifest. The notice excludes original game/data rights; its final footer also names the 1987 first game. Preserve the notice verbatim and record the discrepancy rather than treating it as permission to ship original resources. Keep our independently authored work and contributed upstream files identifiable. This source-license inspection is not a provenance guarantee for every embedded table or game string.

## Development sequence and decision gates

1. **P1-R01, complete:** freeze clone, cover every tracked file, static crosswalk, original custody, gap register and this decision. No candidate source is accepted into the runtime.
2. **P1-R02:** admit candidate addresses/ranges against the exact EGA image and reconcile all 50 unmatched starts; build a source-to-original crosswalk and per-site deviation/data-constant register. Resolve low-memory-read and memory-domain conflicts first. Do not rename/register candidates solely from upstream names.
3. **P1-R03:** in a separate writable workspace, build the candidate under pinned C17/SDL/compiler inputs and adapt representative original-byte differential checks: byte-ring/RNG consumers; codec synthetic inputs; timer/input/SS behavior; one simulation slice; one EGA primitive. No whole-core acceptance follows from this sample. Compare logic before changing integration architecture. Preserve a source-only outcome if the local dependencies are unavailable.
4. **P1-R04:** choose qualified subsystem imports using measured mismatch/debugging cost. Record accepted caller domains, intentional changes, origins, independent evidence and remaining obligations. Retain the independent route for failed families. P1-05 through P1-11 still close all supported EGA semantics; P1-12 through P1-14 still follow for CGA.
5. **Phase 2:** adapt admitted format logic to bounded read-only loaders. Account for all 249 DOS files and every EXE-embedded range. Use upstream tools as inspected candidates, not uncontrolled extraction commands. Resolve both PCS families, CAMA's extra 49 bytes, ordered `.SS` labels, sign/font exceptions, VOICES adjacency and route-tail behavior.
6. **Phase 3:** fork/adapt the validated host/game/renderer source; separate original reads from profile writes; externalize media; add host-independent state/scheduling/provider interfaces; validate all admitted content and packaging. A build or `--check` alone cannot finish P3.
7. **Phases 4/5:** preserve the existing Amiga recovery, extra-scenery mapping and independent graphics/music/effects switching requirements. Global upstream memory access can be a temporary compatibility representation; it cannot silently become a second simulation when providers switch.

The required ordering remains in [roadmap](roadmap.md) and [backlog](backlog.json). The adoption tasks are prerequisites to accepting imported EGA code, rather than a parallel route around CGA/resource/native acceptance.

## Time-saving assessment

**Substantial savings are plausible for DOS EGA translation, DOS format discovery and first native integration. They are not yet measured.** The native implementation and detailed specifications already exist, so much of that work can become validation and adaptation. The review also found enough semantic and custody differences that a claim of immediate post-RE readiness would be unsupported.

For planning, use the following sensitivity model on the *remaining candidate-covered work*, not on the entire project or on effort already spent. This avoids pretending that the original broad baseline estimates are current measured remaining estimates:

| Remaining work family | Conditional reduction in effort | Assumption |
| --- | ---: | --- |
| EGA translation, naming and game integration covered by upstream | 40–65% | Most representative candidate code agrees and reconciliation costs less than rewriting |
| DOS format discovery/decoder implementation | 35–60% | Consumer/format leads apply across the complete supplied corpus |
| Native EGA host/renderer/input/audio scaffolding | 40–65% | Read-only/profile changes, media externalization and C17 portability remain bounded |
| CGA renderer, Amiga recovery/content, live switching | No reduction budgeted | Upstream has no implementation satisfying these requirements |
| Original differential, complete-content, visual/audio and packaging acceptance | No reduction budgeted | Independent verification remains required |

These percentages are engineering assumptions, not benchmark results or promised savings. Example: if 100 remaining effort units consist of 50 candidate-covered implementation units and 50 unaffected validation/feature units, a 50% reduction of covered work saves 25 units overall, before any additional integration overhead. Different work weights can produce much smaller savings. Do not report a percentage of the full project completed from the 417 matched starts.

Timebox P1-R02/R03 discovery and representative adaptation to **5–10 engineer-days** before committing to a large import. That is a proposed future work budget, not time already spent or an authorization to bypass gates. Record actual compiler/setup time, candidate sites compared, divergences, fixes and fixture/debugging effort. Re-estimate the remaining work by subsystem after that spike; keep existing broad phase estimates historical until those measurements exist. There is no verified calendar acceleration claim yet.

## Validation and remaining limits

This review validates static compatibility, full tracked-file inventory, frozen clone integrity, original custody, planning/dependency consistency and the new verifier behavior. The complete source reviews distinguish observed code, author assertions, changed semantics and open questions. Existing original-byte comparison receipts are retained; this turn does not rerun them or establish a new runtime checkpoint.

MSVC is present for our existing helpers; CMake exists inside Visual Studio but was not on PATH, and the expected MSYS2 SDL3/toolchain installation was absent. This review did not install dependencies or compile upstream. Consequently upstream's advertised playable status has not been independently exercised here. Original instruction contracts, compilation, isolated comparisons, complete sessions, original visuals/audio and fidelity remain separate gates.

The first full review audit correctly rejected a Git optional index refresh: `.git/index` retained its exact content hash but its timestamp and ReadOnly flag changed. Its pinned metadata was restored without rewriting content; the [repair record](evidence/kylofon-index-metadata-repair-v1.json) and failed v1 audit are retained. Use `git --no-optional-locks` for all further frozen-clone inspection.

The final review audit is recorded at `docs/recovery/evidence/p1-kylofon-reference-review-audit-v2.json`. The [continuation record](continuation.md) preserves the unfinished early-exit work and adds the adoption frontier. No staging, commit, push, source merge, original game execution, CGA implementation or Amiga recovery was performed in this review.
