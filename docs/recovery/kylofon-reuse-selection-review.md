# Kylofon P1-R04 subsystem selection review

22 October 2026. This review selects bounded implementation units from the frozen R03 candidate for future reuse. It neither imports code into the recovered core nor changes original function acceptance. Source paths and line numbers below refer to `analysis/candidates/kylofon-r03-v1/candidate/td2port/src/`, pinned through the R03 build/change receipts. Upstream origin is commit `352b56824d8c91e938b8f0794a71afca9a276193`.

## Selection decision

Select the eleven sampled entry points as **qualified native data-API implementation units**, with the branch and caller restrictions below. Select the repaired scalar accessors, guarded signed division, exact-edition loader and separate profile adapter as **qualified support components for the private Windows candidate**. Retain our existing original-byte/raw-bus implementations as the reference and as the fallback outside those domains.

This is a symbol/branch allowlist. It is not permission to accept `res.c`, `input.c`, `timer.c`, `sim.c`, `gfx.c`, `mem.c` or the complete port wholesale. Those files also contain untested or deliberately changed paths. Moving selected code into an integrated target changes dependencies and callers and therefore requires fresh source/build/composition receipts. Existing R03 DLL acceptance cannot be transferred unchanged to extracted or edited source.

The selected units are useful native integration building blocks. They do not newly close eleven recovery functions: live `functions.json` already records all eleven as bounded `code_contract=passed`, with portable source. The local IDs are FN-EGA-000003, 138, 139, 140, 163, 169, 243, 371, 376, 378 and 414. Reuse should avoid a second translation and aid integration; it must not count already-spent recovery as a future saving.

## Common admitted profile

The R03 comparison uses actual candidate C and independently executed original instructions from the admitted image. Load segment is `1000`, DGROUP is `278F`, and the compared original assembly CS is `16C9`. It observes declared scalar results and first-1MiB memory outside an explicit original scratch aperture. Original SS is either `9000` or `278F`, with SP `E000`, except for four deliberately excluded alias fixtures. C frames do not reproduce original PUSH/CALL/RET stores, GPR/FLAGS or return-word aliases.

The native code requires owned stable `mem[]`, fixed DGROUP/CS views, an initialized external original image and declared table/descriptor spans. Direct typed lvalues are qualified only under the tested Windows x64 little-endian/compiler profile. A scalar wrapping repair does not prove all typed lvalues or contiguous bulk spans. Serialized RAM agreement does not establish IRQ/nesting, hardware A20/timing, all writers, callback lifetimes, initial seeding or supported historical caller reachability.

Four original setter aliases remain demonstrated mismatches: its first store changes the second live SS argument before the original reads it, whereas C receives already-evaluated host values. Therefore a native caller must use materialized value arguments with no reliance on such live frame aliases. Proving that the original game never reached those contexts is still a separate obligation. No global DS=SS invariant is admitted.

## Qualified original-entry units

The passing receipt is [representative validation v1](evidence/kylofon-representative-validation-v1.json), with 2,233 admitted vectors, 116,990 original instructions and 259 exercised instruction sites. Counts below are evidence for the fixture stream, not exhaustive counts of all inputs.

| Unit | Candidate source | Qualification and dependency boundary |
| --- | --- | --- |
| `rand8`, original `06C9:780E` / FN003 | `platform/res.c:1103-1111` | Select the byte-ring primitive. Its 278 fixtures include every low cursor position, 16-bit edges and selected 17-call sequences. Requires the current word cursor at DS66E6 and 256 external mutable bytes at DS66E8; fixed-DGROUP byte/word accessors. This does not select initialization, seeding purpose, reentrancy or whole-game consumption history |
| `bios_ticks`, `bios_ticks_since`, originals `5D83/5D8D` / FN138/139 | `platform/timer.c:208-216` | Select the repaired literal physical086C word and modulo subtraction, with 27 read and 243 subtract fixtures. Depend only on repaired `rd16`. The historical function names do not establish BIOS clock/time units. The host's physical046C clock is separate; do not normalize this operand |
| `kbd_set_getkey_fn`, `kbd_get_getkey_fn`, originals `6A17/6A28` / FN163/414 | `platform/input.c:301-309` | Select raw far-word publication/readback, 128 fixtures each. Depend on `ds_far_wr/ds_far` and wrapped word helpers at DS64DC. Accept materialized value arguments, disjoint original scratch and explicit serialized ownership. Do not select callback execution, target legitimacy, installed handler, IRQ behavior or live-SS alias equivalence |
| `curve_sum`, original `448A` / FN371 | `game/sim.c:360-366` | Select eight signed byte samples at DS335D, sum at DS30E4 and speed snapshot at DS30E6. Its 320 fixtures cover varied signed ring bytes and speed values. Requires fixed-DGROUP views and stable source state; does not select units, road feed/lifetime or a complete simulation tick |
| `drag_apply`, original `45BF` / FN376 | `game/sim.c:442-459` | Select the measured speed/force/drag state update, 162 fixtures with speed/force edges, throttle00/FF and a synthetic drag byte. Requires DS52CE, DS336C and the selected drag-table byte. The FF branch calls `brake` at462-469, then `update_rpm`; R03 sets gear DS2F56=0 for that composition. The transitive neutral brake tail is included only in that profile, not a new standalone/general brake approval |
| `update_rpm`, original `4612` / FN378 | `game/sim.c:472-482` | Select state-only invocation `update_rpm(NULL,NULL)`. The 243 fixtures combine speed/ratio edges and gear00/01/FF, including high products and minimum clamp. Requires DS3328, DS332C, DS52CE and dirty/gear fields. Non-NULL output pointer aliases and preserved CX/DX caller conventions are untested and not selected |
| `gfx_set_clip_current`, original `5DFB` / FN140 | `platform/gfx.c:173-179` | Select four raw clip-word assignments to live CS fields AF46..AF4C, 128 fixtures. This is descriptor state, not raster/clipping-policy or constructor/lifetime acceptance. Requires the CS view and materialized four-word API arguments |
| `gfx_plot`, original `BA3C` / FN243 | `platform/gfx.c:496-500,511-518` | Select **RAM planar branch only**, 384 fixtures. Requires valid current plane/row-table views, `row_at`, external DS68CE bit table and repaired byte accessors. Fixtures use plane0=7000/FFFF, other planes0/7100/7200/7300, arbitrary 16-bit row arithmetic and declared x/y samples. Branch501-509 (`A000` hardware model) and its latch/register helpers are unselected. General plane aliases/overlapping descriptor mutation need new cases |
| `rle_decode`, original `6B02` / FN169 | `platform/res.c:413-421,430-439` with `rle_run_pass:373-409` | Select **bounded run-only branch**, not the complete decoder. The 192 fixtures require original DS=SS278F/SP E000, ec81/83/8B (1/3/11 escape bytes), input8000:0120, destination6000:1234 with actual output beginning6000:0000, total_paras0400, readable20-byte header envelope and disjoint owned buffers/scratch. They exercise literals, zero/short/long run lengths and fixed-repeat ranks. They do not select independent-SS header aliases, ec<=80 sequence-first calls, zero compressed-count/full-LOOP, zero/>11 escapes, overlapping input/output, malformed streams or an external-input parser |

For the codec, `rle_seq_pass` and `far_move_up` are not transitive dependencies of the selected high-bit branch. For a complete `rle_decode` import they would become dependencies and would need separate admission. The selected run branch depends on wrapped scalar byte access and a local zero-initialized 256-entry escape map; the map is algorithm state rather than embedded original media. Future use requires a guard/envelope proving the selected branch and readable/writable bounds before entering it. The R03 dispatcher was a test adapter, not a production bounds checker.

The drag and RPM rows do not select the surrounding `engine`, `decode_controls`, neutral-clutch events, steering, AI, traffic, collision or progression routines. The graphics rows do not select line/rect/sprite/dissolve constructors merely because they share the same file or macros.

## Qualified support components

[Support v2](evidence/kylofon-admission-support-v2.json) passes 380 separate checks. These are not original-body differential vectors and do not enlarge raw function coverage.

| Component | Source and dependencies | Reuse decision |
| --- | --- | --- |
| Physical address/scalar access | `mem.h:32-40`; `lin`, `rd8/16/32`, `wr8/16/32`; `mem[]` and explicit-width types | Select repaired byte-wise 20-bit scalar semantics for the Windows candidate. 240 model checks cover144 reads/96 writes; baseline has35 disagreements across all five tested read/write families. `wr8` is exercised transitively by actual RAM plotting/codec. `mp`, fixed typed lvalue macros46-56 and bulk pointer spans are not automatically portable/wrapped abstractions |
| Signed divide guard | `mem.h:85-91`, `idiv32_16` | Select guard/result logic, supported by77 normal/fault cases. Baseline `INT32_MIN/-1` was deliberately not executed. `div_error` is a terminal/error dependency, not a proved original exception or source-safe release diagnostic; `mem.c:198-202` contains blocked original runtime text. Preserve the terminal contract and externalize/replace that presentation dependency before distribution |
| Exact canonical loader | `mem.c:13-23,43-195`; SDL file/allocation APIs, BCrypt SHA-256, relocation and scalar helpers | Select the exact canonical packed EXE admission path:114421 bytes, admitted SHA-256,130240 image bytes,1652 relocations and five declared passed-state byte assignments. Two canonical native loads match all model RAM and ten altered/truncated/oversized identities reject. Do not select arbitrary EXEPACK, uncompressed MZ, CGA/Tandy or alternate editions. Those paths are outside the hash-admitted input domain, even if compiled. Required original resources remain external; three marker strings and original runtime text still prevent whole-file release approval |
| Original/profile path adapter | `host_paths.c:9-112`; `host.c`/`host.h`/`main.c` hooks; SDL and Windows filesystem APIs | Select this **local-derived Windows adapter** for the declared disjoint-root, basename lookup/create domain. It includes lookup logic derived from upstream `host.c:498-517`; preserve MIT attribution. 51 checks exercise actual synthetic writes, read fallback/override, unsafe names, nested roots and existing hardlink-write denial. It is not a generic portable filesystem layer or proof against concurrent adversarial filesystem races. Quiet `write_file_c` has ambiguous zero on some failures; callers must not treat zero alone as write success |
| Deterministic probe/build plumbing | `probe.c`, direct build maker and test scripts outside candidate source root | Retain as verification infrastructure. Host stubs trap unsupported pump/presentation/filesystem services; `setjmp` fatal trapping is a test mechanism, not the production host/error design. `/W3` C17 build success is not `/W4 /WX` or second-host portability qualification |

The profile adapter does not qualify all `res.c` file formats, score validation or game save semantics. Before integration, keep explicit original read roots, separate user state and content/profile precedence. Before shipping, also review which file classes may legally be overlaid; synthetic `SELECT.DAT` behavior does not prove all data files should load preferentially from a mutable profile.

## Later-phase candidates and rejected imports

Keep the following as strong references or future scaffolding candidates, with **no current behavior acceptance**:

- The integrated game/scene/renderer/resource flow can reduce repeated translation and provide call/data relationships, but its large untested families retain the source-deviation ledger. Qualify one caller/composition family at a time under P1-05..P1-11.
- DOS decoder/schema tools can guide phase2 after the phase1 gate. Admit the complete supplied corpus and parser bounds before choosing a complete loader; run-only192 cases do not substitute for that work.
- The SDL window, input/gamepad and audio transport can be adapted during phase3 after DOS source/resource gates. The full executable has only build evidence. No menu/session, device lifecycle, draw timing or audible output was exercised.

Reject direct import of the remaining known-conflict families for now: short-DAT zero fill and heap-tail assumptions; inherited CH/SI/BP/DI/CX/DX semantics in cockpit/traffic/collision/neutral clutch; buffer constructor wrapping/allocation/terminal paths; general graphics blitters/latches; complete sequencers/PCM timing; synthetic-stack substitutions for raw aliases; full mutable-code/ownership/lifetime claims. The admission source record lists38 per-site dispositions and the existing project gap register keeps the broader obligations visible.

CGA, Amiga resources/code, Northern Germany Challenge and independent live provider switching remain unimplemented requirements. Upstream function indexes do not supply those native features. No savings credit is earned for them by this selection.

## Provenance and import manifest requirements

Each later extraction/import must identify:

1. Original repository URL, exact commit, upstream Git blob/file SHA-256, file and selected function/branch span; candidate file/span hashes and private patch hash.
2. Whether it is unchanged upstream code, modified upstream code, a local-derived adapter or an independently authored verification component. `host_paths.c` must retain its lookup derivation; it is not wholly independent source.
3. Original entry/FN mapping, selected native observable contract, required data/offsets, dependency closure, excluded branches and the exact R03 evidence. Macros such as `DSW` are address/access dependencies, not admission of every symbol in `symbols.h`.
4. Retained `LICENSE` and Krzysztof Kania's2026 MIT notice for copied substantial source; additional local change notes without rewriting upstream attribution. The notice covers repository code/documentation and excludes original game data. This inspection does not guarantee provenance of embedded game prose/tables.
5. Media disposition: no game/runtime strings, font dumps, payload-bearing specs, sprites, roads, audio or original binary-derived resource arrays in the distributed source/package. Twenty-seven text tokens remain blocked, eight markers need review, and public original-offset metadata is not permission to copy the bytes.
6. The fresh build and integration/composition acceptance record after extraction/adaptation. Keep the R03 frozen source/DLLs and our existing raw oracle intact; do not overwrite them and claim inherited acceptance.

## Implication for effort estimates

The measured evidence is35.585 seconds of direct compile/link work and81.974 seconds of representative test execution, plus the exact candidate disagreement/debugging classes and preserved setup/refinement attempts. It proves build/test feasibility for this sample. Neither duration measures developer throughput, elapsed engineering days, full-game correctness or a percentage of future effort saved.

All eleven sampled entries already have local bounded contracts and source, so immediate savings should be budgeted as reduced duplicate translation/native integration effort, not removal of eleven pending recovery functions. The larger possible saving lies in the unadmitted integrated game/resource/rendering source; retain that as a conditional upside, with cost assigned to caller qualification, parser/media repairs, ownership/architecture work and independent acceptance. Do not mechanically apply the initial40-65% family assumptions to the entire remaining project.

A defensible estimate should show a current remaining-work baseline, the selected-unit implementation credit, added adaptation/composition work, unchanged validation and missing-feature work, and a separate conditional broader-reuse scenario. Savings and new-work terms must not be double counted. Until the integrated families are admitted, the conservative plan retains independent reconstruction as the fallback, budgets no savings for CGA/Amiga/switching and keeps all acceptance effort.

No compiler, test, old maker, original executable or game was run by this selection review. Only the two new review artifacts were written; candidate/reference/source/build/receipt files were read without modification.
