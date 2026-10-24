# Kylofon SDL3 port: game, simulation and scene source review

Review date: 2026-10-22 (Europe/Istanbul). Reference: `reference/repos/kylofon-test-drive-2-sdl3`, commit `352b56824d8c91e938b8f0794a71afca9a276193`. All upstream locators below are relative to that pinned checkout. The checkout was read as reference; this review changes no upstream source, recovered source, accepted receipt or function status. No game session, compilation, pixel/audio comparison or source-to-instruction differential run was performed by this reviewer.

## Assessment

The upstream game layer is a substantial implementation asset: it already expresses the startup/intro/menu/selection cycle, the complete stage/result/high-score loop, the front and mirror road renderer, cockpit, vehicle/input/gearbox model, opponent, police, traffic and collision paths as native C. This can replace a large amount of discovery and initial translation work after its assumptions are admitted and tested. Reusing it as a product integration base is technically plausible. It is not evidence that our P1 gate, all-resource gate or original-fidelity gate has passed.

The most useful combination is upstream's integrated game source plus our original-byte contracts, alias/caller analysis and differential verification infrastructure. Our existing C APIs model CPU registers, actual SS frames, flags, full RAM and qualified terminal boundaries. Upstream's game APIs model normal gameplay with fixed DS data and C calls. A source merge therefore needs explicit adapters and accepted domains; replacing one implementation with the other solely because their original entry addresses match would discard evidence.

A first adoption should preserve the upstream memory model. It already executes C game logic rather than interpreting original x86 instructions. A 1 MiB byte array and far-pointer values do not themselves make it an emulator. However, its fixed DGROUP globals and renderer writes are not yet the separate canonical-state, read-only presentation and atomic-provider design required for final CGA/Amiga switching.

## Coverage ledger

The source review covered all 17 files in `td2port/src/game` (6,420 lines total), their subsystem specifications, symbol records and architecture rules. Specification pseudocode was reconciled with the corresponding C implementation; upstream confidence labels remain upstream claims, not independent original-byte acceptance. External host/platform/build/tool files are covered by the companion reviews and parent inventory.

| File | Lines | Reviewed responsibility and disposition |
| --- | ---: | --- |
| `td2port/src/game/game.h` | 23 | Cross-subsystem startup, runner and simulation entry contracts; useful entry crosswalk |
| `td2port/src/game/flow.h` | 123 | Catalogue layouts, near-string helpers, screen/results APIs; extra limits and host stdio interface need admission |
| `td2port/src/game/flow.c` | 584 | Main, disk replacement, catalogue/select I/O, text-mode scanner, long arithmetic and screen pacing; integrated source candidate |
| `td2port/src/game/flow_scores.c` | 158 | Checksum, score load/save, name input/insertion/display; separate save root and strict length validation needed |
| `td2port/src/game/flow_screens.c` | 598 | Intro/logos/showroom/menu/car/scenery selection; paced effects and bounded frame tables differ from raw original |
| `td2port/src/game/flow_stage.c` | 605 | Difficulty, stage resources, scoring/results/ending/progression; zero-fill, arithmetic and embedded text need review |
| `td2port/src/game/scene.h` | 143 | SceneView parameterization, raw DS tables and graphics handles; good renderer structure, still EGA-specific |
| `td2port/src/game/scene.c` | 646 | Stage setup, snapshots, life/reset, frame loop, end-state handling, crashes/smoke/messages; high-value integrated caller source |
| `td2port/src/game/scene_project.c` | 408 | Front/mirror projection, spans, cut lines, clipping; domain-dependent LOOP normalization |
| `td2port/src/game/scene_draw.c` | 205 | Sky/cloud/mountain/tunnel/ground scanline filling; shortened invalid/full-cycle loop domain |
| `td2port/src/game/scene_objects.c` | 547 | Far-to-near markings/tunnels/scenery/SGN/FNT/cars; useful ordering and content contract candidate |
| `td2port/src/game/scene_cockpit.c` | 315 | Dash/HUD/ticket/radar/progress/gear/wheel/instruments; two explicit inherited-register TODOs |
| `td2port/src/game/sim.h` | 158 | Raw DS aliases, traffic/driver layouts, signed-difference helper and APIs; useful schema candidate |
| `td2port/src/game/sim.c` | 570 | Reset, timer tick, sound tone fields, input/control/gear/engine/steering/fall; native simulation candidate with neutral-clutch deviation |
| `td2port/src/game/sim_motion.c` | 450 | Motion/lookahead/object dispatch/damage/edges/roadside collision; SS and stale-BP assumptions need qualification |
| `td2port/src/game/sim_ai.c` | 507 | Opponent/lane gaps/police/demo behavior; preserves several quirks, adds invalid-state braking policy |
| `td2port/src/game/sim_traffic.c` | 380 | Moving traffic, meet/push/pass collisions, resynchronization/nearest selection; inherited DI/CX assumptions |
| `port/spec/game_flow.md` | 1,794 | Overview, function/globals tables, pseudocode, all eight format sections, hardware/timing, replacement/open-question records; includes stale/unproven statements below |
| `port/spec/simulation.md` | 1,632 | Overview, contracts/globals, all 21 pseudocode subsections, five format groups, timing/open questions/corrections; useful semantic map, not verified ownership |
| `port/spec/scene_render.md` | 1,585 | Front/mirror call graph, function/globals/handle tables, 13 rendering pseudocode groups, formats/timing/open questions; contains unresolved inherited state |
| `port/spec/game_flow_symbols.csv` | 173 data records | 66 function and 107 global records; includes other-owner and omitted install/disk entries |
| `port/spec/simulation_symbols.csv` | 274 data records | 65 function and 209 global records; aliases need address-based alignment |
| `port/spec/scene_render_symbols.csv` | 299 data records | 95 function and 204 global records; includes external platform functions |
| `td2port/PORTING.md` | whole file | Fixed memory model, ownership, timing, port changes, arithmetic and suggested checks |
| `port/RE_GUIDE.md` | whole file | Confidence convention and RE/spec methodology; source guidance, not authority to change our workflow |

Symbol totals include duplicate/external ownership records; do not sum them into unique implemented or accepted original functions. The parent address comparison supplies the full machine-readable candidate crosswalk.

## Source-supported capability

| Capability | Pinned source evidence | Value for our work |
| --- | --- | --- |
| Startup to menus | `flow.c:312` (`game_main`); `flow_screens.c:481` (`main_menu`) | Replaces considerable caller/state discovery once verified |
| Menus to complete stage/result cycle | `flow_stage.c:556` (`run_game`), `scene.c:401` (`run_stage`), `flow_stage.c:173` (`stage_results`) | Existing end-to-end structure, including death/restart, station/finish, duel and score paths |
| EGA presentation | `scene_project.c:7` and `:22` front/mirror descriptors; `scene_objects.c:464` object loop; `scene_cockpit.c:113` HUD | Complete candidate scene pipeline and draw-order map |
| Simulation scheduling | `sim.c:84`: `sound_tick()` first; decrement byte divisor, reset to 10, then controls/engine/motion/AI/police/traffic/pass collision | Audio/timer routine ~100 Hz, gameplay step ~10 Hz, seconds every tenth gameplay step; rates require independent host/original verification |
| Deterministic update order | `sim.c:84`, `sim_motion.c:84`, `sim_traffic.c:19` | RNG and state checkpoint boundaries can be extracted without rediscovering the entire system |
| Semantic car/road inputs | `sim.h:112` DS aliases and traffic/driver layouts; `simulation.md:1367`, `:1421`; `flow_stage.c:478` stage loader | Field names and consumer candidates for our raw resource registry |
| Preserved quirks | `sim_ai.c:118` curve scan; `sim_motion.c:279` doubled damage accumulation; `sim_traffic.c:160` shoving order; `scene_objects.c:209` mirror signs | Explicit quirks provide targeted comparison cases; verify rather than assume these summaries are right |
| Native integration | `PORTING.md:33`, `:38`, `:45` | Game C does not include SDL directly; it uses mem/host/platform interfaces. Host separation is present, state separation is incomplete |

The stage implementation is materially beyond this project's current nonplayable helper library. Source existence supports feasibility; this review does not independently establish that any particular car/route completes successfully at runtime.

## Gaps and required tightening

### GC-01: fixed DS/SS is a different acceptance domain

`PORTING.md:38-59` deliberately keeps all original state in `mem[]` at fixed relocated addresses. Upstream `sim_motion.c:234-237` treats the original SS-relative roadside writes as DS array writes, justified by `simulation.md:1612-1614` asserting SS=DGROUP. Its game functions do not model C-call push/pop bytes, mutable stack returns, independent DS/SS or register/flag postconditions.

Our `td2ega-session-init-bus.md:21-38` records actual frame writes, 168 conditional ring-alias witnesses and open bindings/lifetimes. `td2ega-sim-controller.md` retains raw callback selectors and actual near/far returns. These stronger bounded observations must survive adoption. Admit a normal-game caller domain only after proving DS/SS, valid stack exclusion, live heap/descriptor ownership, callback lifetime, mutable-code state and allowed data ranges. Upstream's semantically named DS variables are leads; they do not close every writer/reset/lifetime obligation.

### GC-02: two explicit cockpit TODOs remain

`scene_cockpit.c:207-210` assumes CH=0 when the original sets only CL for the steering-marker Y coordinate; `scene_render.md:1571-1573` explicitly asks for the blitter exit path to confirm it. `scene_cockpit.c:257-260` initializes SI to slot 0 where the original retains runner SI on a tachometer-digits/no-speed-digits path. The source says none of its shipped cars use that latter combination; that is a corpus/domain claim to check, not proof of the full instruction contract.

Resolve with the actual caller/callee register evidence and admitted car-field matrix. Retain or explicitly exclude unmatched source states. A clean build cannot close either TODO.

### GC-03: known gameplay/audio and inherited-register changes

`sim.c:265-273` skips `clutch_check` in neutral. `simulation.md:1598-1602` says original inherited CX/DX can produce a grind tone while free-revving in neutral; the code deliberately omits it. This affects original PC Speaker event fidelity even if vehicle speed is unaffected.

`sim_motion.c:436-439` always treats a billboard collision as a crash when the original can compare inherited BP for types >=0x50. `sim_traffic.c:367` seeds DI with the list base where the original leaves it inherited; `sim_traffic.c:244-245` seeds CX with same_count8 based on a normal caller-path argument. `sim_ai.c:447-451` brakes for police drive states outside 1..5, explicitly replacing a raw out-of-table jump.

Add targeted caller/domain tests: neutral release at high RPM, both keyboard and joystick paths; billboard type >=0x50 with inherited BP <20 and >=20; zero/all-ahead/tie traffic lists and DI preservation; inactive-position pass checks; police roadblock/opponent collisions and every drive-state target. Classify each difference as proved unreachable for admitted gameplay, restored fidelity, or an approved native policy. Do not relabel upstream policies as original behavior.

### GC-04: zero/full-cycle loops have changed

`scene_project.c:392-396` returns for first>=end instead of executing the original zero/wrapped count. Our independently compared `td2ega-near-clamp.md:19-24` records 65,536 words per pass at zero count and 327,680 operations across five passes. `scene_draw.c:128-130` treats a ground span at/after the end as empty instead of retaining its raw loop. Upstream `sim_traffic.c:364-365`, in contrast, intentionally preserves 65,536 iterations in nearest selection.

The code is a product-domain adaptation, not an interchangeable general raw-helper implementation. Preserve our raw APIs/receipts. Prove top-row bounds from projection plus the actual resource corpus before admitting simplified draw helpers. Add domain checks at the adapter boundary and preserve evidence for rejected/changed states.

### GC-05: resource tail, file and table policies need full-corpus proof

`flow_stage.c:526-529` zero-fills the fixed 0x1E5E DAT copy beyond the decoded file's size; `game_flow.md:1777-1779` describes the original tail as heap garbage and asks whether anything reads it. The source comment saying the bytes are zero is a port decision, not original-byte proof. Our raw DAT-copy/owner/lifetime work must qualify that difference.

`flow.h:22` and `flow.c:450` cap catalogues at 30 instead of the original 31; `flow.c:159` bounds `%s`; `flow_screens.c:237`, `:297`, `:317` expand/bound showroom frame arrays; `flow_scores.c:37-43` caps high-score reads at 340 bytes. These are clear native robustness choices. They should be documented as such and validated separately. The high-score loader discards `fread`'s actual byte count before checksum validation, so truncation/partial-load behavior needs a specific test rather than an assumption that capped reads guarantee a valid record.

The full original corpus and synthetic malformed-input cases remain necessary. In particular validate CAMA's extra bytes, every road length/lookahead, optional SGN/FNT references, every carousel frame count and every used handle. Upstream spec field names alone are not a closed consumer/disposition record for all 249 DOS identities or every embedded view.

### GC-06: timing is partly redesigned and documentation drifts

`scene.c:411` inserts `host_frame_begin`; `flow.c:184-201` sets 4 ticks per dissolve step; `flow_screens.c:52` sets 3 ticks per title morph step and `:377` 1 tick per car-slide row. These replace CPU-speed original effects. `scene_cockpit.c:169-170` decreases gate close delay per drawn frame, so the selected rendering cadence affects UI lifetime.

Game state is sampled and advanced serially around host pumps. `scene_render.md:1544-1546` acknowledges the original read traffic lists without a fully protected snapshot and recommends synchronous rendering in the port. This is a useful consistent native scheduler, but it is not proof of original interrupt interleavings or hardware timing. Record normal scheduling and any presentation policy separately from timer/IRQ fidelity.

`game_flow.md:1665` still says dissolve pacing is inside graphics, while `flow.c:184-185` says callers pace it. `scene_render.md:1540-1541` loosely calls motion a per-100-Hz-tick operation, while `simulation.md:1541-1543` and `sim.c:84-129` distinguish ~100 Hz sound, ~10 Hz gameplay and ~1 Hz seconds. Use source and original instruction evidence to settle the schedule, then update our own precise clock description. Do not import conflicting prose verbatim.

### GC-07: disk/protection omissions are deliberate, not recovered code closure

`flow.c:253-263` always succeeds at ensure_disk; `:319-320`, `:334-349`, `:400` drop timing/device checks, initialize the passed state and force EGA; `:581-584` makes Install a no-op. `sim.c:197-209`, `:227-230` and `scene.c:469-470` use only the passed mutable-code behavior.

For the final external-file native product, such replacements may be appropriate. For P1 they need an explicit original-function disposition and evidence of the replaced behavior/transition, not a claim that the omitted installer/runtime code has been ported. Our multiple mutable states, saved-return mechanisms and pending runtime/formatter work cannot be closed solely by a fixed-state upstream C call.

### GC-08: original text is embedded in game code

Despite most strings being read by DS offset from the external EXE, `flow_stage.c:52-83`, `:202-221`, `:340-396` and `flow_scores.c:139-144` embed original result/score text formats. The adjacent comments identify their original DS addresses. This conflicts with this project's requirement to keep original game text and media external.

Before product adoption/package publication, replace these embedded originals with validated external-EXE string access/formatting or an explicitly classified permitted replacement. Preserve exact spaces and formatting where original fidelity requires it. Upstream MIT permission for its code does not satisfy our stricter no-original-media product policy by itself.

### GC-09: portability needs arithmetic proof beyond fixed-width typedefs

Upstream uses many explicit u16 truncations, carry/borrow helpers and checked division APIs; examples include `flow.c:26-37`, `sim.h:148-154`, `scene.h:130-141`. Those are useful foundations. However, `flow_stage.c:246-254` and `:315-321` have signed s32 multiplication chains, and `sim.c:510`, `:531-535` use signed narrowing/right shifts. The CMake flags do not select a defined wrapping model for signed overflow (`td2port/CMakeLists.txt:18-27`).

This is a static portability obligation, not an observed shipped-data failure. Establish bounds for admitted states or replace overflow-sensitive operations with defined unsigned/widened helpers; verify bit-pattern truncation, signed shifts, INT_MIN cases and cross-compiler outputs. Our C17 requirement and second compiler/host gate still apply even though upstream targets C11 and exposes no SDL objects in game headers.

### GC-10: specifications are valuable but contain direct evidence conflicts

`game_flow.md:225` and `:1638` identify the anomaly readers as BIOS 0040:006C, while our original-instruction work preserves literal 0040:046C, physical 0x086C. Dropping the protection timer does not resolve the original address or justify replacing that finding. `simulation.md:1361` calls the 1BF7 failed-tail write an INT 19h-vector overwrite; `game_flow.md:1758` and our original evidence identify the write at physical 0x86, the INT 21h segment word. Keep source locators and correct address arithmetic.

`simulation.md:828-831` describes BP as stale on the whole SGN path, while its later correction at `:1627` and `sim_motion.c:436-439` refine that to types >=0x50. `scene_render.md:1439` says the 20 side bytes are not read in the renderer, but the simulation uses them. Absence of a consumer within one subsystem is not a whole-program unused-data finding.

Tighten our registries by recording upstream names/semantics as candidate annotations with source locators and conflict records, then promote only after our byte/consumer/caller proof. Preserve all contrary evidence and accepted receipts.

## Practical crosswalk and acceptance work

| Original entry/family | Upstream candidate | Our retained authority / next use |
| --- | --- | --- |
| `0000:07B3` | `flow.c:312 game_main` | Pending whole-main/startup-to-exit proof; use as caller map, including every omitted service |
| `06C9:1B2C`, `1C8F` | `scene.c:401 run_stage`, `:298 stage_load` | Pending full runner/constructor/loader ownership; high-value implementation source after byte/domain alignment |
| `06C9:3F40`, `3FF9`, `38F2`, `1E31`, `5427` | `sim.c:14`, `:61`; `scene_cockpit.c:44`; `scene.c:352`; `sim_ai.c:223` | `src/recovered/td2ega_session_init_bus.c` and its frozen receipts; compare normal DS/SS domain, retain conditional stack aliases |
| `06C9:403B` | `sim.c:84 sim_timer_routine` | `td2ega_state_tick_bus` and published timer-caller supplements; use recovered actual body chain to assess ordering and mutable variants |
| `06C9:420A` | `sim.c:183 read_input` | `td2ega_input_update_bus` actual frame/FLAGS evidence; neutral/protection/input domain differences explicit |
| `06C9:4674`, `499A`, `4A2E`, `4AFA`, `4B5D`, `4B9A`, `4C85` | `sim_motion.c` | Our sim_controller, sample_adjust, window_controllers, threshold_transition and indexed_sample contracts; adapt by entry and qualified caller domain |
| `06C9:088E` | `scene_project.c:390 clamp_spans` | `td2ega_near_clamp` deliberately preserves full LOOP counts; keep both contracts and prove product bounds |
| `06C9:53A6`, `56ED` | `sim_ai.c:191 police`, `:417 police_drive` | Full 403B chain has nonlocal-return/flags evidence; preserve original return semantics and classify new braking policy |
| `06C9:780E` / callers | game invokes platform `rand8` | `td2ega_byte_ring` plus actual SS caller packets; retain ring cursor/high-byte/writer/seed/lifetime obligations |
| `06C9:3A91`, `3AB8`, `BA3C` | `scene_cockpit.c:102`, `:90`; platform plotting | Our point_sequence/point_update/pixel_point receipts; verify raw word-port/device effects separately from final pixels |
| `13A8:0582`, `0B00` formatter/runtime | Replaced by native startup/stdio/fatal control | Our early-exit WIP and formatter frontier remain independently scoped; port omission cannot register/close them |

The crosswalk is for investigation. It does not transfer any acceptance status to either side, and exact line anchors should be read in the pinned reference commit.

## Adoption strategy

1. Keep the pinned reference immutable. Import any candidate code into a separate development copy with upstream provenance/license retained; do not build a feature branch inside the reference checkout.
2. Map original entries, shared tails, data fields, omitted runtime/device/install code and deliberate deviations to our task/function/resource records. Reconcile edition bytes and mutable states first.
3. Reuse our original-instruction comparisons as independent oracles. Start with normal-domain reset/tick/motion/traffic/projection slices and explicitly include the differences above. Never overwrite the old source, DLL or accepted receipt to manufacture agreement.
4. Close EGA source/ownership obligations using upstream source where it actually satisfies them. Then perform the required CGA comparison; the upstream EGA renderer is useful shared-core evidence but supplies no CGA implementation.
5. Validate all DOS consumers/resources, including tails, malformed input and optional dependencies. Keep source read-only and move selections/high scores to a user profile.
6. Only after the required code/resource gates, adopt the integrated SDL host/flow for the native phase, repair text/arithmetic/policy gaps and run the full gameplay/pixel/audio/content matrix. A `--check` success is loader evidence.
7. Factor canonical state and provider-owned graphics/audio/cache state once a validated EGA baseline exists. Snapshot simulation tick/RNG/input/positions/progression/events before and after provider commits. EGA-only source has no Amiga, Northern Germany Challenge mapping or atomic live provider-switch implementation.

This route can save substantial discovery, first-translation and integration effort. It cannot eliminate source admission, CGA work, full resource accounting, original/runtime/audio/visual validation, Amiga reverse engineering or provider switching. No reliable calendar percentage follows from static source coverage. Measure a representative adoption slice before revising effort beyond conditional ranges in the parent assessment.

## Verification boundary and outputs

This review is static source/document/contract comparison. It identifies concrete integration and fidelity gaps; it does not report an upstream gameplay defect as reproduced. The approved project phase order remains EGA recovery, CGA comparison, complete DOS resources, native Windows DOS baseline, Amiga recovery, then live media switching and extra scenery. New reference evidence can shorten those tasks without pretending they were already completed.
