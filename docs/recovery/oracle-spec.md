# Future DOS EGA execution oracle

Specification date: 2026-10-13. Task: `P0-04`. Status: **defined, not installed or exercised**. No game was executed to produce this document, no trace/save state/capture exists from this work, and repeatability is **unproven**. Phase 0 requires a concrete future oracle recipe; its documentation gate is separate from runtime admission. This specification does not pass any Phase 1 differential, runtime, visual, audio or fidelity gate.

## Pinned implementation and missing setup

The proposed debugger oracle is [DOSBox-X release `dosbox-x-v2026.10.01`](https://github.com/joncampbell123/dosbox-x/releases/tag/dosbox-x-v2026.10.01), source commit `b6abbd5980a885f5f310a4088c59a8688d1b116c`. Tool research found no local executable in the searched tool/program locations; see the [toolchain record](toolchain.md) and [discovery evidence](evidence/toolchain-discovery.json) for exact scope. A future executable must be acquired or built, its debugger capabilities verified, and its binary/DLL/build-options hashes entered in the tool lock before use. An upstream release-archive digest is not the executable digest.

Configuration keys and debugger commands are based on the commit-pinned [full configuration reference](https://raw.githubusercontent.com/joncampbell123/dosbox-x/b6abbd5980a885f5f310a4088c59a8688d1b116c/dosbox-x.reference.full.conf) and [debugger manual](https://raw.githubusercontent.com/joncampbell123/dosbox-x/b6abbd5980a885f5f310a4088c59a8688d1b116c/README.debugger). These are capability references, not proof of local debugger support or the game's behavior.

| Item | Current state | Required before a measured run |
| --- | --- | --- |
| Upstream version/source | Selected and pinned | Record exact acquired/build identity |
| Executable and debugger | Not installed/verified by this work | Binary hash, dependency hashes, debugger smoke check using synthetic code |
| Complete effective configuration | Design below; file not generated | Save all effective defaults and overrides; hash config/map files |
| DOS disk fixture | Not created by this specification | Complete private copy, exact file/timestamp/attribute manifest |
| RNG/time/input boundaries | Not recovered yet | Locate seed reads, tick source, input sample and tie ordering |
| Measurements | Targets specified below | Resolve concrete game addresses and record layouts |
| Repeatability | Unproven; zero runs | Three fresh repetitions per admitted fixture and comparison scope |

## Private files and edition

The canonical input is `reference/dos/TD2EGA.EXE`, SHA-256 `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182`, together with the complete admitted DOS resource set. Do not run from or mount `reference/`. Create `runs/oracle/<fixture>/<run>/dos/` from the admitted set; verify copied bytes against the manifest before launch. Keep traces, framebuffer/audio dumps and save states in `analysis/oracle/<fixture>/<run>/`, never in publication. Preserve original path names; record the emulator's case and directory-order behavior.

Each run starts from a newly verified copy. Record all initial DOS file bytes, sizes, timestamps and attributes, including selection and high-score metadata; do not substitute a cleaned/blank file unless it is a separately named synthetic fixture. Hash changed/created/deleted files afterward and preserve their write log. Every run has an explicit working directory, mounted-drive map, DOS environment, command tail and output directory. Mount no unrelated host directory or network drive. The final reference-manifest check is independent of a fixture's byte equality.

A checkpoint is a derivative of one named cold-start run. Record its full save-state hash, producing emulator/config/input/edition hashes, game checkpoint, CPU/memory/IRQ/PIT/audio state and mutable files. Never use an unexplained downloaded save state. Do not force a state across different versions/configurations. Repetition from one checkpoint establishes checkpoint repeatability only; separately repeat cold startup to test initialization.

## Proposed machine profile

This profile is an engineering starting point, not a claim about the machine originally used to develop or play Test Drive II. Confirm compatibility and inspect effective values before admitting it; a changed value creates a new fixture revision and new repeatability check.

| Dimension | Proposed value/policy |
| --- | --- |
| CPU | `core=normal`, `cputype=286`, `cycles=fixed 6000`; no automatic speed/turbo changes |
| Memory | `memsize=1`, `memsizekb=0`, `dos mem limit=640`; XMS, EMS and UMB disabled; record actual DOS free-memory/load-segment map |
| Video | `machine=ega`; no shader/scaler in the measured pixel path; capture raw planes/indexed output plus palette/register state |
| Address wrap | `a20=off`; record actual A20 state at program entry and post-unpack checkpoint |
| DOS | Same built-in DOS kernel from the pinned executable; record reported DOS version, country/code page, environment, PATH and PSP/MCB allocation |
| Loader | Primary profile `exepack=none` so the supplied EXEPACK stub is actually executed; record the post-unpack state and any compatibility failure |
| Input | Keyboard only; `joysticktype=none`; pinned mapper; no host clipboard, mouse integration or interactive key injection during a measured segment |
| PC Speaker | `pcspeaker=true`, `pcrate=48000`; mixer rate 48000 Hz; fixed recorded filter/volume policy; all unrelated audio devices disabled |
| Clock | `synchronize time=false`; DOS date/time and BIOS tick start fixed before launch, with the actual observed values recorded |
| Presentation | Windowed software output initially; fixed focus policy and no pause-on-background changes; host refresh/scaling excluded from semantic timing |
| States/logs | Autosave disabled; explicit checkpoints only; bounded debugger logs to private output paths |

The EXEPACK setting is material: the pinned reference offers `none`, `a20off` and `unpack`, and defaults to automatic unpacking. A separate loader-comparison fixture may use automatic unpacking, but its results must name that transformation and cannot establish execution of the supplied stub. If the primary profile fails, keep the failure and investigate address/loader assumptions; do not silently enable a compatibility workaround. Physical-cycle timing remains a separate question: fixed emulator cycles do not establish real-hardware timing accuracy. [DOSBox-X configuration reference](https://raw.githubusercontent.com/joncampbell123/dosbox-x/b6abbd5980a885f5f310a4088c59a8688d1b116c/dosbox-x.reference.full.conf)

Generate and retain the full effective configuration from the pinned build, then add these overrides. The override table alone is insufficient because omitted defaults can influence memory, timer, disk, audio and input behavior. Hash effective config, mapper, debugger script/instrumentation and command-line arguments as one environment identity. Record host OS/build, architecture and scheduler/audio backend for reproduction; host elapsed time is diagnostic only.

## Time, input and measurement contracts

Before a game fixture can be locked, recover the source of RNG seed, BIOS/DOS time reads, installed interrupt ownership and actual simulation/input/audio scheduling. Do not assume one frame, one IRQ0, one BIOS tick or one main-loop iteration is one simulation tick. At each checkpoint retain the relevant original register/memory values and the interpretation used by the portable C harness.

Use an integer logical timebase with a named origin. Prefer a recovered simulation/input-sampling boundary for gameplay fixtures; use original instruction boundaries for function-level vectors and emulated PIT-cycle/event indices for speaker timing. Define tie ordering for interrupt delivery, key make/break, input sampling, simulation step, presentation and audio events. A human wall-clock keypress replay is exploratory observation and cannot be called a deterministic fixture.

The input schedule lists every make/break scan code, its logical timestamp, held duration, delivery mechanism and acknowledgement point. Starting BIOS/keyboard-controller queues must be known. Recover scan codes and the game's polling method instead of assuming BIOS `INT 16h` owns all input. The selected debugger must demonstrably support the chosen control/measurement mechanism; otherwise the fixture stays `specified` and requires a separately reviewed adapter. Debugger commands to set registers/memory must be logged as test mutations, not mistaken for original behavior.

At program entry, record actual load segment/PSP/environment/stack, MZ entry, relocation policy, A20 and memory allocation. At the verified post-unpack transfer, compare the unrelocated derived image to the runtime image with an explicit relocation map. Subtract the actual load segment only from relocation words; do not normalize arbitrary differing bytes. Record any self-modification, initialized/BSS area, stack or heap difference separately. Hash raw and normalized comparisons, not merely the normalized success result.

Function vectors capture entry/exit registers, relevant flags, stack words, segment assumptions, input memory, global writes, calls/OS effects and expected arithmetic width. Choose recovered-contract boundaries and failure/edge cases. Every vector must identify its original-function ID and portable-source revision; compiling the harness is a separate gate from agreement.

Gameplay checkpoints capture the state machine, RNG value and call count, input state, player/opponent/traffic state, route/section/progress, timers, score, pending events and known mutable files when their locations are recovered. Presentation comparison captures EGA planes/palette, masks/clipping/draw order, animation phase and pre-scaling indexed output. Audio comparison captures timestamped PIT/speaker-control events first, then PCM with sample rate/filter/volume/capture latency recorded. Unknown state fields remain unknown; broad memory hashes supplement a semantic map rather than replacing it.

## Initial fixture queue

These are recipes to make concrete after address/state recovery, **not recorded tests or claims that every named path exists**. All have status `specified`, zero runs and repeatability `unproven`. Allocate trace-record IDs when recipes and addresses are actually locked.

| Recipe | Start and inputs | Stop/measurements | Admission dependency |
| --- | --- | --- | --- |
| `EGA-BOOT-001` | Fresh DOS copy, fixed date/tick/environment, empty input queues, direct `TD2EGA.EXE` launch; no game input | Original packed entry, verified post-unpack transfer, first stable frontend state; image/relocation/register/file-open summary | Proven packer transfer, controlled clock and finite stop condition |
| `EGA-LEAF-001` | Verified original-function entry with explicit registers/segments/stack/memory; contract-derived zero/extrema/overflow/alias vectors | Return boundary; registers/flags/memory side effects and declared OS effects | Reviewed function contract and valid invocation context |
| `EGA-SELECT-001` | Named frontend checkpoint; schedule confirmed scan codes at recovered sample boundaries to select one exact catalog car/scenery/mode | Before race-state commit; selection globals, resource requests, RNG/timers and file writes | Recovered menu/input state and catalog identities |
| `EGA-RACE-001` | Admitted race-entry checkpoint; hold/release acceleration for 120 recovered simulation steps, then no input for 60; steering/gear state explicitly fixed | Per-step car/road/RNG/timer/event state and final indexed framebuffer | Confirmed driving controls, tick definition and valid resource-fed start state |
| `EGA-SPEAKER-001` | Named startup/music or effect checkpoint; a single recovered cue/event with no other game inputs for a bounded recovered interval | PIT channel programming, speaker gate/events and PCM; sequence/end/priority state | Recovered audio cue, event ownership and timebase |
| `EGA-PERSIST-001` | Fresh private copy; replay a proven selection/exit path with exact inputs | Original DOS reads/writes, changed-file bytes and termination/vector restoration | Recovered write/quit paths and controlled exit |
| `EGA-EDGE-001` | Vector/checkpoint chosen from a recovered collision/road-edge/fuel/timer branch | Exact branch ordering, state/events and failure side effects | Actual branch presence and valid boundary context |

The 120/60-step race duration is a bounded proposed input case, not a recovered game frequency or guarantee of useful scene coverage. Extend with crash/repair/refueling/pause/checkpoint/finish/full-session cases only after their paths and control inputs are established. CGA fixtures follow EGA recovery; they need independent edition/config locks and cannot inherit EGA repeatability. Amiga fixtures belong to the later recovery phase.

## Repeatability admission and comparisons

1. Resolve all environment, seed, address, input and measurement dependencies. Save a schema-valid trace record with exact input hashes, configuration and fixture revision. A missing lock field keeps status `specified`.
2. Start three independent emulator processes from separately reset private copies. Execute the same cold-start fixture and preserve each run's exact start state, inputs, logs, raw outputs and final write manifest. Do not average runs or choose the best result.
3. Compare only declared boundaries and fields, applying the reviewed relocation/address normalization and no other hidden masking. Require exact integer/core-state/event-sequence/pixel-index/palette agreement for that scope. Report raw differing regions too.
4. PCM bit identity is a separate measured question. First require speaker event/time agreement; if PCM differs, preserve it, identify mixer/capture causes and predeclare any justified tolerance before another evaluation. An audible similarity judgment cannot hide event drift.
5. Record each difference with the first divergent boundary, both subjects/hashes, reproduction, likely category and unresolved cause. A failed repetition leaves repeatability failed for the affected scope. Reduce scope explicitly or fix a proven uncontrolled variable; do not broaden tolerances just to pass.
6. Repeat checkpoint fixtures from three fresh instances of the same admitted state, then compare their cold-start producer runs. Checkpoint success does not prove startup determinism. Any emulator/config/instrumentation/disk/input/state change requires a new revision and renewed repeatability.
7. Admit the oracle only for its measured boundaries. Compare the portable C implementation against those original outputs using identical semantic inputs, recording source/compiler/harness hashes and exact/tolerant fields. Keep original repetition, native repetition and original/native agreement as three distinct results.
8. Perform a bounded instrumentation check using the same fixture with reduced/no tracing at matching checkpoints. If debugger stops/logging change timer/input/audio results, record that effect and keep affected timing claims unadmitted. Do not assume trace instrumentation is invisible.

No independent timing hardware was used or specified as available here. If a discrepancy depends on real CPU/bus/video/PIT timing, define a justified second oracle or hardware experiment before claiming original physical timing. Human visual review and listening remain separate acceptance steps after numeric checks. Phase 1 cannot close from a plausible startup image, compiled helpers, or these future fixture recipes.

Record shape, address provenance and gate meanings are defined in [evidence-conventions.md](evidence-conventions.md) and [trace-record.schema.json](schemas/trace-record.schema.json).
