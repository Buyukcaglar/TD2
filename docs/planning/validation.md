# Acceptance and validation requirements

This document defines future tests. Only static inspection, metadata generation and documentation consistency checks were performed during planning. No game was launched, source built, original resources rendered or audio played.

## Evidence gates

| Gate | Establishes | Does not establish |
| --- | --- | --- |
| Static bytes and locators | File identity, signatures, documented code/data hypotheses | Runtime behavior or edition originality |
| Reviewed code contracts | Instruction effects, state ownership, bounded schemas | Full-corpus decoding or gameplay |
| Compilation | Valid source and build compatibility | Correct behavior, visual/audio fidelity |
| Differential functions/state | Agreement for specified vectors and checkpoints | Unexercised branches or physical timing |
| Runtime sessions | Observed supported gameplay paths | Every content combination or original fidelity |
| Visual and audio review | Assessed pixels, animation, timing and sound for named scenes | Unreviewed assets or code completeness |
| Edition fidelity | Admitted version, known patch differences and covered original comparisons | Universal parity across versions/platforms |

An emulator is a controlled oracle only after repeated fixtures demonstrate repeatability at the measured boundaries. Record emulator version, CPU/core/cycles, video/audio devices, clocks, memory, loader fixes, media hashes, save-state provenance and input timing. DOSBox-X explicitly does not target instruction cycle accuracy. Where timing discrepancies depend on real hardware, add justified independent hardware/timing evidence rather than asserting that one emulator is exact.

## Requirement mapping

| ID | Requirement | Acceptance evidence |
| --- | --- | --- |
| R01 | Preserve supplied originals | Initial/final manifest equality; future runs/write paths isolated |
| R02 | EGA disassembly and portable C recovery | Validated unpack image/relocations; code/data/function map; reachable contracts; reviewed C and differential vectors |
| R03 | CGA graphics implementation analysis | Function alignment; pixel/memory/palette/mask specification; common-state comparison |
| R04 | All DOS resources understood | File-to-consumer registry for all 249 baseline files; schemas; full-corpus parse and explained exceptions |
| R05 | Executable-embedded resources external | Extraction provenance; required-original EXE policy; package audit |
| R06 | Native Windows gameplay | Clean native launch, complete sessions, menus/race/transitions, all admitted DOS content |
| R07 | Portable game core | Windows and second-host/compiler builds/tests; no OS/dependency types or undefined arithmetic in core |
| R08 | No DOS media bundled | Archive and binary/resource audit; valid-data success and missing-data failure tests |
| R09 | EGA and CGA modes | Independent indexed-pixel/palette/mask/animation review and live switching tests |
| R10 | DOS PC Speaker music/effects | Recovered sequencer/device semantics; timestamped events and audio comparison |
| R12 | Amiga code recovery | Hunk/relocation/patch map; recovered C contracts; selected-edition state comparison |
| R13 | Amiga graphics and animation | Complete consumer-driven resource decoding and semantic mappings; visual/animation comparison |
| R14 | Amiga music and sound effects | Replay-code/sample recovery; period/loop/channel/event and audible comparison |
| R15 | On-the-fly choices | Same-session switch commits preserve canonical state; combinations, failure rollback and repeated-switch tests |
| R16 | Northern Germany Challenge | User-supplied pack identified/validated; route/gameplay/media import; all supplied sections playable and compared; absent/partial pack behavior verified |
| R17 | Required phase order | Gate records prove EGA then CGA, DOS resources, native DOS baseline, Amiga recovery, final integration |
| R18 | Durable documentation | Current roadmap, task/evidence/decision registries, schemas, handoff and reproducible locators |
| R19 | All Amiga resources understood | Disposition and consumer/schema records for all 352 baseline archive members, including executables and explained installer/metadata files |

R16 is conditional on necessary input availability, not an optional omission when the inputs exist. The current archive has a candidate fourth scenery tree, so inspect that before asking the user for another copy. A name confirmation is not sufficient to admit arbitrary same-named files.

## DOS code and resource cases

1. Validate every relocation and input boundary in derived unpacked images. Investigate the CGA remainder, allocation/stack differences, self-modification, indirect targets and alternate launch paths.
2. Compare arithmetic at zero, extrema, overflow, negative values, carries, truncation, division/shift boundaries and aliasing-sensitive operations; use cases from recovered instruction contracts rather than tests copied from implementation.
3. Verify RNG state, call counts and seed ownership at each game-state transition. Presentation, sound and window events must not consume simulation randomness unless original behavior requires it.
4. Exercise each admitted parser with the full original corpus, plus synthetic truncation/length/offset/terminator/corruption cases. Bound decompression and reject partial content commits.
5. Test both observed PCS prefix families, all PES members, scenery DAT/SGN/FNT variations, the exceptional CAMA record, repeated `.SS` labels, case lookup, exact duplicates and two-byte `VOICES.BIN`.
6. Trace original reads and writes: prove each file's consumer/disposition and keep selection/high-score updates away from reference files.

## Native gameplay matrix

Use all 12 DOS catalog cars and three DOS scenery families with all 19 section records. A section count is inventory evidence, not proof every section is independently selectable or a separate complete route; recover their real progression structure. Cover every car and route, then use targeted pairwise combinations plus full sessions for interaction risk. Exhaustive mode/car/route combinations are required where a shared assumption is disproven.

Scenarios include cold startup, default/changed selections, difficulty/mode changes, start and restart, acceleration/braking/steering/gearing, rival/traffic/police behavior where recovered, road edges, collision/crash, refueling/repair, pause/resume, checkpoint/section progression, finish/end, high score, quit and relaunch. Confirm which scenarios the supplied version actually supports.

For each fixture, record input timestamps in canonical ticks, start-state identity, relevant state checkpoints, semantic events and expected outputs. Compare simulation before presentation to localize errors. A menu screenshot or first rendered road is not end-to-end playability.

Windows cases include focus loss, device disconnect, resize, scaling, window/fullscreen changes, audio device replacement, long sessions, pause behavior and user-data permissions. Each should preserve simulation rules and source-file custody.

## Pixels animation and audio

Use controlled original captures only during a later authorized runtime phase. Compare indexed pixels, palette state, masks, clipping and draw order before host scaling. Record original resolution/aspect and color conversion. For Amiga, also establish display mode, bitplane/copper/palette changes and animation phase. Human review resolves visible behavior beyond numeric metrics; arbitrary AI artwork is not a replacement for missing original assets.

For sound, compare sequencer events, PIT/PC Speaker or Paula period/volume/channel changes and loop boundaries separately from final PCM. Align captures by admitted timebase, not arbitrary audio correlation that could conceal drift. Record sample rate, device/filter/panning configuration and tolerances before evaluating. Human listening covers transitions, priority, timbre and unwanted clicks; a waveform or register trace alone does not establish audible fidelity. Where two soundtracks cannot share phase, validate the documented deterministic restart/optional-fade policy separately from each backend's fidelity; gameplay clocks and state must remain unchanged.

## Live switching matrix

| Axis | Cases |
| --- | --- |
| Graphics | EGA to/from CGA, EGA to/from Amiga, CGA to/from Amiga; repeat and rapid requests |
| Music/effects | Every admitted backend independently, including music/effects overlap and silence |
| State | Intro/menu, race, active animation, crash/repair, refueling, pause, checkpoint, finish and section load where present |
| Content | Every car; each scenery family; Northern Germany Challenge once available |
| Failure | Missing target resource, corrupt target, unsupported mapping, memory pressure, device reset, interrupted preparation |
| Invariant | Same canonical tick/RNG/input/car/opponent/route/timer/score/events at commit; no duplicated simulation step |

Use a saved semantic snapshot immediately before and after a switch commit without advancing simulation to prove invariants. Separately exercise normal tick advancement during background preparation. Failed switches retain the previous provider and usable session. Ensure old resource pointers cannot survive into the new provider or active audio callbacks.

## Northern Germany Challenge acceptance

1. Verify its admitted member list and identity. Keep `scen2`/`scen3` catalogs, reused names and nonidentical payloads separate. Explain any missing user inputs with exact required-file roles.
2. Parse every supplied section, link and referenced object/sign/event. Establish which media and gameplay data are mandatory versus optional scores/settings.
3. Compare normalized route geometry, object placement, signs, section order, hazards and checkpoint/finish events against the admitted Amiga edition.
4. Complete gameplay through the full supplied scenery on the native DOS core. Assess original Amiga-versus-DOS physics differences explicitly; route fidelity does not imply platform physics parity.
5. Test all declared supported media choices and live switches on this scenery. If a DOS counterpart does not exist, record that limitation and keep the combination unavailable until resolved; do not call universal switching complete.
6. Verify full DOS operation without this optional pack; verify precise partial/corrupt-pack diagnostics and no source writes.

## Release and claim review

Inspect the final package for original media, generated copies, payload-bearing tests/caches, embedded text/art/audio and accidentally retained third-party installer/manual files. Verify external-data-only operation from a clean install and account for every shipped dependency and license.

A release report must list admitted hashes/editions, tested content and combinations, separate evidence gates, known original quirks, supplied-patch differences and unavailable optional inputs. Counts or build success must not become a blanket parity claim. Preserve the exact evidence and conditions for any remaining defect or acceptance limitation.
