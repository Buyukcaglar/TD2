# Native game architecture and media switching

This is a proposed design for later development. No modules, API implementations or build system have been created. The canonical gameplay behavior comes from the admitted DOS EGA edition; CGA and Amiga presentation must share that state. The Amiga code is also recovered and compared, but its physics or later patch enhancements do not silently replace DOS behavior.

## Module boundaries

| Proposed module | Owns | Must not own |
| --- | --- | --- |
| Portable C17 core | Simulation tick, RNG, car/opponent/traffic state, progression, timers, score, game-state transitions | OS handles, SDL objects, window state, device clocks, original instruction execution |
| Resource readers | Bounded binary parsing, edition adapters, read-only access, schema validation | Simulation mutation during a partially successful load |
| Content model | Stable IDs, car/route parameters, route geometry, event order and scenery dependencies | Hidden graphics-mode-specific physics |
| Presentation commands | Scene/UI intent, projected coordinates where canonical, draw order, stable object/animation IDs | A second independent simulation |
| EGA/CGA providers | Original palette/pixel/mask/animation behavior and profile metrics | Guessed art or modernized geometry |
| Amiga provider | Original bitplanes/palette/masks, presentation and animation mapping | Replacing canonical DOS state with Amiga state during a switch |
| Audio events and providers | Timestamped semantic music/effect commands, DOS PC Speaker and Amiga replay state | Driving physics from audio callback timing |
| Windows host | SDL3 window/input/audio transport, scheduling, filesystem selection, settings and diagnostics | Recovering game rules independently from the portable core |
| Local verification tools | Differential state, pixels, audio events, resource accounting and coverage | Original game payload embedded in published fixtures |

SDL3 and CMake are proposed host/build choices supported by their official documentation in the source register. Pin versions and Windows/compiler baselines when implementation starts. Keep the core buildable without SDL on Windows and at least one second host/compiler. Windows x64 is the initial proposed release target; Windows ARM64/32 bit are later product choices, not current promises.

## C portability and exact behavior

Use fixed-width integers and explicit little/big-endian readers. Avoid direct struct overlays on file bytes, unaligned loads, host `long` assumptions, pointer-sized save fields and native signed-overflow dependence. Write defined helpers for original wrap/carry/truncation and negative shifts/divisions where necessary. Confirm the exact original expression order and rounding at every simulation boundary.

Pointers and handles in the C state must have known lifetimes. Replace 16 bit segmentation only after aliasing is understood; retain offset-based representations when they express original semantics more reliably. No final dependency on DOSBox, an x86 interpreter, Amiga emulation or invoking the original executable is accepted as the recovered portable core.

Keep one explicit simulation clock. Recover timer cadence and how it interacts with main-loop iterations before selecting a step size. Rendering and host PCM sample rates can differ without changing simulation ticks. Preserve event ordering and RNG consumption when a window resizes, focus changes, sound device resets or graphics profiles switch.

## Original data and distribution boundary

The application will require a user selected DOS data directory. The Amiga data directory/archive is optional until an Amiga feature or Northern Germany Challenge is selected. Validate editions by structural checks and admitted fingerprints; avoid silently accepting arbitrary same-named files.

The original EXEs may need to remain external resource containers because they contain game text and other embedded data. Recover precise extraction ranges and transformations instead of copying those media into generated C arrays. Treat executable unpacking as a data transform for resource access if needed; final native gameplay never executes the original instructions.

Original artwork, fonts, maps, car/scenery data, audio, game text and extracted payloads must not enter the distributable, including through generated headers, PE resources, compressed blobs, base64 strings, screenshots or tests. Review behavior constants separately from presentation/resource tables; a compiled-in table requires a documented classification. User-supplied data can be decoded into memory or a local cache with provenance and invalidation keys. The cache stays outside the package and is reproducible from the originals.

Selections, high scores, settings and caches belong in a separate user profile. Loading originals must not update their timestamps through writes or overwrite their contents. Packages and optional archives are untrusted input: validate path boundaries, lengths, member identity and maximum decompression before committing a content set.

## Content identity and Northern Germany Challenge

Use separate internal identities for platform, edition, content pack and object. File names are lookup evidence, not universal IDs. Amiga `scen2` and `scen3` reuse `euro_` names and identical catalogs, while route/media bytes differ. They must stay distinct until mapped; the user has identified the required extra content as Northern Germany Challenge, but the exact supplied member association needs proof.

The route adapter must carry section links, geometry, distance/height units, object placement, signs, hazards, collision-relevant references, checkpoint/finish conditions, scoring/progression events and all identified source fields. Expose unresolved fields rather than dropping them. Content import can transform representation; it cannot invent missing gameplay semantics.

Northern Germany Challenge is optional by availability and required by project scope when necessary files are supplied. The initial supported set must be enumerated in a dependency manifest after phase 4 analysis. Detect absent, partial, corrupt and conflicting packs separately. The game remains usable with valid DOS-only content. Do not report the extra scenery complete just because a menu entry appears.

## Graphics contracts

Retain indexed pixels and palette roles until host presentation. Recover profile dimensions, aspect ratio, offsets, mask rules and animation timing from the original code. A software reference framebuffer simplifies comparison; host texture scaling must account for pitch, logical size and aspect rather than changing game coordinates.

Define whether projection belongs to the canonical core or presentation by actual cross-platform differences. If renderer-specific projection is necessary, it may read canonical scene geometry and time but may not mutate physics, collisions or RNG. Compare object visibility, relative placement and occlusion against each edition rather than only final image colors.

Stable semantic IDs connect car state to dashboards, mirrors/rear sprites, road objects, signs, UI text and animation events. A profile needs complete mappings for the current content. Northern Germany Challenge may have objects without DOS counterparts; recover any valid reuse mapping from original assets. Unsupported combinations stay visibly unavailable until their coverage is complete. Artificially drawing substitute scenery is outside the fidelity requirement.

## Atomic graphics switching

1. Receive a graphics-mode request without advancing game state extra times.
2. Validate the target profile against the current car, scenery, UI state and active animations.
3. Load/prepare resources, palette, masks, draw metrics and caches off the active draw path. Keep the current provider valid until preparation succeeds.
4. At a presentation frame boundary, commit all target references together. Avoid half-old/half-new frame resources.
5. Render from the same canonical simulation snapshot and semantic animation position.
6. On failure, retain the current provider and report the missing dependency. Do not restart the race, reload the route, reset RNG or change scoring/timers.

Use a read-only snapshot at commit to verify tick, input, RNG, position, vehicle/opponent state, route progress and pending game events remain identical. Provider caches may change; canonical state may not.

## Audio contracts and switching

DOS PC Speaker music/effects need accurate sequencer timing and speaker/PIT behavior, including effects priority and any one-bit waveform use. Recover and validate these paths from the supplied DOS code and resources.

Amiga replay requires the recovered music code and sample providers, with channel assignment, period, volume, loop and effects interaction. Determine PAL/NTSC timing and filter/panning assumptions from the admitted edition. Host PCM output is a transport layer, not the recovered sequencer.

Graphics, music and effects should be independently selectable where the evidence establishes the combination. Coupled platform presets may be convenient but cannot replace the requested choices. Disabled choices need a concrete missing-data/unsupported-content reason.

An audio switch prepares the destination song/effect state from a semantic event timeline, commits at a block/event boundary, and retires old references only after the audio thread can no longer use them. Preserve cue/loop position where a proven mapping exists. If track structures cannot map, use a documented deterministic restart at a safe cue/block boundary; any optional fade is a transition policy requiring listening acceptance. The gameplay timer never resets, and current engine/effect semantics remain consistent. Test active effects, engine transitions, music overlap and device changes to detect stuck notes, duplicate cues and stale samples. Audio thread work must be bounded and must not perform synchronous archive extraction or unbounded allocations.

## Proposed future source layout

This is a directory plan, not directories/source created by this planning task:

| Path | Purpose |
| --- | --- |
| `src/core` | Portable game state and behavior |
| `src/formats/dos` and `src/formats/amiga` | Validated external resource readers |
| `src/content` | Car/scenery normalization and dependency manifests |
| `src/video/ega`, `src/video/cga`, `src/video/amiga` | Presentation providers |
| `src/audio` | Sequencers, DOS PC Speaker and Amiga backends |
| `src/platform/windows` | Native host and user-data integration |
| `tools` | Later analysis/inspection utilities, no game payload |
| `tests` | Synthetic fixtures and payload-free differential contracts |
| `docs/formats` and `docs/recovery` | Admitted schemas, function maps, decisions and evidence |
| Private excluded analysis/run/cache directories | Derived binaries, emulator state, resource previews and captured originals |

Build outputs and release manifests must make the external-data boundary auditable. Dependency license review concerns only selected code/libraries and patch reuse; it does not grant rights to original game media.
