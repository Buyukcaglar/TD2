# kylofon SDL3 port: platform, build and host review

Review date: 22 October 2026. Upstream: `https://github.com/kylofon/test-drive-2-sdl3`, commit `352b56824d8c91e938b8f0794a71afca9a276193`. All upstream locators below are relative to `reference/repos/kylofon-test-drive-2-sdl3/` at that commit. This is source/document analysis; the reviewer did not compile, launch, render or play the port. A source comment saying "verified" is an upstream assertion unless independently matched to our original-byte evidence.

## Assessment

This is a substantial, coherent EGA implementation candidate: an SDL host, external-EXE data loader, segmented memory representation, game-address-to-C dispatch, four-plane software graphics, keyboard and gamepad adapters, original-style resource cache, decompression, PC Speaker effect/music sequencing, and timing APIs are implemented. Reusing it could avoid writing these systems from scratch. The right route is a separately pinned implementation candidate with our instruction-level evidence retained as the authority for disagreements. A mechanical merge into `src/recovered` or a blanket Phase 1 completion claim would discard valuable guarantees.

The most decisive cross-check is an actual source conflict: upstream `platform/timer.c:207-216` changes the `06C9:5D83/5D8D` read to `0040:006C`; our admitted bytes read `0040:046C`, physical `0x086C`. Source quantity and reported playability cannot settle that discrepancy. Independent segment/stack profiles, memory wrapping, resource lifetimes and actual host behavior also remain separate validation obligations.

## Review coverage

| Files examined | Result / coverage |
| --- | --- |
| `README.md`, `LICENSE`, `td2port/PORTING.md`, `td2port/CMakeLists.txt` | Read build, claims, dependencies, license text, deliberate changes and port rules. |
| `td2port/src/build.h`, `types.h`, `main.c`, `mem.c`, `mem.h`, `host.c`, `host.h`, `codeptr.c`, `codeptr.h` | Read implementation and declarations throughout. |
| `td2port/src/symbols.h` | Generated 1,091 function/global/address macros; inspected generation contract, naming/layout and relevant platform bindings. This is an index, not independent proof of every assigned name. |
| `td2port/src/platform/gfx.c`, `gfx.h`, `gfx_ega.h`, `gfx_blit.c` | Read all primitives, hardware helpers, blit families and wrappers. |
| `td2port/src/platform/input.c`, `input.h`, `prompts.c`, `prompts.h` | Read keyboard vectors/translation/dispatch, hotkeys, input, prompts, editor and calibration code. |
| `td2port/src/platform/res.c`, `res.h` | Read all filesystem, decompression, resource lookup, memory/cache, trigonometry, RNG and synthetic-stack code. |
| `td2port/src/platform/sound.c`, `sound.h`, `timer.c`, `timer.h` | Read all sequencing, timer-list, clock and device adaptation code. |
| `port/spec/platform.md`, `port/spec/platform_symbols.csv` | Reviewed function/global tables, pseudocode, formats, host replacements, timing, TD1 comparisons and unresolved questions. CSV has 267 function and 199 global rows. Duplicate descriptions and upstream confidence labels are retained as claims. |
| Our `docs/planning/architecture.md`, `validation.md`; relevant `docs/recovery` and `src/recovered` timer/graphics/RNG records | Cross-check against target architecture, custody, gate definitions and admitted independent-segment/actual-stack models. |

Game sources/specifications and reverse-engineering tools have separate companion reviews. This report does not claim full semantic validation of every generated symbol or every upstream instruction transcription.

## What can be reused

| Area | Concrete implementation | Reuse value and required boundary |
| --- | --- | --- |
| SDL host | `host.c:43-95`, `147-216`, `431-487` | Window, nearest-neighbor presentation with 4:3 display, keyboard, gamepad, pacing and audio stream plumbing. Keep original input directory read-only and introduce a writable profile before use. |
| External original EXE | `mem.c:97-173` | Loads and unpacks external TD2EGA data, relocates into `mem[]`, then uses C functions rather than executing loaded x86. Add admitted fingerprints and bounded loading. |
| Stable address mapping | `mem.h:17-68`, `codeptr.c:10-34` | Original offsets let our recovered contracts and upstream functions be aligned without names being trusted. Qualify segment assumptions and callback targets before replacing our APIs. |
| EGA graphics | `gfx.c:36-80`, `156-1040`; `gfx_blit.c:185-477` | Four-plane indexed rendering, descriptors, clipping, text, fills, lines, dissolves, grabs and 24 sprite entry points. Useful implementation coverage well beyond our bounded leaf contracts, but not yet our hardware/pixel acceptance. |
| Input/UI | `input.c:53-558`; `prompts.c:26-177` | Original key table data is loaded from the EXE; code implements one-key semantics, hotkeys, prompts and editor. Gamepad timing/calibration is an explicit new adapter. |
| Resources/cache | `res.c:180-1135` | Size helpers, external files, packed stages/archives, lookup, per-block UNFLIP, named memory records and cache moves. Reconcile with our alias/zero-count/caller lifetime tests instead of assuming the simpler contract is universal. |
| Timer/event sequencers | `timer.c:65-305`, `sound.c:54-406` | Strong source starting point for PC Speaker music/effects and callback order. Keep sequencer/register evidence separate from final PCM and real IRQ behavior. |
| RNG | `res.c:1102-1111` | Preserves decrementing word index, low-byte table selection and byte rotate behavior. Initial table stays external. Use our accepted byte-ring comparison suite as an independent check; initial ownership and consumption history remain open. |

The platform is EGA-specific. `build.h:16-18` deliberately fails compilation when CGA is enabled. Neither CGA implementation nor Amiga media/audio nor live provider switching is supplied by these modules.

## Findings and tightening work

### KP-01: literal external-memory read conflicts with admitted bytes

**Confirmed disagreement, high priority.** `timer.c:207-216` reads `rd16(0x40, 0x6C)` for both helpers. `timer.h:27` and `port/spec/platform.md:1600-1601` call this BIOS ticks. Our `docs/recovery/td2ega-startup.md:100` records original instructions reading `ES=0040h`, offset `046Ch`, physical `086Ch`. Our bounded comparisons deliberately preserve that address without assigning units or historical cause.

Tightening: retain `0040:046C` in canonical recovered semantics; place the upstream normalization in the discrepancy register. Prove call reachability and any desired native-host substitution separately. Do not rename our literal helper or change its accepted receipt to match the upstream narrative. Even if dropped disk code makes the discrepancy irrelevant to ordinary port play, that is a scope qualification, not original-code agreement.

### KP-02: fixed DS/SS and synthetic locals cannot inherit actual-stack proof

**Confirmed contract reduction.** `mem.h:10-13` assumes the stack is in DGROUP, all `DS*` macros use fixed `DGROUP`, and `res.h:102-108` states `SS=DS`. `res.c:1116-1135` allocates zeroed near-pointer locals using a host-side `port_sp`. C call frames never perform the original SS stores. `input.c:294-297` explicitly removes the `SS != DS` peek-only case.

Our current bus interfaces deliberately compare independent DS/SS, actual PUSH/CALL/RET memory effects and aliases, including conditional writes into input/control views. These are broader contracts. The synthetic stack is useful for a valid native caller profile but cannot establish the original frame/alias/lifetime behavior. `DS_STACK_TOP=0xA3CE` is a selected native allocation policy; it is not fresh evidence that all historical contexts used that stack.

Tightening: define a normal native caller profile and show why excluded contexts are unreachable there, while preserving our raw/bounded contracts. Differential bridge code must adapt observations explicitly; do not replace a bus function with the upstream C function and label earlier tests inherited.

### KP-03: memory addressing and multi-byte reads differ outside normal ranges

**Confirmed representation difference.** `mem.h:17,29-37` has a `0x110000` byte array, computes `(segment << 4) + offset` without a 20-bit wrap, and reads the second/third/fourth byte contiguously. Our validation model wraps physical addresses at 20 bits and retains original operand ordering. `far_add` wraps a 16-bit offset (`mem.h:64`), but that does not make every multi-byte read or high linear address equivalent. Direct `DSW`/`DSL` lvalues also bypass byte-granular wrap helpers.

Tightening: either implement the admitted memory semantics or prove and document the native valid-state bounds under which these differences cannot be observed. Add focused integration cases for last-byte word/dword reads, high segment aliases, low memory, and live descriptor/table views. Do not generalize normal Collection data success into arbitrary context equivalence.

### KP-04: C portability has known source-level hazards

**Confirmed source patterns; behavior not executed here.** `mem.h:39-53` casts byte-array addresses to `u16*`, `s16*`, `u32*`, `s32*`, assuming little-endian aligned host access. Several original offsets are odd; for example music tempo uses `DSW(DS_mus_tempo)` and the symbol is `0x65D3` (`sound.c:295,316-322`, `platform.md:538`). `-fno-strict-aliasing` in CMake reduces one optimizer risk but does not establish alignment portability. `idiv32_16` performs signed C division before range checking (`mem.h:82-88`), so `INT32_MIN / -1` needs handling before the division. Signed right shifts and the claim that all MSC long helpers are ordinary C operators (`mem.h:103-104`) require width/overflow/shift review.

Tightening: use explicit byte accessors and defined-width wrap/shift/divide helpers; retain our C17 strict-warning build contract. Build selected portable core with a second compiler/host and appropriate undefined/alignment checks. This is relevant to R07; a Windows x64 executable alone is not portability proof.

### KP-05: source directory is intentionally writable

**Confirmed custody incompatibility.** README requires a writable game directory and says selection/high scores are saved there. `host.c:498-517` resolves both reads and new file names under `game_dir`; `res.c:302-331` opens writes through that resolver with `"wb"`. Our architecture requires a separate writable user profile and immutable originals.

Tightening: separate read-only original lookup from profile lookup/create; import originals' settings only by an explicit adapter, write only to profile, and validate source hashes/mtime/attributes after runs. Do not point this unmodified port at `reference/dos`. Future runtime evaluation must use isolated disposable copies until the adapter exists.

### KP-06: executable admission is heuristic and loader bounds need repair

**Confirmed source limitations.** `mem.c:135-156` accepts a `0x1FCC0` image plus three fixed strings, rather than the project's admitted file/image hashes and relocation identity. EXEPACK relocation counts check only that the next count word fits, then read `n` entries without a corresponding inner bound (`mem.c:50-60`). `packed_len` arithmetic trusts `skip_len` (`63-68`). The raw-MZ path does not verify relocation allocation success (`127-132`), and relocation entries outside image bounds are silently skipped (`141-147`). `--check` only invokes this loader then exits (`main.c:43-51`).

Tightening: use our validated unpacking/admission metadata and explicitly check size arithmetic, header/table spans, counts, allocation and every relocation. Keep original image, relocated image and intentional copy-protection state changes distinct in provenance. Treat `--check` as loader smoke only; it does not parse all resources, run a session, test graphics/audio or establish version parity.

### KP-07: timing policies deliberately change original behavior

**Confirmed changes.** The host uses rational `PIT_DIV_GAME/PIT_HZ` tick scheduling (`host.c:97-100`), a catch-up limit of 50 ticks followed by clock resynchronization (`169-184`), and default driving draw rate 15 FPS (`host.h:29-35`, `host.c:201-216`). Rendering is VSync paced. Source comments recognize some game fields count rendered frames. Original slow-clock high/low comparison quirks are replaced by ordinary `u32` comparison (`timer.c:275-305`, `input.c:350-370`). PIT reprogramming ignores the supplied divisor and assumes the only admitted game value (`timer.c:124-126`).

Tightening: label host pacing and robustness policies explicitly and measure simulation/checkpoint/event equality under a controlled deterministic runner. Include stalls, prolonged sessions, low-word rollover, pause/resume and draw-rate dependence. Preserve timing quirks in the recovered oracle where required, even if a native product profile intentionally repairs them. A fixed 100 Hz callback rate alone does not establish original ISR scheduling or draw-dependent behavior.

### KP-08: PC Speaker sequencer implementation is useful, PCM is approximate

**Confirmed design.** `sound.c` implements the stream player, effect priorities/shared busy flag, song lists, voice loads, articulation, arpeggio and vibrato while reading original tables externally. It adds a 100,000-opcode guard (`17-20`, `70`, `272`, `282`, `378`) and selects 8086-style shifts while retaining a CPU-family TODO (`47-51`). `host.c:102-123` synthesizes one tick of square-wave audio from the final divisor/gate state and drops queued output when the device falls behind. `host_speaker` only stores the current state (`492-496`), so multiple register events inside a tick are not timestamped individually. PIT mode behavior and audible phase transitions are not independently established.

Tightening: compare ordered PIT/gate events and sequencer state against admitted originals first; validate waveform/pitch/phase/queue/device behavior separately. Retain original VOICES heap-adjacency as a hypothesis requiring actual allocation/lifetime and data evidence (`platform.md:2377-2383`, open question `2844-2847`). Do not copy voice bytes from SONGS into code or claim sound fidelity from a player listing.

### KP-09: graphics preserves many quirks but still narrows malformed-state contracts

**Mixed faithful detail and explicit reductions.** The code preserves bit-mask leakage (`gfx.c:561-566`), zero-height constructor LOOP expansion (`252-257`), constant-plane quirks and multiple zero-width blit LOOP cases (`gfx_blit.c:5-19`, `38-169`). That makes it a valuable independent implementation candidate. However fifth destination entries are dropped rather than reproducing original frame overlap (`gfx_blit.c:267-287`, `371-380`), and dissolve overflow is represented in extended host arrays (`gfx.c:844-874`). EGA memory is outside `mem[]`, and VRAM dispatch recognizes exactly segment `A000h` (`gfx_ega.h:82-87`), so equivalent physical segment aliases need qualification. `ega_write` uses current destination data for logical/masked operations (`54-79`); full latch/ROP equivalence needs focused hardware/reference tests, not the EgaState name alone.

Tightening: cross-check our EGA port traces and primitive contracts with this model under admitted valid input bounds. Cover clipping, every shift/op, inherited register state, stale latches, overlap, zero width/height, planar masks and aliased video addresses. Then compare indexed pixels/palette/frame sequencing and obtain visual review. Do not equate bounded RAM writes or the software EGA model with real adapter acceptance.

### KP-10: original decoders and safe resource readers need distinct contracts

**Confirmed deviations and open bounds.** Runtime RLE uses a replacement escape-table policy when zero or too many escapes occur (`res.c:430-438`), and UNFLIP skips empty dimensions (`642-655`). Huffman and other loops intentionally retain several original unchecked behaviors (`443-497`). File loading is capped only by remaining global `mem[]` bytes, not the particular allocation (`74-83`, `266-279`); decompression does not implement a complete file/block boundary policy. This is unsuitable as the sole bounded external-input reader without validation.

Tightening: retain exact behavior models for recovery/differential evidence, and admit a separately bounded external-resource path with explicit supported-input constraints. Full corpus parse/disposition, corruption/truncation and decompression budget checks remain R04 tasks. Upstream claims 164 archives + 19 packed stages matched in a private `work/platform/emu_unpack.py` (`platform.md:2282-2316`); that script/receipt is not part of this checkout and the claim must be reproduced locally before it receives our acceptance credit.

### KP-11: specifications and implementation have drifted

**Confirmed inconsistencies.** The platform specification's memory-manager recommendation after the SDL replacement table proposes stable host pointers/name-keyed caching; `res.c:743-1097` actually retains segmented named records, moves and compaction. `platform.md:1919-1920` describes a stage copy direction/length inconsistent with the current project's admitted DAT-to-`DS:346A..52C7` view. `platform.md:2138-2143` says `mem_release_cache` returns its new segment; `res.c:1060-1062` explicitly corrects that to `0:off`. `PORTING.md` still discusses expected unfinished links while README claims a release. The 11927 divisor in the `host.c:26` comment differs from the actual `PIT_DIV_GAME=11932` implementation.

Tightening: prefer actual code and original bytes to prose, keep a source/spec discrepancy ledger, and transfer only independently checked format/consumer facts into our resource registry. Treat every "no callers" label and global `DS=SS` statement as a scoped analysis claim, not an exclusion proof. Avoid copying upstream recommendations into our plan without identifying whether they are implemented.

### KP-12: no checked-in acceptance suite or build pin exists

**Confirmed checkout scope.** CMake sets C11, requires an externally found SDL3 package and builds one executable from all C files. It has no core library/test target, pinned SDL version/hash, CTest suite or CI acceptance matrix. MSVC uses `/W3`; non-MSVC uses `-fno-strict-aliasing` and disables unused-parameter warnings, with an additional GCC format-truncation suppression. The one workflow is mirroring, not game validation. Documentation references private scratch emulation, screenshots and unpack checks that are absent from the tracked tree.

Tightening: import in an isolated writable candidate tree after reference freeze; preserve MIT notice, pin tool/dependency versions, establish C17/MSVC and second-compiler builds, make an SDL-free deterministic runner, attach our accepted differential packets through explicit adapters, and later conduct real sessions/pixel/audio acceptance. Build success must remain separate from source contracts and gameplay.

### KP-13: host robustness and event lifecycle still need product tests

**Source-review risk, not a demonstrated runtime failure.** `process_events` covers quit, key up/down, fullscreen and gamepad addition/removal (`host.c:431-470`); no focus-loss reset or audio-device lifecycle is present there. Pressing both physical modifier keys maps them to one XT scan byte, so release ordering deserves tests. Delays/prompts call `host_pump` and may reenter tick dispatch; the model does not expose actual IF/IRQ frames. Termination calls `exit` directly from host/prompt code, making deterministic integration testing harder.

Tightening: test focus loss while a key is held, release outside window, paired modifier keys, existing/removed/reconnected gamepads, audio removal, fullscreen/resize, prompt entry from callback dispatch, and quit from each state. Adapt event boundaries without changing canonical tick/RNG ordering.

## License and media handling

`LICENSE:1-21` supplies MIT terms for code/documentation, including retention of copyright/permission notice in copies or substantial portions. Its trailing notice excludes original game/data from that grant. A code reuse path should preserve the upstream notice and record exact source origins; no upstream contact or publication is implied by this analysis.

Source generally reads palettes, fonts, strings, sprites, tables and song data from the external EXE/resources. The private clone nevertheless contains original-data descriptions and literal payloads in documentation: the complete built-in glyph hex table at `port/spec/platform.md:1280-1297`, speaker divisor data at `2391-2399`, and concrete original text/data examples. Our no-original-media packaging rule therefore still applies to copied documentation and generated headers as well as binaries. Keep reference documentation private and perform a payload review before selecting files for distribution. This review does not certify every source literal as algorithmic or permitted media.

## Suggested admission work and phase mapping

1. Freeze upstream commit/tree/files and separate writable candidate/build/run directories. Retain current recovered source and receipts untouched.
2. Establish exact original-image and resource identity compatibility against our admitted EGA file. Reconcile KP-01, loader bounds and intentional copy-protection mutations before assigning original-byte equivalence.
3. Create address-based crosswalks from upstream functions/globals to our function/resource IDs, with explicit dispositions: matched contract, narrower normal-caller profile, deliberate native policy, conflict, or unresolved.
4. Port our meaningful independent vectors and actual-stack/bus witnesses to a differential adapter. This must expose mismatches, not normalize both sides to the upstream result. Include arithmetic/shift/division, memory wrapping, resource moves/lifetimes, callback publication and timer/input order.
5. Complete EGA closure against revised evidence, then analyze the still-unimplemented CGA branch in the required order. Decoder and format leads may accelerate investigation, but a PCS tool or macro is not CGA game implementation.
6. In Phase 2, perform bounded full-corpus parsing and file/embedded-media disposition. In Phase 3, add read-only originals + profile storage, deterministic host/core boundaries, complete sessions and pixel/audio review. Amiga and live switching retain their existing later gates.

A separate product-oriented fork can gain time by keeping original offsets and using upstream's integrated platform initially. A final provider architecture still needs semantic state/event interfaces because current `mem[]`, descriptors, resources, graphics and audio are coupled to the EGA layout. Large-scale typed-state refactoring before proving an admitted baseline would spend part of the expected time saving and make disagreement localization harder.

## Evidence boundary

This report establishes source implementation coverage, concrete textual/code differences and a reuse path. It establishes neither a successful local build nor actual local playability, whole-core completeness, DOS/IRQ/device timing, full-corpus decoding, visual/audio acceptance, original edition fidelity, CGA/Amiga support or live switching. It does not change existing acceptance statuses by itself.
