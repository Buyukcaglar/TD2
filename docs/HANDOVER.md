# Project handover and salvage report (24 October 2026)

This file replaces `docs/planning/continuation.md` as the place to start. That file, `backlog.json`, `progress.json` and the P-gate structure are kept for history but no longer drive the work.

## 0. Current state (end of session 3, 24 October 2026)

M0 "Adopt" is done except the user's play test. M1 "Verify EGA" has started.

- **Code.** The Kylofon port is vendored in `port/td2/` (provenance and local changes in `port/td2/PROVENANCE.md`). Local fixes: 20-bit address wrap, the `INT32_MIN / -1` division guard, EXEPACK bounds checks, and `--user-dir` so scores and `SELECT.DAT` never go to the game folder.
- **Build.** `.\build.ps1` (add `-Clean` for a fresh build) builds `build\td2port.exe` and `build\td2diff.dll` with MSVC 14.44, the VS-bundled CMake and Ninja, and SDL3 3.4.18. It builds with no warnings at `/W3`.
- **Run.** `.\run.ps1` copies `reference\dos` to `runs\game` on first use and plays with `--user-dir runs\profile`. `.\run.ps1 --check` prints `TD2EGA.EXE ok (EGA): image 130240 bytes at 1000:0000, DGROUP 278F`.
- **Headless check.** With `SDL_VIDEO_DRIVER=dummy` and `TD2_SNAPSHOT_DIR` set, the game ran 90 s without errors. The snapshots show the Accolade and DSI logos, credits, the high-score table, the race-against and select menus, skill level and the attract-mode drive with cockpit, traffic and scenery.
- **Not yet done.** Nobody has played a race. The user has been asked to play one race on each scenery (CCC, ec_, TDS2) and report problems. Without `--user-dir` the game creates `%APPDATA%\TestDrive2` as its profile folder. No run has saved a score or `SELECT.DAT` yet, so the write path is untested.
- **Differential harness.** `tools/diffharness/` runs an original function under Unicorn and the port's C function from `build\td2diff.dll` on the same memory snapshot. It compares the returned registers and every changed memory byte, excluding the original's own stack frame. Run it with:

  ```
  $env:PYTHONPATH = "analysis/tools/python;tools"; python -m diffharness
  ```

  It rewrites `docs/verification.md`. Its own tests are in `tests/test_diffharness.py`; they check that it catches deliberate register and memory mismatches. First results: rand8, curve_sum, free_rev, drag_apply, brake, update_rpm, overrev_check, rle_decode and huff_decode all match on 200 randomised cases each. The unpacker cases cover every packed PES, PCS and DAT file.
- **PC speaker sound (session 3).** Synthesis moved from `host.c` to `speaker.c`, which has no SDL dependency. It models PIT channel 2 in mode 3: the speaker follows port 61h bit 1 AND the PIT output, a low gate holds the output high, and raising the gate restarts the wave. The square wave is averaged exactly over each sample on a 4× grid, then passes a 9 kHz two-pole low-pass (the cone) and a 10 Hz DC blocker. Aliasing is 20 to 35 dB lower than before, ultrasonic divisors no longer fold into audible whines, and a stopped note settles to silence. Tests are in `tests/test_speaker.py`. Set `TD2_AUDIO_DUMP=<file>.wav` to record what the speaker plays. Nobody has listened to it yet; the cut-offs are in `speaker.h` if it sounds too dull or too bright.
- **Adding a function to the harness** takes three steps: add an adapter in `tools/diffharness/adapters.c`, add a `Spec` with an input generator in `tools/diffharness/cases.py`, and rebuild.

### Next steps (in order)

1. **Billboard collision** (`sim_motion.c:436`). For sign types ≥ 50h the original tests a stale BP. Add the collision function to the harness, feed it BP values from real driving states, and decide from the result whether some billboard hits should not crash.
2. **Neutral clutch grind** (`sim.c:265`). In neutral the original compares leftover CX/DX (throttle byte or joystick value, and 0100h), which can start the grind tone. Model those leftovers instead of skipping the check, and add a harness case.

3. **Traffic seeding** (`sim_traffic.c:244, 367`). The original leaves DI and CX uninitialised there. Use the harness to check whether the leftovers ever change which car is picked.

After those: the cockpit marker's CH (`scene_cockpit.c:207`), then whole-tick subsystem tests (run the original sim tick and `sim_tick` on the same state) before CGA.

### Open questions

- Is the playable game correct over a full race? Waiting on the user's play test.
- Harness speed is about 50 ms per case, mostly 1 MiB snapshot copies. That is fine for hundreds of cases. For whole-tick tests with many cases, copy only the changed pages.

## 1. TL;DR

- **Goal (unchanged).** A native Windows Test Drive II built on portable C. It reads the user's original DOS files and supports EGA, then CGA. Later it adds Amiga graphics, music and sound effects, plus the Amiga "Northern Germany Challenge" scenery, all switchable live during play.
- **What the previous agent did.** Eleven days (13–22 October), with one commit on 13 October. It produced:
  - 12.5k lines of x86-literal C leaf functions;
  - 1,293 JSON "receipts" taking 205 MB;
  - 178 copies of one map file and 175 of another;
  - a 203–461 engineer-day estimate.

  There is no playable result. The rest of this report calls that previous agent "the predecessor".
- **What already exists.** A third-party, MIT-licensed, playable C11/SDL3 reimplementation of TD2EGA (Kylofon, `reference/repos/kylofon-test-drive-2-sdl3`, commit `352b568`, v0.1.0, about 11.7k lines). The predecessor reviewed it, then admitted only 11 functions from it. All 11 were functions it had already recovered itself.
- **Verified in this session.** The existing MSVC build of a patched Kylofon copy loads our `TD2EGA.EXE`:

  ```
  analysis/candidates/kylofon-r03-v1/native-build-v1/candidate/td2r03_full.exe
  ```

  - `--check` printed `TD2EGA.EXE ok (EGA): image 130240 bytes at 1000:0000, DGROUP 278F`.
  - A normal launch opened the game and was still running when killed after 6 seconds.
  - Both runs used a scratch copy of `reference/dos`. The originals are unchanged.
  - Nobody has played it through yet.
- **Recommendation.** Make the Kylofon port this project's codebase. Verify it by playing and by bulk differential tests. Then add CGA as a second presentation backend, and do the Amiga work on top of a backend/provider split. Details are in section 7. The work prompt for the next session is in [NEXT-SESSION-PROMPT.md](NEXT-SESSION-PROMPT.md).

## 2. Requirements (from `docs/planning/roadmap.md`, still valid)

1. Recover portable C from `TD2EGA.EXE` (primary), then analyse `TD2CGA.EXE` graphics.
2. Decode every supplied DOS resource, including data embedded in the EXEs.
3. Native Windows game on that C core. It reads the user's files and ships no original media.
4. Analyse and decompile the supplied Amiga game (`reference/amiga/TestDrive2&DataDisks_v1.1_HD_JOTD.lha`, JOTD HD install v1.1, not WHDLoad). Distinguish its patches from original disk behaviour.
5. Amiga graphics, animation, music and SFX, selectable live alongside EGA, CGA and PC Speaker. Graphics, music and effects switch independently, with no simulation reset.
6. Northern Germany Challenge scenery (route and gameplay, not just media) when its files are supplied. The candidate is the Amiga tree `scen3`.

Hard rules that stay:

- `reference/` is read-only.
- No original media in the repo or in a distributable.
- Game runs use a writable copy of the data.
- DOS audio is PC Speaker only (no AdLib).
- Tandy is context only, not a deliverable.

## 3. Why the project stalled (do not repeat)

1. **Fidelity at the wrong level.** Every C function had to match the original under Unicorn on:
   - all 1 MiB of RAM, flags (including AF), stack aliasing and DS≠SS profiles;
   - two load segments.

   Functions already passed were then re-recovered as "bus" variants (`timer_handler`, `timer_handler_bus`, `timer_handler_bus_flags`). None of this composes into a game: every module takes the raw 1 MiB memory and private register structs.
2. **Write-once evidence bureaucracy.** Every step produced new versioned receipts that could not be overwritten, plus "consumed maker" scripts that must not be rerun. Whole-program maps were regenerated after each step: `td2ega-control-map-v1..v178.json` and `td2ega-resource-consumer-map-v1..v175.json`, about 650 KB each. In addition there were eight acceptance gates per function and custody audits re-hashing all 250 originals.
3. **Refusal to assign meaning.** It would not name the 100 Hz timer, the RNG, the race states or the copy protection. No game-level model ever formed, and every document ends with "gates remain open".
4. **Reuse treated as a compliance exercise.** It found a working port and spent the remaining days on admission and custody reviews.
5. **Unreadable handoffs.** `continuation.md` has words run together ("actualSSframe", "nativev1REGISTERED") and is 27 KB of status for a project with no executable output.

## 4. Salvage inventory

### Keep and use

| Asset | Path | Why |
|---|---|---|
| Kylofon port (read-only clone) | `reference/repos/kylofon-test-drive-2-sdl3` | Playable EGA game in C plus format docs, specs, symbol tables and EGA/CGA/TDY function indexes |
| Patched Kylofon copy and build | `analysis/candidates/kylofon-r03-v1/candidate/`, `candidate-fixes-v2.patch`, `native-build-v1/` | Proven MSVC build on this machine. The patch adds a 20-bit wrap, a division guard, a user-profile directory and a stricter EXE loader |
| Direct MSVC build script | `tools/build_kylofon_candidate_v1.py` | Working cl/link recipe (it refuses to reuse an existing output folder) |
| SDL3 3.4.18 VC SDK | `analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18` | Includes the `cmake/` config |
| EXEPACK unpacker and tests | `tools/exepack.py`, `tests/test_exepack.py` | Validated three ways. Use it for CGA and TDY too |
| Unpacked EGA image | `analysis/derived/td2ega-v1/` (`TD2EGA.image.bin`, `TD2EGA.unpacked.exe`, `relocations.json`) | Image SHA-256 `8db38a02…59c4`, 130,240 bytes, 1,652 relocations |
| Unpacker-stub check | `tools/validation/verify_exepack_loader.py` | Runs the original stub under Unicorn |
| Ghidra headless runner and scripts | `tools/run_ghidra.ps1`, `tools/ghidra/*.java` | Ghidra 12.1.3 and JDK 21 are borrowed from `C:\Projects\Civ1RE\tools\` |
| Ghidra projects and exports | `analysis/ghidra-projects/TD2EGA*.gpr`, `analysis/exports/td2ega-v1/` (363 decompiled functions) | Starting point for CGA and verification |
| Flow crawler | `tools/map_ega_flow.py`, output `analysis/flow/indirect-v8/` | Function and instruction map |
| Unicorn/Capstone install | `analysis/tools/python` (unicorn 2.1.4, capstone 5.0.9) | Use `PYTHONPATH=analysis/tools/python` |
| Harness template | `tools/validate_music_tick.py` or `tools/validate_bios_block.py`, plus `tools/validation/twenty_bit_bus.py` | Base for one generic differential harness |
| Registries | `docs/recovery/functions.json` (440 functions), `docs/recovery/resources.json` (305) | Address and range data. Ignore the gate fields |
| Fact documents | `docs/recovery/td2ega-{startup,startup-abi,main-state,state-and-consumers,resource-cache,mutable-platform,timer-control,timer-handler,music-tick,effect-tick,keyboard,key-bindings,key-actions,input-poll,gameport,prefix-stage,run-stage,state-loop,sim-controller,line-draw,sprite-draw,projection}.md` | Exact semantics, useful when verifying Kylofon code |
| Planning facts | `docs/planning/resources.md`, `dos-executables.md`, `amiga-evidence-and-plan.md`, `evidence/reference-manifest.json`, `evidence/resource-observations.json`, `evidence/amiga-member-inventory.json`, `evidence/whdload-source-examination.json` | File inventory, hashes and signatures |
| Working data copy | `analysis/inputs/dos/` (249 files, including TD2CGA, TD2TDY and DUEL) | Do not run games here either; copy it first |

### Reference only (do not extend)

- `src/recovered/*.c|h` (165 modules) and their `tools/compile_*.cmd` and `tools/validate_*.py`. These are exact behaviour notes for about 30 meaningful routines: byte ring, cache, both codec stages, music and effect ticks, keyboard, gameport, timer, line, rectangle and sprite drawing. They are not game code.
- `docs/planning/kylofon-*.md` and `docs/recovery/kylofon-*.md`. The useful content is summarised in section 6.

### Noise (safe to archive out of git later)

- `td2ega-control-map-v1..v177.json` and `td2ega-resource-consumer-map-v1..v174.json` (351 files, 173 MB). On 24 October 2026 they were moved out of git to `analysis/archive/recovery-evidence-maps/`; `analysis/` is gitignored. Only v178 and v175 remain in `docs/recovery/evidence/`. Links to those earlier versions in old documents are now broken; the files themselves are in the archive.
- Per-function `*-validation-vN.json`, `*-build-*.json`, `*-diagnostics-*.json`, the audits and `analysis/history/`.
- The roughly 300 `analysis/{prepare,refine,checkpoint,archive,inspect}_*_vN.py` scripts.
- `docs/planning/kylofon-effort-review.md` and the engineer-week estimates.

Nothing has been deleted. Apart from the map copies above, everything was committed as-is on 24 October 2026.

## 5. Technical fact digest

Addresses are load-relative `seg:off` in the unpacked EGA image. Items marked *[unverified]* are a reader's observation and have not been checked against code.

### Executables

| | TD2EGA | TD2CGA | TD2TDY |
|---|---|---|---|
| File size (bytes) | 114,421 | 104,160 | 103,905 |
| Unpacked image (bytes) | 130,240 | 119,872 | 119,744 |
| Packed entry (CS:IP) | 1AEC:0012 | 186A:0012 | 1858:0012 |
| Original entry | 13A8:03F8 | 1136:03F8 | 1104:03F6 |
| Relocations | 1,652 | 1,652 | 1,674 |
| DGROUP | 178F | 151D | 1505 |

- All three are EXEPACK-packed, with an identical 283-byte stub.
- **CGA has 11 unexplained bytes after its packed data:** `FF 40 00 FF FF 00 00 FF FF 00 00`.
- Built with Microsoft C 5.x in the medium memory model: 22 far code segments, DS = SS = DGROUP. The DSI assembly library from TD1 is linked in.
- **EGA segments:**
  - `0000`: main and DISKID check
  - `00c0`/`010c`: titles
  - `0143`/`019e`: selection and showroom
  - `0267`: gas station, results and filename builders
  - `0432`: CARS/SCENES/select
  - `0645`: high scores
  - `06c9`: driving game at 0000–5CFF, DSI library at 5D00–CD9F
  - `13a3`/`13a8`: C runtime and protection
  - `16a7`–`1769`: helpers, dialogs, UNFLIP
- `DUEL.EXE` menu choices: 1 → `td2cga.exe`, 2 → `td2tdy.exe`, 3 → `td2ega.exe`, 4 → `td2cga.exe herc`.

### Runtime model (EGA)

**Startup.** `13A8:03F8` is the CRT start. It far-calls `main` at `0000:07B3`.

**main, in order:**
1. Resource pool init (`06C9:6F86`).
2. Video: Hercules if `argv[1]=="herc"`, otherwise EGA init `06C9:90E8` (mode 0Dh, palette from DS:6848).
3. Keyboard ISR install (INT09 → 6907, INT16 → 69B7).
4. Load `voices.bin`, then `songs.bin`.
5. Working surface `B0FE(320,200,0F)`.
6. DISKID and copy-protection checks.
7. Menu loop `00C0:039C`, then session `019E:06C5` → stage load `0267:15E4` → race loop `06C9:1B2C`.

**Copy protection.** `13A8:002E` patches its own code. On failure it sabotages: the 1BF7 tail writes to the INT21 vector segment, and the sim branches at 424A, 4275 and 42AD are flipped. Kylofon writes the "passed" state.

**Race loop `06C9:1B2C`.** Each frame runs 11 helpers, then checks the signed byte DS:5490:
- 0 = continue;
- negative = exit;
- 1–9 = dispatch through the table at DS:2302 (handlers 374F, 3532, 3643, 36E0, 371F, 372B, 3737, 3743, 3713). These are probably crash, police, finish and fuel states; Kylofon names them.

**Timer.** The PIT divisor is 0x2E9C, about 100 Hz. The ISR `61BF` calls a far callback list at DS:5F12 (five slots):
- music `75EA`
- sound effects `6269`
- sim tick `403B` (the sim steps every 10th tick)
- `0143:019E`

Flag 5EFE pauses all callbacks.

**RNG.** `06C9:780E` is a byte ring: cursor DS:66E6 and 256 bytes at 66E8, updated as `b=(b<<1)|(b<0x80)`.

**Input.**
- Key-down table at 62BA+scancode.
- Gameport at port 201h.
- Ctrl hotkeys: J joystick on, K joystick off, S sound effects, Q music, P pause, X quit.

**Resource cache and loaders.**
- 48 descriptors of 18 bytes at DS:68E2.
- Packed loader `6D50` dispatches to RLE `6B02` or Huffman `7C16`.
- Graphics loader `1748:000E` tries `.PES` then `.ESH` and runs UNFLIP.

**Literal `0040:046C` read** (5D83/5D8D, physical 086C, not the BIOS tick). It is used only by the protection delay check, so it has no gameplay effect.

### DOS formats (mostly from Kylofon `FORMATS.md`, consistent with our observations)

**Packed files.**
- Header: `u8 type`, then `u24` unpacked size. Type 1 = RLE, 2 = Huffman, `0x80|k` = k passes; `0x82` = Huffman, then RLE.
- Huffman codes are canonical and read LSB-first. RLE uses an escape table.
- PES and most PCS start with 0x82. The ten EC_ PCS files are a single RLE pass (type 01).

**Archives.** `u32 total`, `u16 count`, `char[4]` names, `u32` offsets measured from the end of the table.

**Sprites.**
- Header: `u16 wbytes, h, hot_x, hot_y; s16 x, y; u8 planemap[4]`.
- PES is EGA planar, with planes selected by planemap nibbles.
- PCS is CGA 2 bpp, with storage modes 1–3 in the high nibble of `planemap[2]`.
- Names ending in `M` are masks.

**Car files.**
- `.BIN` (847 bytes; CAMA is 896, and its extra 49 bytes are unread): 0x34F bytes are copied to DS:23A6. The record holds gears, rpm values, the grip constant, ratios, the shift gate, engine strength, an 81-entry torque curve and the cockpit layout.
- `O.BIN` (32 bytes): 16 words of opponent acceleration.
- `.SS`: ASCII `frames standing ticks` followed by 4-character sprite names.

**Stage `.DAT`** (19 files).
- Packed. The unpacked data is an image of DS:346A–52C7; the game copies a fixed 0x1E5E bytes.
- Contents: 20-byte scenery name, 128 road records `[flags,curve,pitch,object]`, objects, zones, colours, length, traffic (up to 50 cars per direction), then the road byte stream.
- One road unit is 256 sub-units, and 420 units make a mile.

**`.SGN`.** 20 billboard records with NUL-terminated text. Only `TDS20.SGN` exists for the master scenery.

**`.FNT`.** Vector font: 64 offsets, then 4-byte line segments, each glyph ending `FF FF`.

**Catalogs and saves.**
- `CARS.DAT`: 12 cars (F40 P959 CAMA DODG GOAT GT50 STNG VETT ROSS COUN LOTU RUF).
- `SCENES.DAT`: CCC (7 stages), `ec_` (6), TDS2 (6).
- `SELECT.DAT`: drive numbers, then car, opponent and scenery.
- `*HISC.DAT`: 340 bytes, a dump of DS:90B8 with a 32-bit additive checksum.
- `DISKID.DAT`: 9 bytes, meaning unknown (protection).

**Audio.**
- `SONGS.BIN`: song → pattern → 2-byte event sequencer.
- `VOICES.BIN` is just `0D 0A`. Voice records are 32 bytes and are probably read from the bytes that follow in memory (SONGS).
- Driving effects come from TD1's effect player.

**Duplicates.**
- CCCCAR1/2 = TDS2CAR1/2.
- CCC.FNT = EC_.FNT.
- `.SS` groups: CAMA = STNG, F40 = LOTU, GOAT = GT50, ROSS = RUF = VETT.

### CGA bootstrap (from Kylofon `port/`)

- `port/td2cga_functions.json` (440 functions) and `td2tdy_functions.json` exist.
- *[unverified]* 325 of 444 EGA functions have identical size, instruction count, calls and strings in CGA. The segments map one-to-one (EGA 06c9 → CGA 06cf, 0267 → 026e, 13a8 → 1136). Names in `port/symbols.csv` (1,091 entries) can therefore be carried over by segment ordinal and call graph.
- The non-matching functions are the CGA work list: graphics library, scene renderer and PCS fix-up.
- CGA video ports are touched at `06cf:345c`, `5c18`, `5e86` and `5ede`.

### Amiga (nothing reverse-engineered yet)

**Archive.** 352 members; 7-Zip 25.01 at `C:\Program Files\7-Zip\7z.exe` extracts it. Main executable `duel` (108,868-byte hunk); launcher `DuelHD`; `sfx/song` (26,852-byte hunk: replay code plus data).

**Formats.**
- 53 ILBM, 2 8SVX and 177 `Rpck`-wrapped members. Some use `PPkc` (PowerPacker).
- *[unverified]* Raw samples are `u32 BE len`, `u16 BE rate`, then 8-bit PCM.

**Car data** *[unverified]*.
- `*.b2` = the DOS `*O.BIN` byte-swapped.
- `*.b` is a 1,670-byte big-endian car record sharing DOS's grip constant.
- `vectorsigns*` use the DOS SGN offset table in big-endian.

**`scen3`, the Northern Germany Challenge candidate** *[unverified]*.
- 37 members with road files 0–6.
- Its `scen.dat2` is byte-identical to scen2's (`scen/euro_`).
- Most roads and shapes are byte copies from other trees under new names. Only `roaddata1` is unique, and some sign files are edited. It may be a remix, not an original data disk. Verify before building a route importer.

**Tools.** No Amiga tools are installed: no emulator, no 68k disassembler, no hunk parser and no Rpck/PowerPacker unpacker. Ghidra handles 68000 Amiga hunks.

## 6. Kylofon port: status and known deviations

**What it is.**
- `td2port/src`, about 11.7k lines: `host.c` (SDL3), `platform/` (gfx, blit, res, timer, sound, input, prompts) and `game/` (flow, scene, sim, ai, traffic, cockpit).
- It loads the user's TD2EGA.EXE, un-EXEPACKs it into `mem[]` and uses the original DS/CS tables in place.
- It has no CGA (`build.h` stops with `#error` when `TD_CGA` is set) and no PCS loader in C. The Python tools do handle PCS.
- The 100 Hz simulation tick is kept; drawing runs at an emulated 15 fps.

**Deviations the predecessor found** (`docs/recovery/kylofon-r02-r03-results.md`, `kylofon-r04-boundary-review.md`):

| Deviation | Player impact |
|---|---|
| `bios_ticks` reads 0040:006C instead of literal 046C | None (unused) |
| No 20-bit wrap; `INT32_MIN/-1` UB; heuristic EXE loader | None with real data (the patch fixes them) |
| Neutral `clutch_check` skipped (`sim.c:265`) | Missing grind tone |
| Billboard collision always crashes; original tests a stale BP for types ≥0x50 (`sim_motion.c:436`) | Some billboard hits may not crash in the original |
| Traffic DI/CX seeding (`sim_traffic.c:244,367`) | Rare |
| Cockpit steering-marker Y forced to CH=0 (`scene_cockpit.c:207`) | Maybe a pixel |
| Short stage DAT zero-filled instead of leaving stale bytes (`flow_stage.c:518`) | Unknown, probably none |
| 15 fps draw pacing; dissolves paced to the timer | Feel difference; configurable |
| PC speaker audio is a square wave synthesised once per 10 ms tick (`host.c:102`) | Audible quality gap |
| About 26 game text format strings compiled into C | Only matters if strict media-free source is wanted; they can be read from the EXE at their DS offsets |

There are 6 `TODO(verify)` and 81 `PORT:` markers in the source; these are good test priorities.

**Build recipe (proven).** MSVC 19.44 from VS 2022 BuildTools 17.14:
- `vcvars64.bat 10.0.26100.0 -vcvars_ver=14.44`
- `cl /TC /std:c17 /W3 /O2 /utf-8 /MD /D_CRT_SECURE_NO_WARNINGS`
- Link SDL3.lib, bcrypt and the Win32 libraries.

See `tools/build_kylofon_candidate_v1.py`. Alternatively use CMake with `-DSDL3_DIR=…/sdl3-3.4.18/sdk/SDL3-3.4.18/cmake` from an x64 Native Tools prompt. VS-bundled cmake exists; no standalone cmake or ninja is on PATH.

**Run.**

```
td2r03_full.exe --game-dir <writable copy of reference\dos> --user-dir <dir>
```

Without `--user-dir`, the patched build creates `%APPDATA%\TestDrive2\KylofonAdmission`. The unpatched upstream build writes `SELECT.DAT` and `*HISC.DAT` into the game folder.

**Licence.** MIT (Krzysztof Kania). Keep `LICENSE` and note the fork. SDL3 is zlib-licensed.

## 7. Recommended plan

The order still follows the user's sequence (EGA → CGA → resources → native → Amiga → switching). EGA phases 1–3 collapse into "adopt and verify" because a working EGA C core already exists.

| Milestone | Content | Done when |
|---|---|---|
| **M0 Adopt** | Import the Kylofon source into `port/` (or `src/td2/`) with its LICENSE and provenance note. Apply the useful parts of `candidate-fixes-v2.patch`. One CMake build with MSVC and SDL3 3.4.18. A `run.ps1` that copies the data to a scratch folder | The user plays a full race from a clean checkout |
| **M1 Verify EGA** | One generic Unicorn differential harness (original function vs Kylofon C on the same `mem[]` image), run in bulk with ranked results. Fix clutch, billboard, traffic and cockpit. Better speaker synthesis. Headless snapshot tests via `TD2_SNAPSHOT_DIR` | Harness runs over N functions in one command; fixed deviations have regression tests |
| **M2 Backend split** | Introduce `gfx_backend` and `audio_backend` interfaces at `platform/gfx.h` and `sound.h`. The EGA backend must stay pixel-identical | EGA snapshots unchanged |
| **M3 CGA** | Unpack TD2CGA, build the EGA→CGA crosswalk from the function indexes, implement the CGA backend (PCS loader, 2 bpp interleaved, CGA palette and tables read from TD2CGA.EXE). Hotkey switch between EGA and CGA | CGA is playable and switchable live |
| **M4 Resource closure** | `tools/` corpus scan: every one of the 249 DOS files gets a parser or a written disposition | Table generated by script |
| **M5 Amiga RE** | Extract the LHA to `analysis/amiga/`. Write a hunk parser and Rpck/PowerPacker unpackers. Ghidra 68k on `duel`. Decode ILBM, shapes, samples and `sfx/song` replay. Establish what `scen3` really is | Amiga assets decode to inspectable PNG/WAV files privately |
| **M6 Amiga providers and switching** | Amiga gfx and audio backends; atomic switch at a frame boundary; independent music and SFX switching | Switch mid-race with no state change |
| **M7 Northern Germany Challenge** | Route, sign and object converter from `scen3` into the DOS stage model | Full drive through all sections |

## 8. Decisions made in this handover and decisions open

**Made (recommended, user may veto).**
- Build on Kylofon.
- Abandon whole-RAM/flag-exact per-function proofs and the P-gate bureaucracy.
- Keep `reference/` read-only.
- Verify by playing plus targeted differential tests.

**Open for the user.**
1. *Resolved 24 October 2026:* the versioned maps were archived and everything else was committed.
2. Kylofon fork layout: vendor it as a subtree in this repo (recommended) or keep a separate fork repo?
3. Should the strict "no game text compiled into C" policy remain? It matters only for public distribution.
