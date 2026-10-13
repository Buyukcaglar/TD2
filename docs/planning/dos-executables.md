# DOS executable evidence and reverse-engineering plan

This is the earlier static planning snapshot. New Phase 1 results, including validated unpacking and startup/C recovery, are tracked in the [current recovery checkpoint](../recovery/README.md); the historical observations and limits below remain scoped to the planning inspection.

Snapshot date: 2026-10-13. Scope: read-only, static inspection of the supplied DOS executable bytes. No game, installer, loader, emulator, unpacker, disassembler, decompiler, or compatibility test was executed. No original file was modified. This document is a planning artifact, not recovered source or a claim of behavioral fidelity.

All offsets in this document are hexadecimal **file offsets in the supplied, still-packed executable**, unless explicitly labelled segment-relative. They must not be reused as unpacked-image or runtime addresses. SHA-256 values pin the evidence to these exact supplied files.

## 1. Executable identity

| File under `reference/dos` | Bytes | SHA-256 |
|---|---:|---|
| `TD2EGA.EXE` | 114,421 | `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182` |
| `TD2CGA.EXE` | 104,160 | `3e254f317b8d91c6b6d1e1b3d873f80f71c630e30f77a7cf7243cbe7eec979ba` |
| `TD2TDY.EXE` | 103,905 | `6a22aeeb809b483f6c19bc201eb9e267fd6800ca1dfd1af427a05622ce2293fa` |
| `DUEL.EXE` | 960 | `76d5ba36c4c755a86a3a15f61e32b4a5d2fab0efcb2182bb8cc474a48e2ef25f` |

`TD2EGA.EXE` is the primary reconstruction target. `TD2CGA.EXE` is the second graphics implementation to analyze after the EGA program is understood. `TD2TDY.EXE` is useful comparison evidence; a complete Tandy port is not one of the requested delivery milestones. `DUEL.EXE` is a small DOS launcher, not the main game.

## 2. Verified MZ header facts

The standard MZ fields occupy the first 28 bytes. In all four files the signature at `0x00` is `4D 5A`, the header paragraph count at `0x08` is `0x0020`, and the load image therefore begins at file offset `0x0200`.

| Header field (file offset) | EGA | CGA | TDY | DUEL |
|---|---:|---:|---:|---:|
| Last-page bytes (`0x02`) | `00F5` | `00E0` | `01E1` | `01C0` |
| 512-byte page count (`0x04`) | `00E0` | `00CC` | `00CB` | `0002` |
| Outer relocation count (`0x06`) | `0000` | `0000` | `0000` | `0002` |
| Header paragraphs (`0x08`) | `0020` | `0020` | `0020` | `0020` |
| Minimum extra paragraphs (`0x0A`) | `05FD` | `05F7` | `05FE` | `0000` |
| Maximum extra paragraphs (`0x0C`) | `05FD` | `05F7` | `05FE` | `FFFF` |
| Initial SS (`0x0E`) | `20B0` | `1E28` | `1E23` | `001A` |
| Initial SP (`0x10`) | `0080` | `0080` | `0080` | `0020` |
| Stored checksum (`0x12`) | `0000` | `F8A4` | `0000` | `5BF0` |
| Initial IP (`0x14`) | `0012` | `0012` | `0012` | `0000` |
| Initial CS (`0x16`) | `1AEC` | `186A` | `1858` | `0000` |
| Relocation-table offset (`0x18`) | `001E` | `001E` | `001E` | `001E` |
| Overlay number (`0x1A`) | `0000` | `0000` | `0000` | `0000` |
| Entry file offset, `0x200 + CS*16 + IP` | `1B0D2` | `188B2` | `18792` | `00200` |

For each file, `(pages - 1) * 512 + last_page_bytes` equals its exact file size. There are no bytes beyond the MZ-declared file image. This does **not** prove the program never loads overlays or other files at runtime; it only rules out appended data beyond this particular declared image.

The two DUEL outer relocation records at `0x1E` and `0x22` are `(offset=0x0167, segment=0)` and `(offset=0x018F, segment=0)`. The three game variants have zero **outer** relocations, but retain substantial candidate relocation data inside their packing tails. Do not treat them as relocation-free, flat binaries.

## 3. Packing evidence and first blocker

The entry addresses of the three game variants point near the end of each load image, into the same byte sequence. The first 32 entry bytes are:

```text
8C C0 05 10 00 0E 1F A3 04 00 03 06 0C 00 8E C0
8B 0E 06 00 8B F9 4F 8B F7 FD F3 A4 8B 16 0E 00
```

Static reading of the short stub shows segment setup, a backward byte copy (`STD; REP MOVSB`), byte-run and literal-copy branches using `B0` and `B2`, relocation-word processing, stack replacement, and an indirect far transfer. Those are loader/unpacking operations. They are not the game main loop.

Let `P = 0x200 + outer_CS * 16`. The following observations are verified without unpacking:

| Observation | EGA | CGA | TDY |
|---|---:|---:|---:|
| Stub-segment file base `P` | `1B0C0` | `188A0` | `18780` |
| Bytes before stub after MZ header | 110,272 | 100,000 | 99,712 |
| Word at `P+0x10` | `4252` | `4252` | `4252` |
| Packed-tail size word at `P+0x06` | `0E35` | `0E35` | `0E61` |
| Literal `Packed file is corrupt` | `1B1D7` | `189B7` | `18897` |
| Candidate packed relocation start `P+0x12D` | `1B1ED` | `189CD` | `188AD` |
| Candidate packed relocation end | `1BEF5` | `196D5` | `195E1` |
| Actual EOF | `1BEF5` | `196E0` | `195E1` |

The exact 283-byte range `[P+0x12, P+0x12D)` has the same SHA-256 in all three variants:

`3c2ecf0c7854abfe0390cfa2482fc3941cf255546ce1629132eb62bb08f3d435`

This range includes the common entry/unpacking code and corruption message, and excludes variant metadata and relocation words. The combined signature, metadata layout, and backward run decoder strongly identify a **Microsoft EXEPACK-family layout**. Exact historical packer version, tool invocation, and any later patching history remain unestablished. The project must verify its selected unpacker against the observed bytes, not rely only on a filename/signature detector.

### Candidate packed metadata

The nine little-endian words at `P+0x00` through `P+0x10` are:

| Segment-relative location | EGA | CGA | TDY | Provisional interpretation to verify during unpacking |
|---|---:|---:|---:|---|
| `+00` | `03F8` | `03F8` | `03F6` | Original IP |
| `+02` | `13A8` | `1136` | `1104` | Original CS relative to program load segment |
| `+04` | `0000` | `0000` | `0000` | Runtime load-segment scratch word |
| `+06` | `0E35` | `0E35` | `0E61` | Packed-tail byte size |
| `+08` | `0FA0` | `0FA0` | `0FA0` | Original SP |
| `+0A` | `20D2` | `1E4A` | `1E42` | Original SS |
| `+0C` | `1FCC` | `1D44` | `1D3C` | Destination image paragraphs |
| `+0E` | `0001` | `0001` | `0001` | Skip/segment adjustment field |
| `+10` | `4252` | `4252` | `4252` | Packing signature |

The numeric words are facts. Their semantic names are provisional until checked against a verified packer specification and actual reconstruction of the loader result. In particular, do not import the candidate original CS:IP as if the packed file already had that address layout.

### Candidate relocation consistency check

Following the table structure suggested by the stub, a static pass over 16 groups, each consisting of a little-endian count and that many little-endian offsets, consumes:

| Variant | Counts for first two groups | Other 14 groups | Total words representing relocation offsets |
|---|---:|---:|---:|
| EGA | 1,361 + 291 | all zero | 1,652 |
| CGA | 1,362 + 290 | all zero | 1,652 |
| TDY | 1,369 + 305 | all zero | 1,674 |

For EGA and TDY, this pass ends exactly at EOF and at `P + word(P+6)`. For CGA, it ends at `0x196D5 = P + 0x0E35`, followed by these 11 bytes still inside the MZ-declared image:

```text
FF 40 00 FF FF 00 00 FF FF 00 00
```

Their role is unknown. They might be padding, residue, or a meaningful alteration. Preserve the bytes in custody and classify them explicitly during the unpacking task; do not silently discard them or infer that CGA is damaged.

## 4. Compiler, resource, and subsystem anchors

All three executables contain this literal ASCII string:

`MS Run-Time Library - Copyright (c) 1987, Microsoft Corp`

It begins at EGA `0x16FB8`, CGA `0x1486D`, and TDY `0x146C4`. This establishes a Microsoft runtime attribution in the supplied bytes. It does not establish an exact compiler version, a particular C standard, the memory model, that every function was compiled from C, or the original source code. Library-signature matching should be corroborated by startup/calling-convention analysis after unpacking. Handwritten assembly and third-party routines are possible.

Selected useful raw string anchors follow. Strings prove that the bytes exist; their code cross-references and reachable behavior are future work.

| Literal or prefix | EGA | CGA | TDY | Planning implication |
|---|---:|---:|---:|---|
| `accolade.pcs` | `17381` | `14C36` | `14A8D` | Both PCS and PES name tables occur in all variants. |
| `accolade.pes` | `173F6` | `14CAB` | `14B02` | Presence alone does not identify the selected graphics decoder. |
| `select.dat` (first occurrence) | `1746B` | `14D20` | `14B77` | Configuration/persistence discovery anchor. |
| `NO ROOM LEFT ON TIMER INTERRUPT ROUTINE LIST` | `192DE` | `16ABE` | `16983` | Scheduler/interrupt callback-list investigation anchor. |
| `MUSIC ON` | `1930C` | `16AEC` | `169B1` | Music and effects controls should be mapped independently. |
| `SOUND ON` | `1931F` | `16AFF` | `169C4` | Does not identify the sound device. |
| `%s NOT PACKED FILE` | `19558` | `16D38` | `16BFD` | Resource packing reader anchor, separate from EXE packing. |
| `%s INVALID PACK TYPE` | `1956C` | `16D4C` | `16C11` | Multiple resource pack types are plausible, not yet decoded. |
| `locateshape - %-4.4s SHAPE OR SOUND NOT FOUND` | `19583` | `16D63` | `16C28` | Four-character lookup keys may serve graphics and sound; trace reader. |
| `reservememory - OUT OF MEMORY LOADING %s` | `195B3` | `16D93` | `16C58` | Memory/resource ownership boundary anchor. |
| `memory manager - BLOCK NOT FOUND at SEG= %x` | `1960E` | `16DEE` | `16CB3` | Segment-oriented allocation manager; a flat C pointer substitution is premature. |
| `diskid.dat` (near loader options) | `19E68` | `17647` | `17534` | Original media identity behavior and installation assumptions. |
| `herc` | `19E78` | `17657` | `17544` | Launcher command-line option also appears in all variants. |
| `voices.bin` | `19E7D` | `1765C` | `17549` | Audio-resource discovery anchor; name is not proof of sampled speech content. |
| `songs.bin` | `19E88` | `17667` | `17554` | Music-resource discovery anchor. |
| Selected title resource literal | `19E94`: `testdrv2.pes` | `17673`: `testdrv2.pcs` | `17560`: `testdrv2.pes` | Variant-specific literal differences guide the graphics comparison. |
| `Cannot open cars.dat for read.` | `1AAE8` | `182C7` | `181B4` | Car catalog reader anchor. |
| `Cannot open scenes.dat for read.` | `1AB1A` | `182F9` | `181E6` | Scenery catalog reader anchor. |
| `Cannot open select.dat for write` | `1AB89` | `18368` | `18255` | The original program has a write-capable persistence path. |
| `Please remove write protect tab` | `19E42` | `17621` | `1750E` | Never run the original in the immutable reference tree. |

The EGA string region has `.PES` at `0x198B0`, `.ESH` at `0x198B5`, `UNFLIP` at `0x198C0`, and `WINDOW` at `0x198D4`. CGA has `.PCS` at `0x17076`, `.CSH` at `0x1707B`, and `FLIPBUF` at `0x17086`. TDY has `.PES` at `0x16F37`, `.ESH` at `0x16F3C`, `PTS` at `0x16F41`, `TSH` at `0x16F45`, `.TSH` at `0x16F56`, `.PTS` at `0x16F5B`, and `UNFLIP` at `0x16F4F` and `0x16F60`. These are valuable decoder/cache/graphics comparison anchors. `.ESH`, `.CSH`, `.PTS`, and `.TSH` should be searched in loader paths and container entries before they are declared missing media; they may be internal or generated names.

Long contiguous four-character names include dashboard-related identifiers (`dash`, `gbox`, `mirr`, `rad0`), collision/road/traffic names, and cop/driver animation identifiers. Such strings suggest rich executable-resident metadata, but this pass has not assigned a schema or decoded any shape.

The user-confirmed DOS audio scope is **PC Speaker music and sound effects**. This static pass has not recovered or exercised their implementation. Trace the original sequencing, timer callbacks, effect priorities and hardware accesses before translating the audio behavior into portable C.

## 5. DUEL launcher: bounded static decoding

The executable load image is only 448 bytes. The menu text begins at `0x27E` and offers:

1. CGA or Tandy, four colors.
2. Tandy, sixteen colors.
3. EGA, sixteen colors.
4. Hercules Graphic Adaptor.

The key comparisons and branches are visible at `0x22E` through `0x241`. The selected path sets `AL=0` at `0x258`, sets `AH=4Bh` at `0x25A`, and reaches DOS `INT 21h` at `0x25C`, with these paths and execution blocks:

| Key | Branch code | Filename at file offset | Execution block | Command tail |
|---|---:|---|---:|---|
| `1` | `252` | `358`: `td2cga.exe` | file `363` | length 1, one space; tail begins at `371` |
| `2` | `268` | `380`: `td2tdy.exe` | file `363` | same one-space tail |
| `3` | `260` | `375`: `td2ega.exe` | file `363` | same one-space tail |
| `4` | `270` | `358`: `td2cga.exe` | file `38B` | length 4, `herc`; tail begins at `399` |

Hercules is therefore routed to `TD2CGA.EXE` with the `herc` option; the launcher does not imply a missing separate Hercules executable. This is a static branch/parameter trace, not a tested launch. Menu/device claims still need original runtime observation during the later authorized implementation phase.

## 6. Ordered executable reconstruction work packages

These are future tasks. They were not performed in this planning phase.

### DOS-EXE-01: pin working inputs and toolchain

1. Verify the four hashes above against the immutable input manifest.
2. Create a separate derived-analysis tree and writable disposable runtime fixtures. Reference files remain read-only.
3. Pin tool versions, command lines, CPU/language profile, and intended load addresses. Choose an x86 16-bit capable disassembler and a decompiler with explicit segmented-address handling; validate capabilities on these inputs before committing the whole workflow.
4. Record every input/output hash and keep packed original, normalized unpacked image, relocated runtime image, and analysis database as distinct artifacts.

Gate: reproducible evidence custody and no dependency on executing files in `reference`.

### DOS-EXE-02: recover and prove the EGA load image

1. Confirm the EXEPACK layout against the common stub, metadata, and relocation table. Obtain a pinned independent unpacker or documented algorithm.
2. Unpack a copy, retaining both the raw reconstructed image and any rebuilt MZ envelope. Record exactly which bytes were synthesized, removed, or normalized.
3. Check destination bounds, block termination, candidate original CS:IP/SS:SP, relocation counts/locations, and the full segment map. Relocations must point to appropriate words within the reconstructed address space.
4. Produce a map from original packed input regions to reconstructed output regions where the packer permits it. Once decompressed, every later source claim should identify the original input hash and unpacked address; do not pretend packed file offsets map linearly to the output.
5. Cross-check with a second independently implemented unpacking path or a controlled loader-memory snapshot. A runtime snapshot is later testing, requiring a writable fixture and explicit test authority; it is not part of this planning phase.
6. Repeat for CGA and TDY only after EGA methodology is reproducible. Preserve and classify CGA's 11 internal trailing bytes.

Gate: a repeatable unpacked load image and proven relocation treatment. A tool's successful exit code or plausible disassembly alone is insufficient.

### DOS-EXE-03: establish address and ABI conventions

1. Start from the verified original entry, map runtime startup and termination, and identify PSP/environment/command-tail reads, DOS calls, heap initialization, stack guards, and compiler helper functions.
2. Recover DS setup, data groups, near/far call boundaries, pointer widths, function return conventions, argument cleanup, and any segment:offset aliasing. Determine the actual memory model from evidence.
3. Mark interrupt entry points, vector installation/restoration, BIOS/DOS boundaries, and any self-modifying code or generated code. Distinguish loader artifacts from game code.
4. Separate validated runtime/library matches from application functions. Do not rename a routine solely because a library detector labels it.
5. Create an address/type/function registry with confidence, caller/callee sets, side effects, global reads/writes, unresolved indirect edges, and evidence links.

Gate: startup-to-game transfer and the principal address/ABI conventions are documented. Unresolved far pointers and indirect control flow are tracked, never hidden by aggressive type inference.

### DOS-EXE-04: recover subsystem boundaries without prematurely porting them

1. Follow the resource error strings to the file-open, read, seek, pack-type dispatch, shape/sound lookup, and memory manager routines.
2. Follow timer-list and music/sound labels to scheduler callbacks, tick rates, IRQ installation, and update cadence.
3. Map keyboard, joystick, pause, options, game-state transitions, catalogs, selection persistence, high scores, and install/delete paths.
4. Map car setup, road/scenery loading, progression, physics, gearbox/engine/fuel/damage, collision, opponent and traffic behavior, police interaction, scoring, and finish/game-over transitions.
5. Document original arithmetic widths, signedness, overflow behavior, fixed-point formats, RNG state, lookup tables, and call order before translating algorithms.
6. Map display/sound hardware access separately from semantic game state. Search candidates include BIOS video calls, EGA/CGA register writes and memory windows, and PIT/PC Speaker port accesses. These are investigation targets, not claims that the supplied code uses particular operations.

Gate: a dependency-aware routine map with explicit unclassified regions and state ownership. Completing menus does not complete driving/gameplay reconstruction.

### DOS-EXE-05: convert EGA game behavior to portable C in bounded slices

1. Define a C17-compatible core with fixed-width integers, explicit endian reads, deterministic state, and injected file/input/timing/audio/video services. Choose C17 as the new project baseline, not as a claim about the original compiler.
2. Translate a small leaf routine with strong evidence and controlled input/output, preserving arithmetic and state transitions. Avoid copying decompiler pseudocode wholesale.
3. Add a per-routine mapping record: original image/address ranges, calls, data dependencies, assumptions, unresolved behavior, and validation vectors.
4. Advance outward through the dependency graph: numeric helpers and data interpretation; car/road state; physics and collisions; traffic/opponents/police; race progression; full frontend and persistence.
5. Maintain a faithful reference behavior mode. Any optional bug fix or modern convenience is a separate behavior choice after the original quirk is established.
6. Keep semantic lookup constants distinguishable from original presentation assets. Do not embed original pictures, sound data, animation tables, or UI text in generated C arrays merely because they were found inside the executable.

Gate per slice: static mapping, compilation, and meaningful deterministic comparisons. Whole-core completion additionally requires later controlled original/native behavioral testing across the complete supported corpus.

### DOS-EXE-06: analyze CGA implementation after the EGA core

1. Unpack and map CGA with the same custody and address conventions.
2. Match shared routines using normalized control-flow, call neighborhoods, data references, and known relocations. A raw file byte diff confounds packing, layout, relocation, and logic changes.
3. Classify differences as graphics/device code, resource selection/layout, runtime/compiler/layout noise, or actual gameplay divergence. Do not assume all nonmatching functions are graphics.
4. Trace the CGA-selected `.PCS`/`.CSH` path, buffering/page layouts, row tables, clipping, transparency/masks, palette selection, drawing order, flipping, and timing-sensitive effects. Resolve the `herc` branch separately so it cannot contaminate normal CGA conclusions.
5. Compare native EGA and CGA rendering from the same semantic state. Keep art dimensions, anchor points, palette choices, and animation sequences in versioned presentation adapters.
6. Use TDY as supporting evidence where it clarifies a shared decoder or rendering operation. Do not infer Tandy timing/audio or promote its optional support without a scoped requirement.

Gate: both requested DOS graphics modes are independently decoded and explained, with a measured list of shared and variant behavior. A recolored EGA renderer is not a reconstructed CGA implementation.

## 7. Required executable evidence artifacts during implementation

The eventual reverse-engineering work should persist at least:

- A toolchain lock record and unpacking recipe with original/unpacked/derived hashes.
- MZ, packer, relocation, segment, and runtime load-address maps.
- Annotated disassembly and decompiler projects, with exported human-readable function/address indexes.
- A routine-to-portable-source map and a globals/type registry with confidence and unresolved items.
- A resource reader/writer call graph, field/schema notes, container entry indexes, and executable-resident resource inventory.
- A hardware-access ledger linking each port/BIOS/DOS/interrupt dependency to its native replacement.
- An EGA/CGA comparison ledger and a separate `herc` investigation note.
- A behavioral test-case registry, deterministic inputs, trace schemas, comparison results, and known mismatches.
- A coverage ledger that distinguishes code bytes, data bytes, loader/runtime bytes, proven unreachable bytes, and unclassified bytes.

An immutable hash alone is not sufficient provenance for reconstructed semantics: it must connect to addresses, data dependencies, translation decisions, and validation evidence.

## 8. Critical traps and decision gates

1. **Packed entry is not program entry.** An outer-MZ analysis can spend weeks documenting the packer instead of the game.
2. **No outer relocations is not a flat program.** The candidate internal tables contain over 1,600 relocation offsets.
3. **Readable strings do not mean the body is already unpacked.** This packer can leave long literal regions readable.
4. **Compiler attribution is bounded.** A Microsoft runtime notice is not proof of exact compiler/version or original C reconstruction.
5. **Resource compression and EXE compression are distinct.** The `%s NOT PACKED FILE` and `INVALID PACK TYPE` strings concern a game-reader path to be traced; they must not be confused with the executable wrapper.
6. **Original resources may live inside EXEs.** The requirement that the native executable contain no DOS resources needs an executable-resident asset audit. Load or derive necessary original presentation data from user-supplied external originals at runtime or in a private, provenance-tracked cache. Do not bundle such data in the native distribution.
7. **Audio reconstruction remains a gate.** The user-confirmed DOS target is PC Speaker music and sound effects. Their event formats, sequencing, pitch/divisor rules, priorities and timing still need recovery and later validation.
8. **The original has write paths.** Selection/high-score/install/delete behavior must be redirected to disposable fixtures for investigation and to user-data storage in the native application.
9. **Data widths matter.** Host `int`, pointer size, right-shift rules, overflow, segment aliases, and evaluation order can silently alter car behavior.
10. **Decompiler output is a hypothesis.** Function boundaries, signedness, structs, and jump tables require cross-references and tests.
11. **Modern host time is not original game time.** Preserve simulation cadence and event ordering while separating presentation refresh and sound synthesis.
12. **Similar outputs are not complete parity.** Compilation, successful loading, menu screenshots, one completed race, and full-corpus fidelity are different gates. Record each independently.

## 9. What remains unknown after this planning inspection

- Exact EXEPACK version, unpacked image contents, true application entry, and runtime memory model.
- Exact compiler version, source language coverage, source organization, and assembly contribution.
- Actual reachable code/function count, game-state layout, arithmetic/RNG rules, interrupt cadence, and hardware accesses.
- Resource pack schemas and executable-resident resource boundaries.
- PC Speaker music/effect event formats, sequencing, pitch/divisor rules, priorities and interrupt timing.
- Whether EGA and CGA differ in gameplay/timing as well as display handling.
- The role of CGA's 11 bytes after its internal packed tail.
- Runtime copy-protection/media checks and any build-specific patches or defects.

These unknowns are normal inputs to the development roadmap. They must become explicit investigation tasks with evidence and exit criteria, rather than assumptions hidden in an implementation estimate.
