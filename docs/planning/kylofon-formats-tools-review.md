# Kylofon formats, tooling and index review

Review date: 22 October 2026. Reference: `reference/repos/kylofon-test-drive-2-sdl3`, upstream commit `352b56824d8c91e938b8f0794a71afca9a276193`. All upstream locators below are relative to that checkout. This review read source and documentation and parsed the complete published index/symbol datasets; it did not execute an unpacker, decode supplied media, generate pictures/audio, build the port or play the game. Upstream descriptions of verification remain attributed claims until reproduced against our admitted inputs.

## Assessment

The upstream tools and format specifications can remove substantial *discovery and implementation* work. They provide concrete candidates for the common resource wrapper, two codecs, archive directory, sprite planes/storage modes, car records, showroom lists, stage/traffic/sign/font data, selection/high scores and speaker event formats. These are much more useful than generic documentation. Our current resource plan still describes many of those meanings as unknown, so the immediate improvement is to replace open-ended rediscovery with explicit candidate-admission and comparison tasks.

They do not supply a replacement for our evidence chain. The published function indexes identify paths such as `work/TD2EGA_unp.exe`, entry points and DGROUP, without original/unpacked SHA-256 values, tool dependency locks or retained differential/corpus receipts. The tools assume cooperative inputs and several documented meanings differ from our exact-byte findings. Preserve our validated unpack image, conditional DS/SS models and function contracts as the comparison oracle; admit upstream names and schemas one claim at a time.

## Complete assigned-file coverage

The following assigned files were read in full as source/text:

- `FORMATS.md`, `port/RE_GUIDE.md`, `.gitignore`, `.github/workflows/mirror.yml`.
- `tools/unexepack.py`, `tools/x86dis.py`, `tools/td2index.py`, `tools/td1match.py`, `tools/td2res.py`, `tools/td2car.py`, `tools/td2road.py`, `tools/td2snd.py`, `tools/sheet.py`, `tools/gen_symbols.py`, `tools/merge_symbols.py`.
- `tools/ghidra/SetDS.java`, `ApplySymbols.java`, `DecompileAll.java`, `postprocess.py`.
- `port/symbol_conflicts.txt` and `port/td2ega_td1_matches.csv`.

Every row of these generated datasets was parsed for structural checks: `port/symbols.csv`, `port/symbols_ghidra.txt`, and the `td2ega`, `td2cga`, `td2tdy` `_functions.json`, `_functions.csv`, `_starts.txt` files. The four `port/spec/*_symbols.csv` datasets were also parsed. No hand inspection of each generated JSON line is implied; full source review of their generator plus complete row-level checks is the inspection method. The subsystem prose specs and game/platform C implementation are covered by the companion reviews.

| Dataset | Verified static result |
| --- | --- |
| EGA index | 444 unique starts, 22 segment labels, 81 jump-table records; 36,256 declared instruction entries; 66 functions flagged as changing DS |
| CGA index | 440 unique starts, 22 segment labels, 51 jump-table records; 31,899 declared instruction entries; 79 DS-changing functions |
| Tandy index | 442 unique starts, 23 segment labels, 51 jump-table records; 32,436 declared instruction entries; 79 DS-changing functions |
| Three CSV/index pairs | All rows agree on start/image/end, size, instruction count, far-return flag and caller/callee counts |
| Three start lists | Each exactly equals its JSON's ordered image-offset list |
| Merged symbols | 1,091 unique kind/address rows: 460 functions and 631 globals; 76 rows retain alternative names |
| Ghidra symbol list | All 1,091 rows agree with merged symbols, including the `+0x1000` segment presentation transform |
| Per-spec symbols | game_flow 173; platform 466; scene_render 299; simulation 274; duplicate cross-spec names are merged, not extra functions |
| TD1 candidates | 53 rows; heuristic matches, explicitly not equivalent-function proof |

The instruction/segment/table counts are published-index properties, not independently validated executable coverage. `td2index.py:281-286` includes discovered jump-table bytes in its coverage numerator and labels the entire pre-DGROUP region "code bytes"; that percentage cannot close our classified code/data or reachable-code gate.

## Identity and address cross-check

Upstream EGA entry `13A8:03F8`, DGROUP `178F` and expanded image size 130,240 agree with our admitted image metadata (`docs/recovery/td2ega-unpacking.md`). That is useful alignment evidence but does not prove full byte equality. `FORMATS.md:37` gives 110,272 as the input side of its EGA expansion arrow: our documented `[0x200,0x1B0C0)` packed-data range has exactly that size, whereas the complete supplied EXE is 114,421 bytes. This is a payload-versus-file distinction, not evidence of an edition mismatch. Upstream unpacker output at `tools/unexepack.py:65` prints `len(packed)`.

Our admitted packed EGA SHA-256 is `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182`; admitted expanded image SHA-256 is `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4`. Those facts are recorded in our existing unpacking document; this subreview did not rerun the transform. Before adoption, prove the upstream loader produces the same image and ordered relocations from this exact EXE, with separate synthesized-envelope and trailing-byte policies. CGA's 11 internal trailing bytes remain our explicit obligation.

Comparing every upstream EGA function start with the `segment`/`segment_offset` values in all 440 current local function records gives 417 exact pairs, 27 upstream-only starts and 23 local-only starts. This is a boundary/index crosswalk, not proof that either side lacks the corresponding code. A port may implement several original entries in one C function; index heuristics may split shared tails differently.

Upstream-only starts:

`06C9:1A37, 5D9E, 607A, 69F2, 6F93, 74D4, 7501, 75D9, 799C, 79D2, 7A93, 7D9C, A547, AC1C, AC64, AF54, BAE8, C030, C65C, C6F0, C760; 13A8:03EC, 2CB4, 2DA7; 16EB:008E, 00D0; 1748:016A`.

Local-only starts and stable IDs:

| Starts | Local IDs |
| --- | --- |
| `06C9:4929,4947,494D,495D,499A,49C9,49CF,49D5,49DB,49E1,49E7,4A18,4A19` | `FN-EGA-000426` through `FN-EGA-000438`, respectively |
| `06C9:61BF,6230,6269` | `FN-EGA-000360,000361,000403` |
| `06C9:69B7,8336,839C,AD8B,ADF4` | `FN-EGA-000160,000213,000214,000239,000240` |
| `13A8:049B,0644` | `FN-EGA-000439,000359` |

Retain every stable local ID. Start-count alignment is not an acceptance criterion. In particular, absence of `61BF`/`6269` as upstream *index starts* does not mean their timer/effect behavior is absent from the port.

## Concrete conflicts and limits to carry into admission

1. **Wrong timer-reader annotation.** `port/symbols.csv:239-240` describes `5D83/5D8D` as reading `0040:006C`. Our instruction evidence in `docs/recovery/td2ega-startup.md:100` identifies literal `0040:046C`, physical `086C`. Preserve our literal read and unresolved historical meaning. Names such as `bios_ticks` cannot rewrite the operand or assign a timebase. Resolve the port's actual replacement separately.
2. **Global DS context is too strong.** `SetDS.java:18` and `DecompileAll.java:39-42` impose DS=DGROUP over all pre-DGROUP code. `RE_GUIDE.md:36-37` generalizes DS for C code. Our range-specific startup, runtime, allocator and live caller DS/SS qualification cannot be replaced by that setting. Use an isolated upstream analysis project if these helpers are useful; do not apply them to our accepted project or import their inferred types as contracts.
3. **Masked TD1 matches can be false.** `td1match.py:16-21,30,67` uses six-instruction windows, masks numbers and accepts score 0.5. Its published table calls `06C9:75C8` `gfx_set_text_colours`, whereas upstream's own merged symbols (`symbols.csv:317`) correctly call it `music_set_voices`; our accepted audio-metadata contract also identifies the source pointer stores. Candidate tables are a search aid only.
4. **Names resolve by policy, not proof.** `merge_symbols.py:53-59` prefers a range owner for functions and otherwise common names/longer notes. All 76 alternate-name rows remain naming disagreements; automatic resolution does not establish semantics. Preserve original address, chosen name, alternatives and local confidence separately.
5. **Index discovery is heuristic.** `td2index.py:75-97` seeds prologue patterns and selected loads, `109-135` guesses jump tables, `146` caps each linear walk at 0x1000 bytes, and `201` bounds functions at the next discovered start/segment boundary. `133` checks a Capstone iterator against `None`, which does not establish that the target yielded an instruction. Dynamic mutation, far aliases, shared entries and saved-return mechanisms still need our control ledgers.
6. **Upstream verification is not retained evidence.** `FORMATS.md:3-4,84-85` reports exact corpus/unpacker checks, but the checkout has no shipped fixtures, image hashes, comparison logs or runnable test suite establishing those claims for our corpus. Its sprite counts also differ within the document: 5,311 at `99`, 5,310 at `121`. Reconcile actual directory/resource counts during corpus admission; do not copy either total into our progress.
7. **Short-stage policy changes state.** `FORMATS.md:156-158` explicitly says the original fixed copy can leave old bytes while the port zero-fills. This can affect repeated stage loads. Require actual original copy/lifetime evidence and order-sensitive fixtures; do not silently adopt zero-fill as faithful.
8. **CAMA tail claim is narrower than its wording.** `td2car.py:3-4` calls the extra 49 bytes "disk junk" because the stage copy consumes 0x34F bytes. A proven excluded copy range would establish non-consumption by that path, not historical origin of the tail or universal non-use. Keep all 896 bytes immutable and retain a per-consumer disposition.
9. **VOICES heap adjacency is an explicit hypothesis to test.** `td2snd.py:28-30,347-350` pads VOICES to a paragraph and concatenates SONGS, making voice 1 read SONGS bytes 16-43. Our accepted `75C8` contract only publishes the supplied pointer; it does not yet prove historical allocation adjacency, all writers or later bounds. Admit the lifetime/allocation chain before labeling that sound faithful.
10. **Exploration parsers are not release readers.** `td2res.py:58-85,87-123,126-137` lacks project-wide input/output/recursion/work bounds; the RLE packed-length field is skipped at `88`. `load_archive:142-154` reads but does not validate total-size agreement and slices entries without explicit offset-range/duplicate policy. `sprite_info:172` accepts 1-3 trailing bytes for any PCS sprite, although the comment names one two-byte exception. `243-244` sanitizes only NUL/`!` in export names. Before reuse, add file/entry bounds, output caps, exact admitted exception records, controlled output paths and malformed-input evidence. Do this in an implementation copy, never the reference clone.
11. **Data dumpers mix known and unknown fields.** `td2car.py:49,53` retains two unknown words, and `75-78` exports a large geometry area raw. This is honest partial interpretation but not every-byte semantic closure. `td2road.py:123` takes a potentially short stream slice, and traffic/sign decoders assume valid headers and offsets. Retain parse completeness and unknown-field statuses.
12. **Schematic and PCM are inspection outputs.** Road walking uses floating point trigonometry (`td2road.py:142-158`), and labels its picture schematic (`225-226`); it is not original geometry/collision proof. `td2snd.py:298-317` restarts waveform phase when the gate comes on, caps interpretation loops (`130,216`) and models one memory layout. Its "tick-exact" description at `73` is an implementation claim, not original event/PCM acceptance. Keep event comparison, device behavior and human listening distinct.

## Candidate format admission queue

| Priority | Candidate evidence | Local obligation tightened |
| --- | --- | --- |
| First | `FORMATS.md:62-85`, `td2res.py` | Compare wrapper/type/length, Huffman bit order and RLE sequence/run passes against our accepted original codec primitives; preserve command order, wrap/zero-count behavior and failure prefixes |
| First | `FORMATS.md:87-123`, `td2res.py:142-217` | Validate every archive directory, offset base, plane count/map, padding and EGA unflip using original consumers; enumerate all 82 PES +82 PCS files without promoting CGA port status |
| First | `td2car.py`, `FORMATS.md:143-150` | Map exact 0x34F car and 0x20 opponent views plus overlapping torque/gauge byte; retain CAMA tail; compare all 12 records and animation label order |
| First | `td2road.py:9-28,92-140` | Attach stage record/ring/traffic/zone/stream candidates to local raw views; compare fixed copy, lookahead, bounds and repeat-load behavior for all 19 DAT files and 14 SGNs |
| Next | `FORMATS.md:166-167`, platform spec | Confirm vector-font offset/glyph terminators and full glyph/corpus disposition; no modern-font replacement |
| Next | `FORMATS.md:172-176`, game-flow spec | Confirm selection fields, six-row score table, checksum and original write behavior; redirect writes to our separate user-data directory |
| Next | `FORMATS.md:180-185`, `td2snd.py` | Compare sequencer instructions and event order before synthesizing PCM; explicitly qualify two-byte VOICES adjacency, PIT cadence, effect priority and raw command envelope |
| Later | CGA/TDY indexes and PCS storage candidates | Use only after EGA portable closure, retaining the user's required phase order; indexes do not constitute a CGA renderer or common-state comparison |

A candidate becomes admitted only after recording our exact input hash, original consumer IDs/ranges, upstream pinned source locator, byte schema, transformation policy, valid/malformed cases, corpus coverage and known differences. Until then the 249-file resource registry remains at its existing gate status. Add upstream candidate links alongside its records rather than bulk changing `code_contract`/format gates.

## Tool-by-tool reuse decision

| Files | Useful reuse | Conditions |
| --- | --- | --- |
| `unexepack.py` | Independent algorithm comparison and future variant experimentation | Keep our admitted hash/bounds/relocation validation. Upstream uses `assert` for MZ/signature (`8,15`), accepts generic inputs and synthesizes different header policy (`57-60`); never replace our primary custody tool wholesale |
| `x86dis.py` | Small read-only disassembly lookup | Add input identity and bounded MZ handling in a working copy; respect distinction between module-relative and relocated addresses |
| `td2index.py` and all index datasets | Candidate entry, call/string/port search | Preserve local IDs, context and dynamic-control ledgers; no coverage/count-based closure |
| `td1match.py`, match CSV | Search hints for common DSI/CRT patterns | Revalidate operands/ABI/side effects; retain false-positive example |
| `td2res.py` | Strong decoder/archive/sprite implementation starting point | Bounded readers, exact exceptions, original differential tests, full-corpus disposition; private outputs only |
| `td2car.py`, `td2road.py` | Useful field candidates and inspection exports | Verify consumer use/units/lifetimes; cap and validate input; raw unknowns stay explicit |
| `td2snd.py` | Sequencer candidate model and later private audio inspection | Compare event-level behavior first; keep heap assumptions and waveform policy separate |
| `sheet.py` | Private review sheets from already admitted decoders | It skips unrecognized sprites (`17-18`), so sheet completeness cannot prove archive completeness; no original art in publication |
| `gen_symbols.py`, `merge_symbols.py` | Alias/name navigation | Keep original address IDs and confidence; generate only in an implementation/analysis copy |
| Four Ghidra helpers | Isolated upstream-named exploratory project and text/xref convenience | Replace blanket DS assumptions for accepted analysis; retain loader, relocation and symbolic segment verification |
| `.gitignore` | Correctly excludes Game/work/decomp/tables and tool downloads | Our broader reference/analysis exclusions remain authoritative; inspect any imported source for original-derived media separately |
| `mirror.yml` | No current recovery benefit | Calls a reusable external workflow at mutable `@master`; it is publishing/mirroring, not build/test CI. Do not activate/copy it as part of reference analysis |

## Impact on feasibility and schedule

The concrete format models and named consumer map strongly support an upstream-based implementation trial, and could save much of repeated DOS decoder/field discovery. They do not justify an unconditional jump past reverse engineering: the exact-byte crosswalk, timing annotation conflict, short-copy behavior, voice allocation and malformed-input work are bounded admission tasks still required. No Amiga decoder, Northern Germany Challenge mapping or live provider switching is supplied by these assigned tools. Those later work packages retain their existing scope.

The best combination is to use the upstream C/data layout as a candidate implementation and our accepted original-instruction contracts as the verification oracle. Do not merge two incompatible memory models function by function without an explicit adapter and comparison frontier. The parent assessment should distinguish time saved in implementation from remaining CGA, resources, integration, runtime, visual/audio, portability and fidelity gates. This static review supplies no measured engineer-week reduction.
