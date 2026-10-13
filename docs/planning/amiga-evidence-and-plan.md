# Amiga evidence and implementation plan

Planning-only inspection dated 2026-10-13 (Europe/Istanbul).

## Inspection boundary and custody

This report supports the later Amiga phases of the overall roadmap. The required sequence remains DOS EGA core recovery, DOS CGA comparison, DOS resource closure, native Windows baseline, Amiga recovery, then switchable presentation and audio. This planning inspection did not run, emulate, disassemble, decompile, patch, render, or play the game. No game/resource decoder or portable game code was written. Existing installed 7-Zip decompressed archive members to process memory solely for hashes, bounded signatures, and two short documentation/launcher reads. No extracted payload files were retained.

Source archive: `C:\Projects\TestDrive2\reference\amiga\TestDrive2&DataDisks_v1.1_HD_JOTD.lha`.

| Observed fact | Value |
|---|---|
| Container size | 1,412,072 bytes |
| Container SHA-256 | `1a2fc1d197e96356aad46fd65b6661fc194aeb2caf764c5a4319d435112ee114` |
| Installed listing tool | `C:\Program Files\7-Zip\7z.exe`, version 25.01 |
| Listed archive type | Lzh |
| Members | 352 files; no explicit directory entries |
| Total uncompressed member bytes | 2,417,938 |
| Compression methods | 332 `-lh5-`, 20 `-lh0-` |
| Member examination | All 352 decompressed successfully through 7-Zip and matched listed uncompressed lengths |
| Payload persistence | None; metadata only in this report and the accompanying inventory JSON |

Successful archive reads and hashes establish the inspected bytes, not historical originality, gameplay completeness, resource validity, or visual/audio fidelity. Archive timestamps are metadata supplied by the packager; they are not release-date proof.

## What the supplied package actually contains

The archive contains an installed file tree, not original disk images. The archive filename is not sufficient evidence that this tree is a WHDLoad release. Its embedded `ReadMe` identifies a Jean-Francois Fabre HD installer/patch v1.1, says it requires original Test Drive II media, describes cache/68040/68060 and FastMem handling, and states that disk protection was removed by an anonymous contributor. Those are claims made by the supplied documentation, not an independently verified patch analysis.

The launcher `TestDrive2&DataDisksHD\TestDrive2&DataDisksHD` is a 513-byte AmigaDOS script. Static reading shows assigns for `tdboot:`, `sc1:` through `sc3:`, and `f0:`/`f1:`; it runs `nofastmem`, waits, calls `DuelHD`, then restores FastMem and dismounts assigns. `DuelHD` contains strings naming `dos.library`, `intuition.library`, `graphics.library`, and `tdboot:duel`. No member name ends in `.slave`, and the launcher does not invoke WHDLoad. Consequently, treat this as the supplied HD-patched Amiga profile until actual patch provenance proves a more specific identity.

| Location beneath `TestDrive2&DataDisksHD` | Member count | Observed role/name patterns |
|---|---:|---|
| Archive/tree root | 11 | Outer drawer icon; `duel`, `DuelHD`, `ReadMe`, icons, launcher, `cars.dat0`, `scen.dat0`, `select.dat0`, `disktype.dat` |
| `cars` | 32 | `f40` and `p959`, 16 files each |
| `cars1` | 82 | Index/type files plus `camo`, `dodge`, `gt500`, `gto`, `stingray`, 16 files each |
| `cars2` | 82 | Index/type files plus `coun`, `lotu`, `ross`, `ruf`, `vett`, 16 files each |
| `pics` | 14 | Titles, options, difficulty, road, palette, game-over/endgame naming |
| `scen` | 18 | `sc1_` base scenery and road/vector naming |
| `scen1` | 32 | `rock_` scenery and road/vector naming plus index/type files |
| `scen2` | 32 | `euro_` scenery and road/vector naming plus index/type files |
| `scen3` | 37 | Another `euro_` tree, different bytes and historical modifications; includes high-score files |
| `sfx` | 12 | Speech/effect-like names and `song`; actual playback roles still require call-site analysis |

The counts describe archive organization, not playable car/course coverage. Stems are preserved exactly rather than expanded into unverified vehicle/scenery identities. `scen2` and `scen3` must remain separate namespaces: similarly named `euro_` members differ, and `scen3` contains `euro_againstcomputer.best2` and `euro_HighScores2`. Preserve those supplied files as evidence; later runtime save writes belong in a separate user-data directory.

## Static format observations

The full member manifest below records per-member SHA-256, first 16 bytes, sizes, archive CRC, and compression method. Classifications in this section are signatures, not complete parse results.

| Observed signature/family | Count | Implication for later work |
|---|---:|---|
| Leading big-endian `000003f3` | 3 | `duel` (108,868 bytes), `DuelHD` (2,232 bytes), and `sfx\song` (26,852 bytes) are consistent with Amiga HUNK load files |
| `FORM` with type `ILBM` at offset 8 | 53 | Bitmap/palette containers; body/mask/compression/palette/display modes remain unparsed |
| `FORM` with type `8SVX` at offset 8 | 2 | `sfx\gameover` (12,916 bytes), `sfx\starter` (25,932 bytes); sample parameters/body not decoded or auditioned |
| Leading `Rpck` | 177 | Packed/wrapped payload family; framing, compressor, output lengths, and payload format remain unverified |
| Leading `CMAP` | 28 | Standalone palette-chunk-looking family; exact interpretation must be traced in loaders |
| Other/short signatures | 89 | Indices, car/road/vector data, icons, raw/custom audio, text, and other data need individual classification |

The three HUNK signatures agree with the documented executable magic in the original [AmigaDOS binary-file structure manual](https://www.pagetable.com/docs/amigados_tripos/amigados_manual.pdf). No relocation, section, symbol, overlay, compiler, or function map has yet been recovered.

`pics\testdrive.pal` is 238 bytes and begins `FORM ... ILBM BMHD`; a `.pal` extension therefore does not imply a bare palette. `pics\testdrive.shp` begins `Rpck` and contains `PPkc` at offset 10 in its first 32 bytes. Preserve these exact observations; do not select a decompressor solely from a filename or a partial magic match. The archive's LHA compression is a separate layer from these in-member wrappers.

IFF ILBM describes bitplanes and optional masks/palette/display metadata; it also permits a palette-only form. The future reader should follow the original specification for chunk lengths/padding, `BMHD`, `CMAP`, `BODY`, and relevant mode/cycling properties rather than assuming every ILBM is a self-contained image. [Original ILBM specification, reproduced by AmigaOS documentation](https://wiki.amigaos.net/wiki/ILBM_IFF_Interleaved_Bitmap).

`sfx\song` must enter the executable recovery queue as well as the audio queue: its HUNK signature prevents assuming it is a standard tracker module. Other names in `sfx` do not establish their encoding. Future 8SVX work must recover `VHDR`, body, one-shot/repeat regions, octave/rate/compression fields, and their actual use by the game. [Original 8SVX specification](https://amigadev.elowar.com/read/ADCD_2.1/Devices_Manual_guide/node02CD.html).

## Historical patch leads and provenance blockers

The patch author's [later WHDLoad Test Drive II release notes](https://www.whdload.de/games/TestDrive2) describe copperlist/blitter frame-timing changes, audio DMA-wait fixes, re-enabled FastMem, different executable versions, and Europe/Northern Germany installation-name collisions. These are valuable investigation leads. They do not prove that those patches, versions, or corrected behaviors exist in this supplied HD tree. The supplied launcher/readme differ from that later WHDLoad package.

| Open question/blocker | Required evidence | Effect on implementation |
|---|---|---|
| Which historical release is `duel`? | Original disk/file hashes, region/language/revision identification, patch-byte comparison | Supplied-profile recovery can proceed later; claims about an unpatched original remain blocked |
| What does `DuelHD` change? | 68k call/patch map and original-versus-installed byte comparison | Keep loader patches separate from recovered game behavior |
| Are original Amiga disk images available? | User-provided or already owned originals with a separate immutable manifest | Needed for disk-layout/protection/installation fidelity; LHA members cannot establish missing disk metadata |
| Why does `scen3` reuse `euro_`? | Index parsing, launcher assigns, loader call sites, original disk comparison | No auto-merging, renaming, or inferred course identity |
| Are all car/course counterparts available in DOS? | Content semantic-ID crosswalk with dimensions/anchors/events | Presentation switching must reject or explicitly defer unsupported combinations |
| Is executable music packed or self-contained? | HUNK sections, replay entry points, embedded data references, timing source | Scope a dedicated music-player recovery task; no generic MOD assumption |
| Are visible/audio timing quirks original or patched? | Pinned original and supplied profile traces under later authorized runtime work | Record separate behavior profiles and bounded fidelity claims |

Missing disk images are a provenance/fidelity blocker, not a reason to substitute an unrelated download or stop all supplied-file analysis. Do not fetch game media or Kickstart ROMs as part of this plan.

### Required extra Amiga scenery content

The user confirms the extra Amiga scenery is **Northern Germany Challenge** and requires it in the final implementation if the necessary files are supplied. This is a content/gameplay requirement as well as an asset requirement. It is conditional on media availability, not an optional feature to discard after the three DOS scenery families are recovered. If required files are absent, retain an explicit pending input and unresolved acceptance criterion; do not mark the requirement complete.

There are four local Amiga scenery namespaces: base `scen\sc1_`, `scen1\scen\rock_`, `scen2\scen\euro_`, and `scen3\scen\euro_`. The fourth tree (`scen3`, 37 members) is a concrete Northern Germany Challenge candidate. It has road files 0 through 6, while `scen2` has 0 through 5. Its `scen.dat2` is byte-identical to `scen2\scen.dat2` (SHA-256 `fb9f139f8207d2544d954454081dc721fd2610e9915075ec77a241eeb881d3ae`), despite different resource/road bytes. The intended content name is user-confirmed; the index alone cannot establish this local tree's byte-level identity. Later historical release notes mentioning a Northern Germany variant using `euro` names are corroborating leads, not a substitute for index/loader/original-media mapping.

The DOS folder contains candidate comparison families `CCC` (road `.DAT` files 0 through 6), `EC_` (0 through 5), and `TDS2` (0 through 5), with corresponding picture/sign/font/high-score naming. These local filename observations provide an investigation matrix; they do not establish a platform-to-platform course mapping. Compare decompressed route segments, stage ordering, lengths, grades/curves, object/sign IDs, traffic/police/fuel events, time/score rules and selection labels. Detect duplicates and modified variants by decoded semantics, not by file prefix or compressed hash alone.

The Amiga-recovery-to-switching gate (P4 to P5 in the main roadmap) must deliver a neutral, validated course/content model usable by the portable core, including the extra scenery's gameplay data. Preserve platform-specific mechanics as explicit profile differences where evidence demands them. Register the new course independently from graphics/music/SFX selection; run its full route and event acceptance scenarios. Availability of EGA/CGA artwork for that course is a separate compatibility decision: document supported provider combinations and any safe rejection/deferral until suitable original counterparts are supplied or proven. Do not substitute arbitrary invented scenery.

## Ordered Amiga development work packages (future authorization required)

These packages start only after the DOS portable-core/resource and native Windows milestones specified in the main roadmap. Minimal cross-platform architecture seams may be designed earlier, but Amiga recovery must not replace the DOS primary sequence.

| ID | Prerequisite | Step-by-step work | Durable deliverable and acceptance gate |
|---|---|---|---|
| AM-01 | Native Windows DOS baseline accepted | Freeze this archive manifest; assign supplied-package profile ID; separately manifest any original disks; record source licensing/provenance and installation differences; map script assigns to a virtual resource namespace | Source profile document that makes every input and derived artifact traceable; no historical-original claim without matching evidence |
| AM-02 | AM-01 | Import `duel`, `DuelHD`, and `sfx/song` as big-endian 68k HUNK candidates; validate every section/relocation/table boundary; detect overlays, packed code, entry points, compiler/runtime patterns; map library vectors and hardware-register references | Reproducible HUNK/relocation map and disassembler projects; original bytes preserved; unknowns explicit |
| AM-03 | AM-02 | Recover file-load and packed-data call sites before selecting wrappers; isolate `Rpck` and embedded-signature handling; document bounded input/output sizes and failure paths; derive synthetic/owned fixtures; compare decompressed data against the game's routine later | Executable-linked wrapper specification and byte-equivalent valid-output fixtures; bounds/negative tests; no magic-only guess accepted |
| AM-04 | AM-03 | Classify every graphics family; parse IFF metadata then pixel/mask/palette bodies; recover custom `.shp` framing and animation tables, anchors, clipping, layering, text/font/vector content; trace screen modes, palette changes, copper/blitter behavior | Complete family catalog and deterministic decoded-frame fixtures; every visible original resource has an owner or documented unsupported status |
| AM-05 | AM-02, AM-03 | Recover car/scenery indices and namespace rules; map road/vector formats and physics/vehicle tables; compare semantics with DOS recovered structures and the `CCC`, `EC_`, `TDS2` families; investigate the fourth Amiga scenery tree; normalize supplied extra-scenery route/event/gameplay data for the portable core | Bidirectional semantic resource-ID crosswalk and neutral course definitions with provenance/confidence; extra scenery included if files supplied, otherwise pending input recorded; geometry/physics equality proven separately from visual similarity |
| AM-06 | AM-02, AM-03 | Recover 8SVX and custom sample loaders; decompile `song` replay/control code; identify channels, sample signedness, rate/period, loop boundaries, pitch/volume/envelope, priority/preemption, stereo/filter behavior and timing source | Portable C sample/music behavior specifications and register/event/audio fixtures; source review and compilation do not equal listening acceptance |
| AM-07 | AM-02 through AM-06 | Recover the remaining 68k control/game logic function-by-function; create a routine ledger linking original section/offset, C function, dependencies, assumptions, and fixtures; compare DOS/Amiga gameplay mechanics before merging any common function | Portable C Amiga semantics with documented differences; every reachable routine translated, consciously retained behind a bounded adapter, or explicitly deferred |
| AM-08 | AM-04 through AM-07 | Under a later explicit runtime-testing authorization, run pinned Amiga reference profiles; capture deterministic event/state, indexed frames and audio/register traces for all menus, races, crashes, police, fuel, shifts, endings, expansions, failures, and timing cases | Scenario-by-scenario differential evidence with separate semantic, visual, audio and user-acceptance results; no blanket parity from a successful boot |
| AM-09 | AM-08 plus switch contracts | Integrate Amiga presentation/audio providers into the Windows host; exercise all supported graphics/music/SFX combinations and switching points; package code without original assets or ROMs | Accepted switchable native build using user-supplied files, exhaustive compatibility matrix and no-resource package audit |

Use a 68k-aware disassembler/decompiler and an independently checked HUNK loader in the future phase; record exact tool/plugin versions and import addresses. Decompiler output is an analysis aid. Review recovered integer widths, signedness, overflow, big-endian loads, packed structures, pointer arithmetic, branch flags and callback contracts before admitting portable C. Prefer fixed-width explicit operations and offset-based resource references over transplanting Amiga pointers into host memory.

## On-the-fly switching contracts and hazards

The integration target is the DOS-derived portable gameplay core with replaceable presentation/audio providers. Amiga decompilation supplies original presentation/replay behavior and documents gameplay differences; it must not silently replace DOS rules when the user changes a graphics or audio setting.

1. **Separate settings.** Maintain independent `graphics = DOS EGA | DOS CGA | Amiga`, `music = PC Speaker | Amiga`, and `sfx = PC Speaker | Amiga` provider selections. PC Speaker music and sound effects are the user-confirmed DOS audio scope; their implementation recovery and runtime validation remain future work. Validate individual cue coverage and timing before accepting the full combination matrix. Keep provider absence visible and explicit.
2. **Stable gameplay state.** Identify resources by semantic IDs (car, course, road object, dashboard element, animation/event) in an authoritative gameplay state. Renderers consume state snapshots; resource addresses, palette indices, frame sizes, and audio-channel state never determine collision, physics, AI, RNG, saves or progression.
3. **Exact content crosswalk.** Build explicit per-profile mappings for each car/course/animation/event. Confirm pivots, scale, clipping, masks, road projection, HUD units and font metrics. Include the extra Amiga scenery's normalized route/gameplay content whenever the required files are supplied. An Amiga-only expansion does not acquire a DOS counterpart merely because filenames resemble one another. For unavailable visual counterparts, retain the current provider or defer the selection at a documented safe point; keep the course inclusion requirement pending until its playable content is validated.
4. **Transactional graphics commit.** Prepare and validate target resources before switching; freeze a complete simulation tick snapshot; replace provider handles at a frame boundary; regenerate background/HUD/caches; then resume. On failure restore the former provider/state. Preserve active animation logical phase and derive the new frame from the target timing table; do not reuse a frame index across unlike sequences.
5. **Independent audio commit.** Define playback policy for ongoing music, engine loops, sirens and one-shot effects. Recover a shared logical event/loop phase where possible; otherwise use an explicitly documented restart/fade policy. Stop old provider voices cleanly and initialize new voices without replaying old gameplay events, double effects or stuck notes. Audible transition behavior needs user acceptance.
6. **Timing fidelity.** Keep deterministic gameplay ticks separate from presentation refresh and audio sample scheduling. Preserve measured original sequence/event timing; assess PAL and NTSC independently. Amiga audio period clocks differ between regions, so fixed sample-rate assumptions can alter pitch. [Commodore Amiga hardware manual, audio clock/period limitations](https://amigadev.elowar.com/read/ADCD_2.1/Hardware_Manual_guide/node00DE.html).
7. **Scope of on-the-fly.** Support switching during menus, loading, title fades, active race, pause, shifts, skid/crash, police/fuel events, stage transitions and ending sequences where providers have the required resources. Treat safe-frame deferral as bounded latency and display the reason if completion requires a later state. Do not claim arbitrary switching until the matrix is exercised.
8. **External resources only.** Mount user-owned DOS and Amiga files read-only through the same resource abstraction. Accept an installed Amiga tree first; direct LHA mounting is a later dependency/security/licensing choice. Cache only user-local derived data with source-hash and decoder-version keys. Keep high scores/settings/cache outside `reference`. Distribution contains code, metadata schemas and synthetic tests; no copied bitmaps, samples, music, fonts, ROMs, game executables or reversible embedded media blobs.

Required integration checks include switching to every supported target from every active provider, repeated/rapid requests, loading failure, missing/corrupt/changed source files, provider initialization failure, current asset with no counterpart, animation boundaries, continuous loops, queued one-shots, focus/pause transitions, save/reload, and rollback. Deterministic core-state/RNG hashes must remain equal when only presentation/audio selection changes. Pixel differences across intentionally different graphic providers are expected; compare each provider against its own pinned original profile, not against another platform's artwork.

## What remains unverified at this planning checkpoint

No Amiga code has been disassembled/decompiled; no HUNK sections/relocations/overlays have been parsed; no in-member packer, `.shp`, road/car/vector, music or custom sound format has been decoded; no asset has been rendered or played; no game has booted; no original disk comparison or authenticity determination has been made; no DOS/Amiga semantic equivalence or live switching has been demonstrated. These are future work packages and acceptance gates, not current achievements.

## Complete archive member metadata

Member paths are archive-relative; sizes are bytes. The CRC column is the archive-reported CRC, not a proof of historical originality. SHA-256 and the first 16 bytes were computed by decompressing each member to process memory through installed 7-Zip, without saving member payloads. The first-byte field is a bounded signature observation, not a decoded-format claim.

| Archive member | Size | Packed | Method | CRC | SHA-256 | First 16 bytes |
|---|---:|---:|---|---|---|---|
| `TestDrive2&DataDisksHD.info` | 900 | 439 | `-lh5-` | `00003C0F` | `4bea5e45848fb6c75d57e94405450f8e04bf656faa9141104f21068fca5f3784` | `e310000100000000005900660038000f` |
| `TestDrive2&DataDisksHD\cars.dat0` | 66 | 55 | `-lh5-` | `00004574` | `6f1e087e80d8420c168e14bd67f62803f5a34c88185b293b2c3633beba8d8f20` | `0002636172732f703935390000000000` |
| `TestDrive2&DataDisksHD\cars\f40.anim.shp` | 12518 | 4509 | `-lh5-` | `000019E9` | `50f67201a6c278594daf87e8d8a56cb5381ab9209269b9a3909ad5dd3237a338` | `5270636b000038cea2000038ca001666` |
| `TestDrive2&DataDisksHD\cars\f40.b` | 1628 | 982 | `-lh5-` | `0000220B` | `208079e97b85f9ba78bb15c0e3fae37236a6f4889e336b1bd80d85a419eb6150` | `5270636b00000686e8000521fc0fa01b` |
| `TestDrive2&DataDisksHD\cars\f40.b2` | 32 | 32 | `-lh0-` | `0000EF59` | `f9b4e473f0c3adcb4a54afc0983e0b431964385720dd3dba251c90e25155a594` | `0479080e0806073804d3041f034002dd` |
| `TestDrive2&DataDisksHD\cars\f40.gas.p` | 104 | 84 | `-lh5-` | `0000653A` | `b60bf65681a99327dc2bd0a0ac45f614076f0ccf3ac2634810de172e6d452f11` | `434d4150499200000000009050404000` |
| `TestDrive2&DataDisksHD\cars\f40.rear` | 11236 | 5287 | `-lh5-` | `0000485D` | `4e9de5aa42f3eeddf16dcbcc09ae90bbc352615a9c67b95245fd5abf9109145b` | `464f524d00002bdc494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\f40.rear.p` | 236 | 185 | `-lh5-` | `0000C1C2` | `0fa0f8e47ec9cb982a4f4d49bbf73544dc0b401e88ef97bf7c8e35f0a19be57c` | `5270636b000000eeef464f524d000000` |
| `TestDrive2&DataDisksHD\cars\f40.sb` | 8776 | 3845 | `-lh5-` | `00001BDF` | `71f61019003f85ce5d8c18574b9dbe3c53563ce3fb5f8dc80e4c41663278df2b` | `464f524d00002240494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\f40.sideview.shp` | 8101 | 5199 | `-lh5-` | `0000CCB8` | `a5bf5a752f1125b1d07993809cb2164bd9059ac75e48bd59389cf385ef18db97` | `5270636b000051feee50506b63000363` |
| `TestDrive2&DataDisksHD\cars\f40.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars\f40.st.p` | 238 | 185 | `-lh5-` | `00005E95` | `e27113da7c519f694449aedcce906cd5ec1748858f597b8b63fdb279ce947af1` | `464f524d000000e6494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\f40dash` | 12322 | 8322 | `-lh5-` | `0000FA1F` | `b707064b320c349b3579d755ac89023d8644f0fd6d45da41db7d4e6333a021d3` | `464f524d0000301a494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\f40dash.shp` | 15231 | 8965 | `-lh5-` | `0000E403` | `e872d30227b5bdfb80db4e7f99cec84ecbf731a3d2919aff2c6d5adcd3a9ace1` | `5270636b00006fe88a50506b63001c66` |
| `TestDrive2&DataDisksHD\cars\f40engine` | 1578 | 1401 | `-lh5-` | `000066A9` | `465e662297b6642a207869b9ac4b8b7d47ad7f80eb6d2759b2ee65d9abafa6ce` | `000006241eef0003020104f9000f0d1b` |
| `TestDrive2&DataDisksHD\cars\f40logo.shp` | 1733 | 1134 | `-lh5-` | `0000C270` | `97028b3863bc9f17c054c64770b830be9b3da81843471291af43a233cb4f4144` | `5270636b0000080ef20000080a00026c` |
| `TestDrive2&DataDisksHD\cars\f40road.shp` | 14991 | 9733 | `-lh5-` | `00005C4E` | `068e2c68c995184bd65df5dd33c2d71a92b1dd0b55f9e0647f171f1b6cd3c80d` | `5270636b000041fa8050506b63002262` |
| `TestDrive2&DataDisksHD\cars\f40turbo` | 4346 | 4275 | `-lh5-` | `0000DFC0` | `5c3fee268292ede14ad660d7fd0df9e4ff548c792648b257623d7b46f70bbd89` | `000010f41eefe7f10d01e5ff23272f24` |
| `TestDrive2&DataDisksHD\cars\p959.anim.shp` | 9566 | 4079 | `-lh5-` | `0000F1AF` | `45443119a0915f1e04d4b01df5b825dd3623674aad98a32c4f5254143bd83731` | `5270636b0000316ca200003168001666` |
| `TestDrive2&DataDisksHD\cars\p959.b` | 1359 | 819 | `-lh5-` | `00008D57` | `422a83c0122f7533ec0f44c595fb0fe92c2f5e51097db0383865b854651c8379` | `5270636b00000686860006206c0ed81a` |
| `TestDrive2&DataDisksHD\cars\p959.b2` | 32 | 32 | `-lh0-` | `0000D633` | `f746647b417007e9a07091a2900844d3a4aafc933524c54476974e00b088579e` | `0822096f08c9058903c4039f02a901f6` |
| `TestDrive2&DataDisksHD\cars\p959.gas.p` | 104 | 80 | `-lh5-` | `00005079` | `33e1f856b1ed7f284c2f9ff4c7e6e597272136bc6150547025e1ec2ec77f49fd` | `434d4150499200000000009050404050` |
| `TestDrive2&DataDisksHD\cars\p959.rear` | 10416 | 4683 | `-lh5-` | `000072F7` | `e4adb03514b5cb469eee3d534b1fc89712eb40bd8568cab918ea04f46bbfc3b5` | `464f524d000028a8494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\p959.rear.p` | 238 | 173 | `-lh5-` | `00000B42` | `6f954311f274739c47c6e538aa3800807b22e83ef747b9e802d7b0e52a099eb5` | `464f524d000000e6494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\p959.sb` | 8670 | 3816 | `-lh5-` | `00008450` | `b84b96290ac1c7722e8ce576763a3d4d6d051c2a44639fece1aa55298d156698` | `464f524d000021d6494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\p959.sideview.shp` | 9008 | 6017 | `-lh5-` | `0000AB06` | `0bdfc81ec9224f5fdd8a2068a3e962e9fb7c66cc497926f1ce51a6f0efc857de` | `5270636b000061c6ee50506b63000363` |
| `TestDrive2&DataDisksHD\cars\p959.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars\p959.st.p` | 238 | 172 | `-lh5-` | `00005789` | `d88bfddcd0e64de14ee772337b11c1f7093e0233fe9faab705d896964dc6ab93` | `464f524d000000e6494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\p959dash` | 11612 | 7787 | `-lh5-` | `0000848C` | `ea8a6f4ac88610ce1624fbea4c5135373347f4d5f9d0277225697f2dca21f5a9` | `464f524d00002d54494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars\p959dash.shp` | 17958 | 10959 | `-lh5-` | `0000F428` | `9ec1dbba2d3a52ce8e7d27784b27dda731f8f4906da7d6b297187e1f1a242b3b` | `5270636b00007cc48200007cc0001e34` |
| `TestDrive2&DataDisksHD\cars\p959engine` | 3042 | 2667 | `-lh5-` | `00003A87` | `256a5311e09b852ad95e7da70f5fd746931e76eb41a594a191f3b81c2d9bfae0` | `00000bdc1eeff0fce8e6e605100b0602` |
| `TestDrive2&DataDisksHD\cars\p959logo.shp` | 1875 | 1132 | `-lh5-` | `0000BE3F` | `447f72d1e60c456ab8052c7513d5776c1aa71f4d3912550765c1b48c718c81a0` | `5270636b00000926f20000092200026c` |
| `TestDrive2&DataDisksHD\cars\p959road.shp` | 15728 | 9563 | `-lh5-` | `00007687` | `7116a7d0ccfdc6273ed1ee86fe591e51034182012bdeb350542be6d34395bb37` | `5270636b000048c48050506b63002262` |
| `TestDrive2&DataDisksHD\cars\p959turbo` | 4494 | 4281 | `-lh5-` | `00003A83` | `084c92ad1aefc1f99dc5643dcae77ccad3c6e3abc7c797ee183a3272f1b49060` | `000011881eef4632ff2b0a112411eed1` |
| `TestDrive2&DataDisksHD\cars1\cars.dat1` | 162 | 84 | `-lh5-` | `00002106` | `dffff8b48a1193dbd70352031a5e9b59d8dea4d8442126512f0d0a5464e12ee8` | `0005636172732f63616d6f0000000000` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.anim.shp` | 12454 | 3933 | `-lh5-` | `000021F7` | `cdfee4546a686621dd4ba6133ee2a9421d3196ca3ebe1ea649cb812c599c41a4` | `5270636b0000364ea250506b63001666` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.b` | 1670 | 704 | `-lh5-` | `0000960A` | `660d1517c2efa6cd162780bc2819f368a2eb354c44fb727c55baf2f724fe43e1` | `000417700d4814b41ce8000100c042c0` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.b2` | 32 | 31 | `-lh5-` | `00004E9C` | `4dc1fba1977e61aaa31688d9b43967aaced370ba38e9956b8b5da8802eed4555` | `04ef04ef04ef034e028901fa018b0139` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.gas.p` | 104 | 85 | `-lh5-` | `0000B3FC` | `de5b301562d2c4422f24d6b6336af9ba66391ba52cabf93e18f962ec21ebd1e9` | `434d41503d3200000000009050404000` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.rear` | 9758 | 4205 | `-lh5-` | `00002B09` | `f9db511de311361eee23c6d5d457931b42c37601d3975ea61e9a7870c5ca1668` | `464f524d00002616494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.rear.p` | 104 | 84 | `-lh5-` | `0000F4C8` | `8a3010dcb85aba51856b46e9579cfe6b76e910c9696391a49fccc6b78ffa505c` | `434d415000c038fe0000009050404000` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.sb` | 8624 | 3842 | `-lh5-` | `0000A95C` | `529f3f873aa93dd6fd26f7d9f8279e5e2cb4e6fd271643f2ed5b300d479f346e` | `464f524d000021a8494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.sideview.shp` | 8378 | 5392 | `-lh5-` | `0000765A` | `f7a0e023a3ee711baf9071cee12515476b071facdc67548f42b66f0b4d25f117` | `5270636b0000627aee50506b63000363` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars1\cars\camo.st.p` | 104 | 83 | `-lh5-` | `00000E46` | `f346ec2e2ef760cef7a79569f3ef16847c3a6b37568e5314f26d306ea6609abe` | `434d415000c039960000009050404000` |
| `TestDrive2&DataDisksHD\cars1\cars\camodash` | 13282 | 6722 | `-lh5-` | `0000B74F` | `2af8baa641711aaea1838b069c74316f40207631624af5c6bc1e7405497797b7` | `464f524d000033da494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\camodash.shp` | 11725 | 6611 | `-lh5-` | `00006A19` | `3be7428d4ff7a50561fcceaef3e23bedb701e484d1e91eda9417db224d75e393` | `5270636b000057ae9e50506b63001766` |
| `TestDrive2&DataDisksHD\cars1\cars\camoengine` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\camologo.shp` | 1870 | 1120 | `-lh5-` | `00006E2B` | `edaf70c0438f6549c2b2eeb4291c8b5133eea2cac2ec4847f68df3c74aaf774f` | `5270636b000008fef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars1\cars\camoroad.shp` | 15797 | 8094 | `-lh5-` | `000069F8` | `3e4eded5da7323fa4dcfb941ddc4503cc0e2190f9d798f37217da7defa1e1f96` | `5270636b0000483a8050506b63002262` |
| `TestDrive2&DataDisksHD\cars1\cars\camoturbo` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.anim.shp` | 9253 | 3863 | `-lh5-` | `0000410F` | `d8f57c33bb9efd480829f2e9a6c5c8f3ec689f5f2ac898095bca0e144d4980c6` | `5270636b00002fe6a250506b63001666` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.b` | 1341 | 839 | `-lh5-` | `000001B5` | `cbef3fa82aa3cbcfbe10f2b2cd2df1b787932a5de9fecf76ab7aa27994fd657b` | `5270636b00000686e800041ce80dac19` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.b2` | 32 | 32 | `-lh0-` | `00000666` | `e7a5e90647dd1f54370e8c85625c97e095841feeb8325e1b9616337da169ce3c` | `07f507f5061b042102bf020701db008a` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.gas.p` | 104 | 79 | `-lh5-` | `0000D7CD` | `214fe1a76d5c05c7c892302ab92d4b02fc7d64b9494c26eb4ab3e22127a22bfb` | `434d4150000000200000009050400000` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.rear` | 10640 | 4513 | `-lh5-` | `00006AEA` | `6ec1b1ea4d04f23a62ffcff8c0a37db91f27fa4d02c0e11fac414f6927a199a7` | `464f524d00002988494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.rear.p` | 104 | 83 | `-lh5-` | `0000EF54` | `bef4cf7c599f0981e50bfc0c6f9a0e8779c4215423d2acf83534c3376f786ee3` | `434d415000c0421800000090f0400000` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.sb` | 8572 | 3801 | `-lh5-` | `000028AE` | `ea62a0b40a54a4b22d10dadf47bf2e31323047da39224a6e3866c9f9e4e3ebf5` | `464f524d00002174494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.sideview.shp` | 7187 | 4623 | `-lh5-` | `00001189` | `4eb728495f509174fc453e57c3f37132d63a429cf17678a60c527c5acdda09bc` | `5270636b00006254ee50506b63000363` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars1\cars\dodge.st.p` | 104 | 82 | `-lh5-` | `0000CBD5` | `9dd2fa5bdc300b83969336a63e6fc0b4b0e7a242087522738a9da313198602b8` | `434d41503d3200000000009050400000` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgedash` | 10838 | 5627 | `-lh5-` | `0000E5A3` | `322ab2e462a5d9a67add6966aa12f6af80a213282f2e242bf4942cfb52115d12` | `464f524d00002a4e494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgedash.shp` | 12509 | 7023 | `-lh5-` | `00009F78` | `dd35dca0392752b9080305665ec91a4363c6d79ccf125c38090b997a2d0d249b` | `5270636b00005754ae50506b63001366` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgeengine` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgelogo.shp` | 1756 | 990 | `-lh5-` | `0000A18F` | `2110d7ee2445f1bc19475e79459294ac0e0e519f5e3852e341446155d3deb5e5` | `5270636b00000a3ef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgeroad.shp` | 13508 | 6288 | `-lh5-` | `0000F44F` | `303a3479eb33ebb2bc1c633fc349ba508e1548e625da30a158b44d11f80a2f6a` | `5270636b000046528050506b63002262` |
| `TestDrive2&DataDisksHD\cars1\cars\dodgeturbo` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.anim.shp` | 13531 | 4650 | `-lh5-` | `00007EAB` | `6cc95383b54fb85557a046c301d4fa0c1dc138368fcb897d99867e4766876743` | `5270636b00003e28a250506b63001666` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.b` | 1460 | 926 | `-lh5-` | `00000E20` | `408613849e10bdf7956ba47f917c3b7569e622a81a7630e048c15b3a85030e17` | `5270636b00000686e8000419000ce415` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.b2` | 32 | 32 | `-lh0-` | `0000A97E` | `ec9ca64e6e738f52ef0fb71a3fe953f34ccdede2946091be336ac6fa3f36442d` | `03d30422045102bf0289020601770129` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.gas.p` | 104 | 81 | `-lh5-` | `00006EB8` | `f0c8efda012f32f354dcdcea23aa3711715df085a90103c8257137369dd8e2b4` | `434d415000c038fe0000009050403040` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.rear` | 10854 | 4231 | `-lh5-` | `0000E140` | `df53b25628e1173defa8e8525a4db7b280b00943ee623a3aa6094a55e92394af` | `464f524d00002a5e494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.rear.p` | 104 | 78 | `-lh5-` | `0000D9FE` | `c587941cf0923985d42c204c2e40969fed2c9158362f2f2d6d14882ebd644b79` | `434d41507b700022000000905040c0d0` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.sb` | 8536 | 3797 | `-lh5-` | `00007C3D` | `1c45d7d8da8336773153767ded97896b6ea95624b25cefeaa1868b8ec431f7c0` | `464f524d00002150494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.sideview.shp` | 7782 | 4921 | `-lh5-` | `0000D48B` | `3e90baaebbec92e56591f1d764cd929c7a2f8e6fc2fe98e9c97d87e825d996ea` | `5270636b0000647aee50506b63000363` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500.st.p` | 104 | 74 | `-lh5-` | `0000E4DE` | `c63876e58bfe7f1b1896e617e9642badbe53d2fc38752d5d919f1d0ecd8fe036` | `434d415000c039960000009050402030` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500dash` | 13218 | 7618 | `-lh5-` | `00000168` | `8bbc9c9793799d1b54d799abe057019834df8943efe670811b7b0ca4b787f5c5` | `464f524d0000339a494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500dash.shp` | 15600 | 8950 | `-lh5-` | `0000075D` | `a0b43a59ed146d977b8da9ed640fb978086d9afa533690b6b2e24a73dcec3044` | `5270636b00007d408250506b63001e62` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500engine` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500logo.shp` | 2061 | 1160 | `-lh5-` | `0000180F` | `6fd89f28d17f561bda0f64f143ae3a5aeebed7c02a95e42e67009c1a8c4430a3` | `5270636b00000ab6f250506b6300026c` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500road.shp` | 17481 | 9819 | `-lh5-` | `000059FE` | `09c49d8bb944743b63e193c5e05b236cb59b173c5cdb89933965513cacd3cb23` | `5270636b0000501e8050506b63002262` |
| `TestDrive2&DataDisksHD\cars1\cars\gt500turbo` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.anim.shp` | 14092 | 4651 | `-lh5-` | `0000D490` | `84877ead476d0301a02ce5dd302bb991cbe684d42eede1d09d73e46d48aee410` | `5270636b00003e14a250506b63001666` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.b` | 1670 | 885 | `-lh5-` | `00002E64` | `c9fb36a5565550d7476e3b44f9020712a787f8153b9d5f70bf0ffa1d6dc726f1` | `00041bbc0dac19002134000100c042c0` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.b2` | 32 | 26 | `-lh5-` | `0000FE34` | `11539d86fc288407b7f99581db0588bee3ce552b4af91b3bac5a59259b15c297` | `088f088f05040375025301bb008b0000` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.gas.p` | 104 | 85 | `-lh5-` | `00009C79` | `0eb88b417e2e100889a6867cbc83d1ce887d8768d2cc79e578414e0448832fd2` | `434d415000c038fe000000a050400030` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.rear` | 9642 | 3861 | `-lh5-` | `00000B65` | `d7c9df60845747aedefc11934f04eae50c4d25475cd699a7671589701331782f` | `464f524d000025a2494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.rear.p` | 104 | 83 | `-lh5-` | `0000CFB3` | `735f05234a2050ec26cd07d349f51a2fc159e880529d77d8f604744a2c299bf1` | `434d415000c20b280000009050400020` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.sb` | 8532 | 3732 | `-lh5-` | `0000CD2B` | `7150f02a410cf210792c073133c7d7c35544a2b153dd9c42a33f7c5fdd4c850c` | `464f524d0000214c494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.sideview.shp` | 8519 | 5354 | `-lh5-` | `0000567C` | `facd2b918593b6b843e2a5894931b6952544a54062c1d798813c3eb209aaeeac` | `5270636b000062caee50506b63000363` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars1\cars\gto.st.p` | 104 | 85 | `-lh5-` | `000012AE` | `bb3b877d25ba783eda5649f6026015f6c6f5edda020a688dd3fc02b73b1da6c0` | `434d415000c039960000009050400010` |
| `TestDrive2&DataDisksHD\cars1\cars\gtodash` | 12854 | 7330 | `-lh5-` | `000004E5` | `e8326804b8926aa37f25aad620488c212d0a5b870a713bf334dbd425cd2c287d` | `464f524d0000322e494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\gtodash.shp` | 15852 | 8876 | `-lh5-` | `00003036` | `22c87cafb490c3b962fe462a86ac80e481dd3d0c9cce385ffe95577c77f6ee6a` | `5270636b000080169a50506b63001866` |
| `TestDrive2&DataDisksHD\cars1\cars\gtoengine` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\gtologo.shp` | 1717 | 1092 | `-lh5-` | `0000A950` | `5c30ba18c7c30d2f7487781ca0b8116cfab807244b65b3208aadb8b82cec74b7` | `5270636b000008aef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars1\cars\gtoroad.shp` | 15019 | 8539 | `-lh5-` | `0000CE72` | `7206ad92c533682a38c58aa23eb2639b1d0c1431947578cd197bf9306dcc3b92` | `5270636b000044f28050506b63002262` |
| `TestDrive2&DataDisksHD\cars1\cars\gtoturbo` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.anim.shp` | 14787 | 4371 | `-lh5-` | `00005597` | `73f2581a957bb358dcdab253f1b51357691cc8abe63ed6f910d94a8920bbe689` | `5270636b0000421aa250506b63001666` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.b` | 1195 | 807 | `-lh5-` | `00007420` | `5a455531277b089580f0f93b9c2fa87bee7d2f7537d64c73771b3a0063dc32ae` | `5270636b00000686f7000414b40af011` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.b2` | 32 | 31 | `-lh5-` | `0000247A` | `3e709443cd3a081463ec668a9483bc4069701fc10e8adffcaad27a983fd47c04` | `04ef04ef04ef034e028901fd018f0146` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.gas.p` | 104 | 85 | `-lh5-` | `0000A6B5` | `a789ca024e2575da69cd6888777969f3bff4501bec747b54445b2e84c2747447` | `434d4150040000fd0000009050404000` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.rear` | 10252 | 5257 | `-lh5-` | `0000B405` | `6a165aafd173d828e6f87143f7f975412cdaf1f6124409d738c05f303cf786a2` | `464f524d00002804494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.rear.p` | 104 | 81 | `-lh5-` | `0000DE0C` | `e9ee789a461a0de5b592dcb97d24e79c6b272757362d6d8e4bad9f1c313eae9c` | `434d415000c038fe000000c070403000` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.sb` | 8656 | 3856 | `-lh5-` | `0000097D` | `05752a1a98e3fefebb57a6f82e1d7a61ec0955506adb0688af292f27e8c6d3a7` | `464f524d000021c8494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.sideview.shp` | 8665 | 5226 | `-lh5-` | `0000314D` | `ccb4015d3bb8546156b021352febbe18f74364ae294d06b23835f91dc216fbe0` | `5270636b0000549aee50506b63000363` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars1\cars\stingray.st.p` | 104 | 86 | `-lh5-` | `0000D7BD` | `b224e08fa9b0a14ea399384ed020993abbcaf0e011373d75bede314228a8ceb1` | `434d415000c039960000009050404000` |
| `TestDrive2&DataDisksHD\cars1\cars\stingraydash` | 14420 | 8976 | `-lh5-` | `00000455` | `0125bf485b7d8b89e6419a8835dda411d2045772c80ccf8817d13d6330ce2eff` | `464f524d0000384c494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars1\cars\stingraydash.shp` | 15884 | 9240 | `-lh5-` | `0000B728` | `fdc9f85b20e29a0fb00f462bd798d10104f630cb36ae643ce6c2029e0dc5f732` | `5270636b00007aa49650506b63001967` |
| `TestDrive2&DataDisksHD\cars1\cars\stingrayengine` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\cars\stingraylogo.shp` | 1959 | 1218 | `-lh5-` | `0000732F` | `753e5f3c9e72502ef2193cbffeae18740be2970553aee5c4772648ee29dd470b` | `5270636b0000094ef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars1\cars\stingrayroad.shp` | 16227 | 9640 | `-lh5-` | `00000064` | `c65ea8c9e0bea3a776d9f59f3efeb102b33043d316c2ff64a35be63b16d863ed` | `5270636b000047508050506b63002262` |
| `TestDrive2&DataDisksHD\cars1\cars\stingrayturbo` | 3267 | 3263 | `-lh5-` | `000096AC` | `f566febf01b5ce10e9d12d103bd5c9a754448a2143617cfeba932f7039cc2067` | `5270636b00000d26f600000d202710d4` |
| `TestDrive2&DataDisksHD\cars1\disktype.dat` | 1 | 1 | `-lh0-` | `0000C0C1` | `4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a` | `01` |
| `TestDrive2&DataDisksHD\cars2\cars.dat1` | 162 | 98 | `-lh5-` | `00009AE5` | `68355e2756294f6501b006dfe3a1705776ed46811074f5aca0e7073d9cfefba0` | `0005636172732f766574740000000000` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.anim.shp` | 26632 | 11681 | `-lh5-` | `0000CE6E` | `d290ae233efbdf20da153c968815950fbb7229b05831e26232929891b0291fbb` | `5270636b00008a14c250506b63000e64` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.b` | 1670 | 920 | `-lh5-` | `000062E2` | `62dfe2a4a923622b9d5211a9f50532e51ee72ca075447f3e5976ca5a6a58f361` | `00051f400e741c842328000100ea9823` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.b2` | 32 | 32 | `-lh0-` | `00007A38` | `a752d51eacfba6e0eb0f9a9b30030b57f11094ad18db7543875e30640297a40d` | `044c042e041a0316023001ce01440122` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.gas.p` | 104 | 85 | `-lh5-` | `0000A858` | `05549509da128c3eb94a48c5872db2d2633554cae339161745702d48248b4c2d` | `434d4150ffd402020000009050406000` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.rear` | 9774 | 4580 | `-lh5-` | `00009E25` | `876ad36c2b7cb0c199a5ff48ee8d9988512752397de8482712032562eca3e198` | `464f524d00002626494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.rear.p` | 235 | 180 | `-lh5-` | `0000DD2B` | `4e24473625b70d12fed6aa3bdd47dc9384f54b94dfd64a940c3719980c15f365` | `5270636b000000eeef464f524d000000` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.sb` | 8696 | 3833 | `-lh5-` | `00009981` | `3ce037c8f0cb9a004b7f5b7acd6c1dda414f6368d9bf79568018b057118bf7da` | `464f524d000021f0494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.sideview.shp` | 8063 | 5598 | `-lh5-` | `0000D37E` | `a1d3fc8cd4cdb19a7d2f32cf6098fd4ed600006a233187f2c4a34c3a4990ff54` | `5270636b000058aaee50506b63000363` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.ss` | 252 | 58 | `-lh5-` | `00004A56` | `ad3feda8686dc0726a126641a2103b74fc99d858b288f648fa25be7d6211fbed` | `320c646f723020646f723120646f7232` |
| `TestDrive2&DataDisksHD\cars2\cars\coun.st.p` | 237 | 182 | `-lh5-` | `000090B1` | `e104ea6e8d4057d9aa1c91001de4691b46d2a782db1d2904d61faf5ff833863a` | `5270636b000000eeef464f524d000000` |
| `TestDrive2&DataDisksHD\cars2\cars\coundash` | 10962 | 6438 | `-lh5-` | `0000E44A` | `0d07caa99ae6effa430b85033e90771cafa47a65e3875648ee846f405d057036` | `464f524d00002aca494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\coundash.shp` | 15959 | 8778 | `-lh5-` | `0000210B` | `55cfbbc95f56a95c2f9b985396e5effa3d49c4ec77e62d88098444588d3b3991` | `5270636b00007d669250506b63001a66` |
| `TestDrive2&DataDisksHD\cars2\cars\counengine` | 3042 | 2667 | `-lh5-` | `00003A87` | `256a5311e09b852ad95e7da70f5fd746931e76eb41a594a191f3b81c2d9bfae0` | `00000bdc1eeff0fce8e6e605100b0602` |
| `TestDrive2&DataDisksHD\cars2\cars\counlogo.shp` | 1557 | 1126 | `-lh5-` | `00001A10` | `b13d0e611fc11ec6b8ac96eebe4a00da4dc3db6bb45f6364fbbc300c962c4e07` | `5270636b000007bef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars2\cars\counroad.shp` | 13768 | 8329 | `-lh5-` | `00008139` | `13890fd105064a46d68a6b92808dccd46beba884fc23aae7665902e89fe5c489` | `5270636b00003d528050506b63002262` |
| `TestDrive2&DataDisksHD\cars2\cars\counturbo` | 4346 | 4275 | `-lh5-` | `0000DFC0` | `5c3fee268292ede14ad660d7fd0df9e4ff548c792648b257623d7b46f70bbd89` | `000010f41eefe7f10d01e5ff23272f24` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.anim.shp` | 11750 | 4393 | `-lh5-` | `00008F48` | `1ccf603ed4f8110bdfa5b1f08f65bd771ad5a0a3f4e308628421cce1d110c9ab` | `5270636b00003e589e50506b63001766` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.b` | 1670 | 1004 | `-lh5-` | `00007F92` | `8adf71e52ce194489e0c2ceb74a269af0562b8867f77399785d08ba9f4d2bcdf` | `00051ce80e101a2c2260000100da9966` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.b2` | 32 | 32 | `-lh0-` | `0000792A` | `0dfb7d80be93bd8796e45cbb36515198c9294e15307a34a897f42ac96f463e82` | `038403e802bc020f0148011600ed00d2` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.gas.p` | 104 | 82 | `-lh5-` | `0000EB2F` | `170a1bebeaf9f2dbcd257077b6e257ca30d77f84e198ab3075d2c7c62e85ab9f` | `434d4150499200000000009050400000` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.rear` | 8532 | 3712 | `-lh5-` | `0000A956` | `c0e91f00ff2fe568d36ed6b5597ce3afdc75d4db027a0e9cf39fb4fa24233e33` | `464f524d0000214c494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.rear.p` | 232 | 171 | `-lh5-` | `0000752D` | `a7d0499c35eb2b1d16e1710b884f0e103a3f22931f20fd0f69d0ee2695c32070` | `5270636b000000eeef464f524d000000` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.sb` | 8746 | 3918 | `-lh5-` | `00003EAA` | `ddfb9e505e82c63f1e253a81a38e5c723ac7ff7f95999dbb42b88d1bcd5081d6` | `464f524d00002222494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.sideview.shp` | 8595 | 5391 | `-lh5-` | `0000F132` | `4c88dccee80d713b510de17c69c469969467be7cb56c5a8bd55c85546fcca63f` | `5270636b00005ce2ee50506b63000363` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars2\cars\lotu.st.p` | 238 | 171 | `-lh5-` | `00002924` | `e260b1698cee0d0ff0a07719c79809d0a6c2957fa64046b5c209f28f6c76c205` | `464f524d000000e6494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\lotudash` | 12120 | 7721 | `-lh5-` | `0000D2FD` | `ea4a033aa9031fb4148e2ca9e8bb609475dd5ffed1a612a55f2c6d0ee68efe39` | `464f524d00002f50494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\lotudash.shp` | 16761 | 10355 | `-lh5-` | `0000B6F0` | `ff19bf45d027f59acd57d7d59f32feeb0f9151934f8549397fd36641467f1ad4` | `5270636b000069888650506b63001d66` |
| `TestDrive2&DataDisksHD\cars2\cars\lotuengine` | 1578 | 1401 | `-lh5-` | `000066A9` | `465e662297b6642a207869b9ac4b8b7d47ad7f80eb6d2759b2ee65d9abafa6ce` | `000006241eef0003020104f9000f0d1b` |
| `TestDrive2&DataDisksHD\cars2\cars\lotulogo.shp` | 1534 | 1059 | `-lh5-` | `0000AE5F` | `881b3a708e8fbf8398c3585413a92d8f025dfe6c6a4ea7667ffd28b6d6445379` | `5270636b00000886f250506b6300026c` |
| `TestDrive2&DataDisksHD\cars2\cars\loturoad.shp` | 13814 | 8407 | `-lh5-` | `00004A6F` | `32714b38418c02426a0e0d15f6c49688c4bb39a5ad71bb9e7e9ea4445fe4f905` | `5270636b000042f28050506b63002262` |
| `TestDrive2&DataDisksHD\cars2\cars\lotuturbo` | 4494 | 4281 | `-lh5-` | `00003A83` | `084c92ad1aefc1f99dc5643dcae77ccad3c6e3abc7c797ee183a3272f1b49060` | `000011881eef4632ff2b0a112411eed1` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.anim.shp` | 14088 | 6090 | `-lh5-` | `0000DE8C` | `9febed5dccfcd367fb97735e68afd8a4af5215a17ce814520fc4155bbb554829` | `5270636b00003d56a250506b63001666` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.b` | 1670 | 865 | `-lh5-` | `000045B5` | `836efe527e9329cc91d100aa3a7e7822941d518bf5dc439b32b78edcbae573c3` | `00051b580dac190020d0000100e7edae` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.b2` | 32 | 32 | `-lh0-` | `000005B0` | `0e4046f6029ff3fac748a2a665f278ba7dc788992efab6b4ad0b2ab13741c9b9` | `028a03ca03c0029e021201a4012c0118` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.gas.p` | 104 | 85 | `-lh5-` | `00009C50` | `6b940a96ea34b51ca06ad6f77df0d6a2d9ac3888264f7c47b9455af29d1a34b2` | `434d4150499200000000009050404000` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.rear` | 8690 | 3641 | `-lh5-` | `0000EFAC` | `d66c35ad39ab2352a28f21d6a82020decfa0123e991f234b52ea5e5404235721` | `464f524d000021ea494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.rear.p` | 104 | 84 | `-lh5-` | `0000A95F` | `64efaa828251faee77b2be5df17d911d40650d2e6ba267c493f76c4261887670` | `434d415000f8b28c000000c070403000` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.sb` | 8750 | 3873 | `-lh5-` | `0000607D` | `53dad328be2efef6bbe9a92640465e029d111defcfc8a755b091c16de672c130` | `464f524d00002226494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.sideview.shp` | 8813 | 5863 | `-lh5-` | `000014BA` | `cb77f66e6205d2d7b00d26a1fc35401c378dc62eb154ae44f2223fc8798865c7` | `5270636b00005e4aee50506b63000363` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars2\cars\ross.st.p` | 104 | 86 | `-lh5-` | `00003808` | `8ee0d3d6e9fe137e578376512a79551b9bee0cd4f586080d77aa24801352a9ce` | `434d415049920000000000a050403000` |
| `TestDrive2&DataDisksHD\cars2\cars\rossdash` | 11876 | 7186 | `-lh5-` | `00007999` | `0353b700b32067730b63ed71ad13120915b8522b823a6e0fdc7c03af951546a5` | `464f524d00002e5c494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\rossdash.shp` | 17127 | 9489 | `-lh5-` | `000052B4` | `fd166d178298a3f777229b6ad992a4beb73e7bae71315729bcbfb75ae4b51352` | `5270636b00007d5e9650506b63001966` |
| `TestDrive2&DataDisksHD\cars2\cars\rossengine` | 1578 | 1401 | `-lh5-` | `000066A9` | `465e662297b6642a207869b9ac4b8b7d47ad7f80eb6d2759b2ee65d9abafa6ce` | `000006241eef0003020104f9000f0d1b` |
| `TestDrive2&DataDisksHD\cars2\cars\rosslogo.shp` | 1880 | 1143 | `-lh5-` | `0000E22D` | `0ecb2e6357815945f61e20d725946797e5033dd8df092520f1f7d553d5ddd9db` | `5270636b00000a34f250506b6300026c` |
| `TestDrive2&DataDisksHD\cars2\cars\rossroad.shp` | 14365 | 8016 | `-lh5-` | `0000302E` | `a883c9dedb3f4a9c483701937d5c36d66413c331f6ffae831d9e68db7f61444f` | `5270636b000040788050506b63002262` |
| `TestDrive2&DataDisksHD\cars2\cars\rossturbo` | 4346 | 4275 | `-lh5-` | `0000DFC0` | `5c3fee268292ede14ad660d7fd0df9e4ff548c792648b257623d7b46f70bbd89` | `000010f41eefe7f10d01e5ff23272f24` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.anim.shp` | 9769 | 3845 | `-lh5-` | `00007592` | `b79c4d21d2c1b848b8478eb7c8195833f86bb75a3347a46919769740e31e0e2c` | `5270636b00002e06a250506b63001666` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.b` | 1670 | 781 | `-lh5-` | `000046B4` | `bb368b5b56e540dd9060048c65454fbdd75561435c7d217676168c6fb9826f54` | `00051c840e1019c820d0000100e7edae` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.b2` | 32 | 32 | `-lh0-` | `00002CAD` | `2163e104fd82523313cdac91d8e91176896f98efb59ca8e436fb16918f67f1a4` | `03e804e2057803840320026e023a01c6` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.gas.p` | 104 | 84 | `-lh5-` | `00003617` | `fa0f33b78ce59ed36358470da79116a3439ad7ac3961006f5c7b1a6d984f6e89` | `434d4150499200000000009050400000` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.rear` | 11776 | 5677 | `-lh5-` | `00001902` | `9399f41788855b41153afb24e3ac9014cfbf42eb3ff3826909e175b3f7b92438` | `464f524d00002df8494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.rear.p` | 104 | 86 | `-lh5-` | `0000FCBC` | `01e3529d5be4d939ea91be9ff61a7d3f4edd491180d830cb8dbc62aaed3877c5` | `434d4150ee9a0000000000e0c0a06030` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.sb` | 8668 | 3677 | `-lh5-` | `0000D92A` | `a5e7c4e9a2b5cfb5db867b8cd67506614e65dcd64c681f90673314699af82d43` | `464f524d000021d4494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.sideview.shp` | 9502 | 6040 | `-lh5-` | `0000136E` | `a92904e49a6ede88cc91c07f2238f0101898336f2c5fee0ff4e81b5fb1cf776a` | `5270636b00006186ee50506b63000363` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars2\cars\ruf.st.p` | 104 | 84 | `-lh5-` | `0000DB90` | `23ed464d60bbe2a3c8d0d3f3559e4423447b8d66d97d6f29d80ee8295093d590` | `434d415049920000000000d060600000` |
| `TestDrive2&DataDisksHD\cars2\cars\rufdash` | 11642 | 7795 | `-lh5-` | `0000D8E2` | `0ae8b89c54d495e058804982c8052538e571b1e57baa3c5982f89c088c80272e` | `464f524d00002d72494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\rufdash.shp` | 17303 | 10699 | `-lh5-` | `0000DF69` | `f365d5adc67e5db6d7a9bd8b07c4f127be38ed6e5963c2d7421c8c060d19532e` | `5270636b00007c568250506b63001e34` |
| `TestDrive2&DataDisksHD\cars2\cars\rufengine` | 3042 | 2667 | `-lh5-` | `00003A87` | `256a5311e09b852ad95e7da70f5fd746931e76eb41a594a191f3b81c2d9bfae0` | `00000bdc1eeff0fce8e6e605100b0602` |
| `TestDrive2&DataDisksHD\cars2\cars\ruflogo.shp` | 2041 | 1389 | `-lh5-` | `0000D899` | `b0b6d027443e3a26ef6a0c49d1ed8ce2995502d471b9148ebdc708a791a7f186` | `5270636b0000099ef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars2\cars\rufroad.shp` | 14875 | 9470 | `-lh5-` | `00006410` | `e48d6b880b8451d6fa3b5baf007fdc0c9e95b218e40832bda98e31f4baa7e777` | `5270636b0000497e8050506b63002262` |
| `TestDrive2&DataDisksHD\cars2\cars\rufturbo` | 4494 | 4281 | `-lh5-` | `00003A83` | `084c92ad1aefc1f99dc5643dcae77ccad3c6e3abc7c797ee183a3272f1b49060` | `000011881eef4632ff2b0a112411eed1` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.anim.shp` | 13861 | 5213 | `-lh5-` | `0000768E` | `7ef11d93a04b89fe8ed814c4ffe36d4b833fc477444e82f8a70517d5cb327b43` | `5270636b00003cfa9e50506b63001766` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.b` | 1670 | 585 | `-lh5-` | `00005B68` | `2b58a19cd76b898da7eb263bfe157eb2f0c84fb2b63b6ce184d8d6ba9c6fa4c3` | `00061c840dac1a2c53d8000100f541f6` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.b2` | 32 | 32 | `-lh0-` | `0000876E` | `4be98e2478e050b1b91bdcf2dd7ea21123fce8197e960f9203376e74224e4612` | `03e805c8041a02e4023001ae017c010e` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.gas.p` | 104 | 87 | `-lh5-` | `00009030` | `42f9e25cacdcbfbdeac6180364e65e5cad79bb9b85a8cd314a63e0d61d23745d` | `434d4150ffd402020000009050404000` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.rear` | 10526 | 4613 | `-lh5-` | `000026EA` | `e1e5c3950d70d4e69fd6262500a113bca86ad2027d0603ec824ab9e8df84188f` | `464f524d00002916494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.rear.p` | 104 | 80 | `-lh5-` | `0000C6B4` | `fb53ba1281cea66230a74daf3dd6792ba088db93f4fa05edce4119e3f77599aa` | `434d415000f96198000000c070403000` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.sb` | 8718 | 3780 | `-lh5-` | `00005C0C` | `cfcf1a0197e88c81ca28cf1878ffb6cd82ebb986b9b5084850d57f331de8ec10` | `464f524d00002206494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.sideview.shp` | 8426 | 5338 | `-lh5-` | `0000109A` | `26753236d524ccabdc2826fb5356c046d823653f55d39994a72c4e61ed251134` | `5270636b00006248ee50506b63000363` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.ss` | 117 | 57 | `-lh5-` | `00000654` | `5913469ee218f354956808071259ddb0063930644a162b620b053e1a3903060d` | `1712776e643020776e643020776e6430` |
| `TestDrive2&DataDisksHD\cars2\cars\vett.st.p` | 104 | 85 | `-lh5-` | `000046AE` | `149f6e6334f3fd771fa592221606da05b826483f0dfdc97fe4d751b9ca089613` | `434d415049920000000000a050404000` |
| `TestDrive2&DataDisksHD\cars2\cars\vettdash` | 13470 | 7879 | `-lh5-` | `0000E17F` | `02a81c6c8c1db8b0626e2999be4f28b9610b643c97812cc50568f4b63cc9d587` | `464f524d00003496494c424d424d4844` |
| `TestDrive2&DataDisksHD\cars2\cars\vettdash.shp` | 17825 | 9201 | `-lh5-` | `0000BBAB` | `2a5cfc275eb32c73dde882dd931ca1631e8aab4405009daf5df5f1e6fd7e1ba6` | `5270636b0000839a8050506b63002364` |
| `TestDrive2&DataDisksHD\cars2\cars\vettengine` | 1578 | 1401 | `-lh5-` | `000066A9` | `465e662297b6642a207869b9ac4b8b7d47ad7f80eb6d2759b2ee65d9abafa6ce` | `000006241eef0003020104f9000f0d1b` |
| `TestDrive2&DataDisksHD\cars2\cars\vettlogo.shp` | 2081 | 1305 | `-lh5-` | `00000C13` | `1da26b76f97d06cdf29ab531f3f0b757f55968ab1031a842b3706555a7cc51a0` | `5270636b00000a3ef250506b6300026c` |
| `TestDrive2&DataDisksHD\cars2\cars\vettroad.shp` | 17244 | 9504 | `-lh5-` | `00002212` | `bfe403531ea11e3ea4f20ff840898a7cc6a8f4c616498d2f1c3deb4de72c24be` | `5270636b0000543a8050506b63002262` |
| `TestDrive2&DataDisksHD\cars2\cars\vettturbo` | 4494 | 4281 | `-lh5-` | `00003A83` | `084c92ad1aefc1f99dc5643dcae77ccad3c6e3abc7c797ee183a3272f1b49060` | `000011881eef4632ff2b0a112411eed1` |
| `TestDrive2&DataDisksHD\cars2\disktype.dat` | 1 | 1 | `-lh0-` | `0000C0C1` | `4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a` | `01` |
| `TestDrive2&DataDisksHD\disktype.dat` | 1 | 1 | `-lh0-` | `00000000` | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` | `00` |
| `TestDrive2&DataDisksHD\duel` | 108868 | 58924 | `-lh5-` | `0000C443` | `02711dab3d11a3d32e9d833c68564e62a5258cc0e9e5cb8299af57be00d3dd18` | `000003f3000000000000000400000000` |
| `TestDrive2&DataDisksHD\DuelHD` | 2232 | 1486 | `-lh5-` | `0000DF04` | `c1fe234d3dacd2dc0e07db37962db3dbc73e5e96ddc3d003a7279a76cb1c0491` | `000003f3000000000000000300000000` |
| `TestDrive2&DataDisksHD\pics\bluestat` | 5020 | 2975 | `-lh5-` | `000064D1` | `dff81bfb8111a1aacb20a5b443cae843b88dcbda7cdc62c0830d8bd90309285d` | `464f524d00001394494c424d424d4844` |
| `TestDrive2&DataDisksHD\pics\dsititle.shp` | 8373 | 4884 | `-lh5-` | `00001527` | `330711e42fbd48b8e9e176a8825f204c7ee6d1b72e258e462608700719137d5c` | `5270636b00003780ea50506b63000461` |
| `TestDrive2&DataDisksHD\pics\endgame.shp` | 15414 | 5928 | `-lh5-` | `000065FA` | `dd9b7bdd04d8a54260c3c5233a9908a9895eaa7001f7255068a67fefc87432c3` | `5270636b00005300ae50506b63001367` |
| `TestDrive2&DataDisksHD\pics\gamedifficulty` | 11104 | 3010 | `-lh5-` | `0000EBD7` | `db5a47571bb82dda7c9564e94ef796c78589f8a0dafc7380ed05d6042e8c0516` | `464f524d00002b58494c424d424d4844` |
| `TestDrive2&DataDisksHD\pics\gamedifficulty.shp` | 457 | 266 | `-lh5-` | `000014D6` | `734687b97e33d3cab1162517f10a1a6436bebe1303936e673a2ead21e58abf91` | `5270636b0000041ef650506b63000161` |
| `TestDrive2&DataDisksHD\pics\gameoptionscreen` | 23528 | 6896 | `-lh5-` | `00009649` | `63583a9a9f5b945cc3f7584416684af0e06603524a772e02c32048b8de159ebd` | `464f524d00005be0494c424d424d4844` |
| `TestDrive2&DataDisksHD\pics\gameover` | 10020 | 6875 | `-lh5-` | `0000E9C2` | `5dfd071ea597ed24b3903d3b02b1512af7e714cc0bd3a6c57a37efda1d5ce508` | `5270636b00002746e8464f524d000027` |
| `TestDrive2&DataDisksHD\pics\gameover.shp` | 1558 | 849 | `-lh5-` | `00007BC5` | `bfd772d923c1dfa7d6fd27a76a407d8917f0b54ed6e7934c255c3b8d2ee23ffa` | `5270636b000006e68a50506b63001c64` |
| `TestDrive2&DataDisksHD\pics\road.shp` | 59892 | 24611 | `-lh5-` | `0000B71B` | `caaeed727ae5dbb75cd41ac112cbbba796988cc4c72f4f26f14a62554f3bc99e` | `5270636b0001319c8050506b6300b962` |
| `TestDrive2&DataDisksHD\pics\testdrive.pal` | 238 | 186 | `-lh5-` | `0000B6E6` | `94957075b593e1315c5fa838c895c9a64369de371f36d68f418d7af53c28874d` | `464f524d000000e6494c424d424d4844` |
| `TestDrive2&DataDisksHD\pics\testdrive.shp` | 7219 | 4624 | `-lh5-` | `0000DB07` | `404181545bd3bb985ba39eb35a1e1fafc0a9f06733324d758729065d450047cb` | `5270636b000035c2f250506b63000254` |
| `TestDrive2&DataDisksHD\pics\title.shp` | 4954 | 3493 | `-lh5-` | `00006248` | `2285c21818d747b743691ad3507774fa5ebab5c14b78b1cb32e6fdc034fe2a4c` | `5270636b00001936f250506b63000264` |
| `TestDrive2&DataDisksHD\pics\title2` | 7910 | 2035 | `-lh5-` | `00007230` | `8e1157fbec73a9a118039567c25083066c60f6c8af9e04ba93072c916b90d75c` | `464f524d00001ede494c424d424d4844` |
| `TestDrive2&DataDisksHD\pics\titlecar.shp` | 52 | 42 | `-lh5-` | `00008018` | `b1e5721b633afb04b227b3115234e62d05a372cf1da1c28c062c5970b8a8a48d` | `00000030000162756c6c000000000006` |
| `TestDrive2&DataDisksHD\ReadMe` | 1526 | 831 | `-lh5-` | `000041BE` | `7b29d53f6102a31c22facb3ecaa92ea61943cee20cb4764179e4a97d3c301134` | `53686f72743a20484420496e7374616c` |
| `TestDrive2&DataDisksHD\ReadMe.info` | 2002 | 1318 | `-lh5-` | `00005A0F` | `8a1179811331e5ecad5715c0d99e0c2def334d4cc1cc2891e509f6787317fbfa` | `e3100001000000000016008700270023` |
| `TestDrive2&DataDisksHD\scen.dat0` | 34 | 34 | `-lh0-` | `00002670` | `397c2395b3b22117eae6c953756604c9bdadc1155e533d9050b6d492d8da1f77` | `00017363656e2f7363315f0000000000` |
| `TestDrive2&DataDisksHD\scen\sc1_desertmountain.shp` | 8402 | 4520 | `-lh5-` | `00004958` | `1d7fe6d55c4f1a6e1a9869052a55baebdc23f6d61adfaa495938c76b468668bb` | `5270636b000024c880000024c400354c` |
| `TestDrive2&DataDisksHD\scen\sc1_gameoption.shp` | 1313 | 830 | `-lh5-` | `0000C3D4` | `cba8cfbd27b95e281ffbd6ad2d5f10e0db45d6bf6fb98c5678bc243e5d601a26` | `5270636b000006f8f6000006f4000173` |
| `TestDrive2&DataDisksHD\scen\sc1_gasstation` | 24320 | 14339 | `-lh5-` | `0000C824` | `b22c9be2db483a90dccecb37a8f0308d64f7b8ef970dd6bbb34fbb6c8f0c036c` | `464f524d00005ef8494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen\sc1_gasstation.shp` | 7150 | 3959 | `-lh5-` | `00005949` | `5169850ef3e8e542f96cda987049957750966c6cd9378f865a67a75c70505c12` | `5270636b00002c52e650506b63000562` |
| `TestDrive2&DataDisksHD\scen\sc1_icon` | 21006 | 11409 | `-lh5-` | `0000EC08` | `e70b291f5b123e63f16419d391a0db33831d704513ae145cb40839b6988aa722` | `464f524d00005206494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen\sc1_mercedes.shp` | 11208 | 5964 | `-lh5-` | `00001AD3` | `b25973121e8bc621360f6985599104e5e656de35bc2a8c210779eac2f0c4a0a8` | `5270636b00003a9cba00003a98001066` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata0` | 402 | 337 | `-lh5-` | `000068C3` | `b86a28975994a60704ecb8a5261b54cf84d70352d5afeb0dda84ba54d13ea9f0` | `5270636b000006bad20006000100010b` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata1` | 504 | 429 | `-lh5-` | `0000B89A` | `00b5fa4fa13b86e29971f835b8654e77dcbe4226195bf0e001842f2009251bdb` | `5270636b00000923d20005000100010d` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata2` | 521 | 402 | `-lh5-` | `0000D2FA` | `b5fe507020d264d68ed002d45497a03674b80164b5614a49741cc15fe020d3d1` | `5270636b00000c58d20005000100010f` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata3` | 627 | 510 | `-lh5-` | `00007DC8` | `2aec7957daf15944315b3fc4635fe4d301b1c4de44b1be721d9154ab6c264a8d` | `5270636b00000bc0d200050001000111` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata4` | 646 | 477 | `-lh5-` | `0000F300` | `2fe03b07f0b903636b387b9501b2de1db9f12d969a924c77316f3c9b4e261910` | `5270636b00000c7cd200050001000113` |
| `TestDrive2&DataDisksHD\scen\sc1_roaddata5` | 695 | 518 | `-lh5-` | `0000E655` | `1a74c11ac849da13816bec6c780fe97f18ffc5c7f24a92bda3dbaffec9039f8b` | `5270636b00000d52d200050001000115` |
| `TestDrive2&DataDisksHD\scen\sc1_slicedata` | 460 | 210 | `-lh5-` | `0000EB87` | `cd4178248ec7ac2bf0f151c59c84912f2dabd4b06a3e9777aa92df36cbe03242` | `00000000000800000010000000200000` |
| `TestDrive2&DataDisksHD\scen\sc1_thunderbird.shp` | 12073 | 6680 | `-lh5-` | `000012B1` | `2fba2396450d63aeea4f36fec999b38ddfeec6c0cc7b04357ddd758d15ed64a5` | `5270636b00003d30ba00003d2c001066` |
| `TestDrive2&DataDisksHD\scen\sc1_treesmountain.shp` | 12120 | 8317 | `-lh5-` | `0000F5FA` | `e26ae3a356b0a27567a7fc79d0f14db0b468aab20edcc12358bd0a0afd3225fa` | `5270636b000041a480000041a0002f4c` |
| `TestDrive2&DataDisksHD\scen\sc1_van.shp` | 18071 | 8293 | `-lh5-` | `0000B661` | `dc8ce6e0ba08c69738c3b39e56a42c7e9977f6910e252254115fe3fb0691633b` | `5270636b000056c6ba000056c2001066` |
| `TestDrive2&DataDisksHD\scen\sc1_vectorfont` | 869 | 411 | `-lh5-` | `0000933C` | `8edd4d015ee6cf40e9d568bd678482c32f8b72f0488dd507326f8e985b2af0ba` | `5270636b000003e4fc56464e543ffff3` |
| `TestDrive2&DataDisksHD\scen\sc1_vectorsigns1` | 80 | 72 | `-lh5-` | `00001015` | `d997e2284a52573db4472e5acc0a15ea2fc79e294f8ec4185721b24a70daa94a` | `5270636b00000056ec00280056005600` |
| `TestDrive2&DataDisksHD\scen1\disktype.dat` | 1 | 1 | `-lh0-` | `0000C181` | `dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986` | `02` |
| `TestDrive2&DataDisksHD\scen1\scen.dat2` | 34 | 34 | `-lh0-` | `0000F314` | `7dd48090397e7e5049d2c769e59e4186a9eea09bfe5de3276390b1ad1ce132a3` | `00017363656e2f726f636b5f00000000` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_caldesert.shp` | 17495 | 10923 | `-lh5-` | `000077AC` | `82555ab203aecbc0609e6b16bda0dec67fd19b0f2d9171fb72f17e175e9a6e57` | `5270636b000060868050506b6300414c` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_frisco.shp` | 16602 | 9354 | `-lh5-` | `00004355` | `ef77a025f175a91d897d0d42a2826167de3c26549a1a26735d57b685ada69ac3` | `5270636b00005ad88050506b6300354c` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_gameoption.shp` | 1444 | 821 | `-lh5-` | `00003D0B` | `a09472d6f3a4636f3563904c760902c3d83a17179905525400c5e56e19c082fe` | `5270636b000006f8f650506b63000173` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_gasstation` | 24320 | 14339 | `-lh5-` | `0000C824` | `b22c9be2db483a90dccecb37a8f0308d64f7b8ef970dd6bbb34fbb6c8f0c036c` | `464f524d00005ef8494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_gasstation.shp` | 10289 | 5989 | `-lh5-` | `0000A6DF` | `c2390f6c2bd8b1aa8dbca5eaf2656923bd7ede4886d936c5f29d9b1f2ee08415` | `5270636b0000375ee250506b63000662` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_icon` | 17776 | 7266 | `-lh5-` | `0000CC50` | `74a34d497a5f51778fce7202a3d47469ee8c87a8d58015eecfcd4733d0c8b859` | `464f524d00004568494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_mercedes.shp` | 11208 | 5964 | `-lh5-` | `00001AD3` | `b25973121e8bc621360f6985599104e5e656de35bc2a8c210779eac2f0c4a0a8` | `5270636b00003a9cba00003a98001066` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_mystery.shp` | 17881 | 8459 | `-lh5-` | `0000D03D` | `6a8cc9a0381e23106da1d9d97ed1a2a5810fa635fb07694c373ad1ea48d84da8` | `5270636b0000565a8650506b63001d48` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_redwood.shp` | 16636 | 9168 | `-lh5-` | `0000A98F` | `889d871ea4872e40dff055c2d64095576482354f3f4a5af1756ddb06a8f6d817` | `5270636b00004f308050506b63003c4c` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata0` | 514 | 344 | `-lh5-` | `00009E5F` | `4964d9bbbdbff00c6171944b97f0bea14ae033744f01d4ebc963095bf0ce06d0` | `5270636b00000938d200070005000111` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata1` | 537 | 403 | `-lh5-` | `0000BB67` | `6f5afbf4d0786dc019110eee6b4c296128e9fe55b731791ccc896dbf359aa3b1` | `5270636b00000830b20007000500010b` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata2` | 720 | 418 | `-lh5-` | `0000F2C7` | `625922da6a7523e398cfe04f946dce5df46ca11d8c3cdc7d01cf83b5ae37f04b` | `5270636b00000a79d200070005000111` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata3` | 599 | 471 | `-lh5-` | `000037C3` | `49ef52ab89fc260490d71b42e2275ee4a8256976c3a02639e24891d2ea017589` | `5270636b00000b09aa0007000500010f` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata4` | 697 | 507 | `-lh5-` | `0000D764` | `915ef64b97f836c2ae52d8a2c0037ede88740c1d30fb022082fce5c8f3d720fa` | `5270636b00000d6c9a00070005000113` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata5` | 670 | 522 | `-lh5-` | `000024AB` | `51f780287e1fdf4f7f8b2ba4f376cbb4bd7039d07d352607cb20515a5811f27a` | `5270636b00000e6da200070005000113` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_roaddata6` | 585 | 431 | `-lh5-` | `0000CE10` | `a5f69d8ea7a1c1bbe7c07d0d0f39b7e43d1172931fd07594f9b1acf001cec775` | `5270636b00000a21c20007000500010f` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_slicedata` | 460 | 210 | `-lh5-` | `0000EB87` | `cd4178248ec7ac2bf0f151c59c84912f2dabd4b06a3e9777aa92df36cbe03242` | `00000000000800000010000000200000` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_southcal.shp` | 12829 | 8224 | `-lh5-` | `00000A46` | `b40a2019ebb66878c28ecf4aa358e9995f39adc207a96adb1c0b30b24a23bde9` | `5270636b00004d8e8650506b63001d4c` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_southcal1.shp` | 16173 | 8646 | `-lh5-` | `000043C6` | `fae1978c17e2b6c6a69dce7605084b04f1c6f395dcee494942c9354cf9a76511` | `5270636b000056028050506b63002248` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_thunderbird.shp` | 12073 | 6680 | `-lh5-` | `000012B1` | `2fba2396450d63aeea4f36fec999b38ddfeec6c0cc7b04357ddd758d15ed64a5` | `5270636b00003d30ba00003d2c001066` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_truck.shp` | 25874 | 16253 | `-lh5-` | `0000548E` | `7ac589cff82592591afa5bd51ff86838f927ff29910f965ea9fb3ee7c18279b3` | `5270636b000075b4ca50506b63000c66` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_van.shp` | 18071 | 8293 | `-lh5-` | `0000B661` | `dc8ce6e0ba08c69738c3b39e56a42c7e9977f6910e252254115fe3fb0691633b` | `5270636b000056c6ba000056c2001066` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorfont` | 876 | 415 | `-lh5-` | `0000A097` | `1bcb69f13d906ca4cb0ff68f9eb9f35f9a3e0f09ac5b45360a972e02c13d6b1b` | `5270636b000003e8fc56464e541bfffc` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns0` | 124 | 101 | `-lh5-` | `00006686` | `423ca2b02dbe6847ea7bde4375f6e83058f05ef19fe6f4e8b3e4c3a2221a459b` | `5270636b00000082ec00280052008200` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns1` | 113 | 98 | `-lh5-` | `0000D505` | `89a5ec5d37328cf49a8f42f68e9e016e4c71f42e2a42d134de52270d7e3ca293` | `5270636b00000078ec0028004e007800` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns2` | 252 | 122 | `-lh5-` | `0000400F` | `59dc4a5733420d217d7abd4ed0209d7ad00411f28797bda65f9b197ee16a1686` | `5270636b00000102ec0028004c007000` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns3` | 220 | 139 | `-lh5-` | `00004834` | `eeeeb7fda3da2744d80467c7e41aeb9ebd5234f1f876fc0f3b1d6737fe8c2249` | `5270636b000000e2ec00280048006600` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns4` | 277 | 183 | `-lh5-` | `00002BFF` | `9742e7cbad37fa482460278b0bd6bebf8d2f263584a1ebed9d3d241c30d1054b` | `5270636b0000011aec00280052007600` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns5` | 344 | 208 | `-lh5-` | `00000928` | `9c218dd27af56134dd28d949ccecd4b55b3c4cf3b29a7c453e670b31dab0baa1` | `5270636b0000015cec00280044005e00` |
| `TestDrive2&DataDisksHD\scen1\scen\rock_vectorsigns6` | 460 | 212 | `-lh5-` | `0000C443` | `c7f38b9e493cd07c7a4ebc5930a86c65e629f6dbf76d480e150c0c4b9551e198` | `002800440064008000a200c600e80108` |
| `TestDrive2&DataDisksHD\scen2\disktype.dat` | 1 | 1 | `-lh0-` | `0000C181` | `dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986` | `02` |
| `TestDrive2&DataDisksHD\scen2\scen.dat2` | 34 | 34 | `-lh0-` | `00002449` | `fb9f139f8207d2544d954454081dc721fd2610e9915075ec77a241eeb881d3ae` | `00017363656e2f6575726f5f00000000` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_gameoption` | 1846 | 193 | `-lh5-` | `000049FC` | `be26e849d8065d4795a9cb503047901ea803b377e6d0ad059e9daf2ae3cc9dde` | `00000736000170696373000000100000` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_gameoption.shp` | 1177 | 235 | `-lh5-` | `00002752` | `37447e5da776b1b18c97965823d81603aba7c98de995dbfc23a2c716ffb95b65` | `5270636b000006f8f650506b63000173` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_gasstation` | 24320 | 14339 | `-lh5-` | `0000C824` | `b22c9be2db483a90dccecb37a8f0308d64f7b8ef970dd6bbb34fbb6c8f0c036c` | `464f524d00005ef8494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_gasstation.shp` | 7909 | 4671 | `-lh5-` | `00004D37` | `d5b0c2734461411e041e232d8634b365d8064e537f33b23a118993beba111bd0` | `5270636b0000352ee250506b63000662` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_icon` | 14596 | 4474 | `-lh5-` | `0000F2DF` | `1de97f6fc0e7b3bd46323947d1dd41843dc79184a56c2211a4837d9e82d0c936` | `464f524d000038fc494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_mercedes.shp` | 20714 | 13538 | `-lh5-` | `000053A4` | `71fe8a79c10a957ac8f454968362ba3a6c075bf5b1d6309a2788de5d45806d6c` | `5270636b00005b3aba50506b63001066` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_redwood.shp` | 16636 | 9168 | `-lh5-` | `0000A98F` | `889d871ea4872e40dff055c2d64095576482354f3f4a5af1756ddb06a8f6d817` | `5270636b00004f308050506b63003c4c` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata0` | 578 | 448 | `-lh5-` | `0000B903` | `23c28ff4ef39686fe28df2069d712b1d6743a3e2e759c432adde6abb00c7bd97` | `5270636b00001275d200060001000111` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata1` | 506 | 419 | `-lh5-` | `00001FC3` | `ef6c2a6ec1717a08a1c560304e8ca25155f6fbac14ccea304412eff3e261933f` | `5270636b00000f3cd20006000100010b` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata2` | 911 | 524 | `-lh5-` | `0000FE18` | `509e770c3bfc27bdd3eb2f06f770b94643315a9aca95c698ed2ed795f0aa8b0f` | `5270636b00001316d200060001000111` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata3` | 689 | 495 | `-lh5-` | `0000CD0F` | `51502ebf6cd25dfc58f14e55c0c0eac941cd497c52acc635dc014d27dfa79be9` | `5270636b00001108d20006000100010f` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata4` | 437 | 376 | `-lh5-` | `000069F3` | `89b1224d62f677020d24b0a27133ff9729c6129bc1d7a6f08a56bdf873b938cf` | `5270636b00000b24ba00060001000113` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_roaddata5` | 657 | 509 | `-lh5-` | `0000737A` | `a1bd8b47aa517ab490ec8996c563ae987f3603e4da4d9f0a782546774d925f61` | `5270636b0000121cba00060001000113` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen0.shp` | 20784 | 15720 | `-lh5-` | `00005E49` | `5e54485cdd2e56d65eb71103edb6f5f510d7be979cbd6c2ff86d12089dd56f2a` | `5270636b00006030a650506b63001548` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen1.shp` | 15877 | 10879 | `-lh5-` | `00006A28` | `cabb9000518a00fa51489ec830b5db5c1288357171cd1d2aa5a60cebfc8621e9` | `5270636b00004b90ba50506b6300104c` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen2.shp` | 22391 | 13942 | `-lh5-` | `0000AE11` | `762840d2eefef604bfc53be66d96d410c576fda802e02d3bcf50bc8adb67ac6a` | `5270636b000080ae8050506b63002148` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen3.shp` | 19093 | 13556 | `-lh5-` | `0000DEDC` | `7e77f3db4e35fb6db0812979e3ff2ff228ba6c56acb3dbb0b5a86dcf2fcc47e2` | `5270636b00005ec8ba50506b6300104c` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen4.shp` | 8097 | 3870 | `-lh5-` | `0000C34A` | `dfa4710993b7d70080e610b1fadd2042601c8894468392046c8db729476a7902` | `5270636b00004570a650506b63001548` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_scen5.shp` | 19884 | 12546 | `-lh5-` | `00007B04` | `05124fffba85938d05dbcaed98072563a20fe95f7035290e7c5568bfd2a5a9ed` | `5270636b000069b28e50506b63001b48` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_slicedata` | 460 | 210 | `-lh5-` | `0000EB87` | `cd4178248ec7ac2bf0f151c59c84912f2dabd4b06a3e9777aa92df36cbe03242` | `00000000000800000010000000200000` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_thunderbird.shp` | 13979 | 7872 | `-lh5-` | `00002EEE` | `78feb477911f328a33b6ca0f9e441b53187921d6cb012e3a0a2a728c13db28e6` | `5270636b00004096ba50506b63001066` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_truck.shp` | 25874 | 16253 | `-lh5-` | `0000548E` | `7ac589cff82592591afa5bd51ff86838f927ff29910f965ea9fb3ee7c18279b3` | `5270636b000075b4ca50506b63000c66` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_van.shp` | 13252 | 7637 | `-lh5-` | `0000AC4E` | `def4522f19bc2a68567f0eced577749f7b436e178b421607baf614ca458c7699` | `5270636b00003afcba50506b63001066` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorfont` | 876 | 415 | `-lh5-` | `0000A097` | `1bcb69f13d906ca4cb0ff68f9eb9f35f9a3e0f09ac5b45360a972e02c13d6b1b` | `5270636b000003e8fc56464e541bfffc` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns0` | 116 | 70 | `-lh5-` | `0000670F` | `5b741300c22966dfc61555f254224f04e9c99fe1559d11a4254e37222ad1652c` | `0028004c007400740074007400740074` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns1` | 192 | 107 | `-lh5-` | `0000F55C` | `80e00361372ec98bf602d37e93eaf170be50faad7759eb8b7cc9ca81ad23a4ce` | `002800500076009c00c000c000c000c0` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns2` | 200 | 127 | `-lh5-` | `0000B042` | `f03e2875affd2bcecfa4f77c5fc285cfec625bd88bc982a05fe4342bb1e4ce9e` | `0028007800c800c800c800c800c800c8` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns3` | 114 | 73 | `-lh5-` | `00005295` | `843d3ebdabf62464cb8ab8f654370291f3789fd77e12a7a7fed26abdf796841e` | `00280048007200720072007200720072` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns4` | 156 | 78 | `-lh5-` | `00006A2C` | `231402a974d8946ffd351c058ede3f2280477a67e3c093492911365b24a0c210` | `0028004e0074009c009c009c009c009c` |
| `TestDrive2&DataDisksHD\scen2\scen\euro_vectorsigns5` | 248 | 135 | `-lh5-` | `0000335F` | `5f04488df4ebc83dbeca1e5dbeac5c5d00c5b8fe6b0a916d55121efc7e0fb4a8` | `00280050007000a000ce00f800f800f8` |
| `TestDrive2&DataDisksHD\scen3\disktype.dat` | 3 | 3 | `-lh0-` | `0000C0A1` | `070b13c004e9475fa155cd84d90de9f87db1b7dea6707329638a6ce66043d246` | `020000` |
| `TestDrive2&DataDisksHD\scen3\scen.dat2` | 34 | 34 | `-lh0-` | `00002449` | `fb9f139f8207d2544d954454081dc721fd2610e9915075ec77a241eeb881d3ae` | `00017363656e2f6575726f5f00000000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_againstcomputer.best2` | 270 | 25 | `-lh5-` | `00001639` | `7b5394e7ed7194efd328b7f3d92836c5a632e72f9ed38236bf8b7b758d8dec16` | `00005345000006e00049000006e00000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_gameoption` | 1846 | 193 | `-lh5-` | `000049FC` | `be26e849d8065d4795a9cb503047901ea803b377e6d0ad059e9daf2ae3cc9dde` | `00000736000170696373000000100000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_gameoption.info` | 1177 | 235 | `-lh5-` | `00002752` | `37447e5da776b1b18c97965823d81603aba7c98de995dbfc23a2c716ffb95b65` | `5270636b000006f8f650506b63000173` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_gasstation` | 24320 | 14339 | `-lh5-` | `0000C824` | `b22c9be2db483a90dccecb37a8f0308d64f7b8ef970dd6bbb34fbb6c8f0c036c` | `464f524d00005ef8494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_gasstation.shp` | 7150 | 3959 | `-lh5-` | `00005949` | `5169850ef3e8e542f96cda987049957750966c6cd9378f865a67a75c70505c12` | `5270636b00002c52e650506b63000562` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_HighScores2` | 266 | 40 | `-lh5-` | `000046EF` | `606b9c3faff37f0009b6573925696eae8df8632e4c68dbcf2d5eaf5365ebcb0f` | `0000568a0001636172732f7275660000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_icon` | 16108 | 8937 | `-lh5-` | `0000DD13` | `d5f7fa6d2bf3aa74b683071d6768a150865545c4628c813584501e7264c9874d` | `464f524d00003ee4494c424d424d4844` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_mercedes.shp` | 13979 | 7872 | `-lh5-` | `00002EEE` | `78feb477911f328a33b6ca0f9e441b53187921d6cb012e3a0a2a728c13db28e6` | `5270636b00004096ba50506b63001066` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_redwood.shp` | 12120 | 8317 | `-lh5-` | `0000F5FA` | `e26ae3a356b0a27567a7fc79d0f14db0b468aab20edcc12358bd0a0afd3225fa` | `5270636b000041a480000041a0002f4c` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata0` | 585 | 431 | `-lh5-` | `0000CE10` | `a5f69d8ea7a1c1bbe7c07d0d0f39b7e43d1172931fd07594f9b1acf001cec775` | `5270636b00000a21c20007000500010f` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata1` | 521 | 403 | `-lh5-` | `0000BAB0` | `3a39e7d32978d809f605e82874efedf19d4a4dd2ecf445424fd43e2b382653a9` | `5270636b00000c58d20005000100010f` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata2` | 689 | 495 | `-lh5-` | `0000CD0F` | `51502ebf6cd25dfc58f14e55c0c0eac941cd497c52acc635dc014d27dfa79be9` | `5270636b00001108d20006000100010f` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata3` | 720 | 418 | `-lh5-` | `0000F2C7` | `625922da6a7523e398cfe04f946dce5df46ca11d8c3cdc7d01cf83b5ae37f04b` | `5270636b00000a79d200070005000111` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata4` | 646 | 477 | `-lh5-` | `0000F300` | `2fe03b07f0b903636b387b9501b2de1db9f12d969a924c77316f3c9b4e261910` | `5270636b00000c7cd200050001000113` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata5` | 657 | 509 | `-lh5-` | `0000737A` | `a1bd8b47aa517ab490ec8996c563ae987f3603e4da4d9f0a782546774d925f61` | `5270636b0000121cba00060001000113` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_roaddata6` | 506 | 419 | `-lh5-` | `00001FC3` | `ef6c2a6ec1717a08a1c560304e8ca25155f6fbac14ccea304412eff3e261933f` | `5270636b00000f3cd20006000100010b` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_scen1.shp` | 22391 | 13942 | `-lh5-` | `0000AE11` | `762840d2eefef604bfc53be66d96d410c576fda802e02d3bcf50bc8adb67ac6a` | `5270636b000080ae8050506b63002148` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_scen2.shp` | 22391 | 13942 | `-lh5-` | `0000AE11` | `762840d2eefef604bfc53be66d96d410c576fda802e02d3bcf50bc8adb67ac6a` | `5270636b000080ae8050506b63002148` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_scen3.shp` | 15877 | 10879 | `-lh5-` | `00006A28` | `cabb9000518a00fa51489ec830b5db5c1288357171cd1d2aa5a60cebfc8621e9` | `5270636b00004b90ba50506b6300104c` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_scen5.shp` | 22391 | 13942 | `-lh5-` | `0000AE11` | `762840d2eefef604bfc53be66d96d410c576fda802e02d3bcf50bc8adb67ac6a` | `5270636b000080ae8050506b63002148` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_slicedata` | 460 | 210 | `-lh5-` | `0000EB87` | `cd4178248ec7ac2bf0f151c59c84912f2dabd4b06a3e9777aa92df36cbe03242` | `00000000000800000010000000200000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_southcal.shp` | 12120 | 8317 | `-lh5-` | `0000F5FA` | `e26ae3a356b0a27567a7fc79d0f14db0b468aab20edcc12358bd0a0afd3225fa` | `5270636b000041a480000041a0002f4c` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_thunderbird.shp` | 11208 | 5964 | `-lh5-` | `00001AD3` | `b25973121e8bc621360f6985599104e5e656de35bc2a8c210779eac2f0c4a0a8` | `5270636b00003a9cba00003a98001066` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_treesmountai1.shp` | 15877 | 10879 | `-lh5-` | `00006A28` | `cabb9000518a00fa51489ec830b5db5c1288357171cd1d2aa5a60cebfc8621e9` | `5270636b00004b90ba50506b6300104c` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_treesmountain.shp` | 22391 | 13942 | `-lh5-` | `0000AE11` | `762840d2eefef604bfc53be66d96d410c576fda802e02d3bcf50bc8adb67ac6a` | `5270636b000080ae8050506b63002148` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_truck.shp` | 13252 | 7637 | `-lh5-` | `0000AC4E` | `def4522f19bc2a68567f0eced577749f7b436e178b421607baf614ca458c7699` | `5270636b00003afcba50506b63001066` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_van.shp` | 18071 | 8293 | `-lh5-` | `0000B661` | `dc8ce6e0ba08c69738c3b39e56a42c7e9977f6910e252254115fe3fb0691633b` | `5270636b000056c6ba000056c2001066` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorfont` | 876 | 415 | `-lh5-` | `0000A097` | `1bcb69f13d906ca4cb0ff68f9eb9f35f9a3e0f09ac5b45360a972e02c13d6b1b` | `5270636b000003e8fc56464e541bfffc` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns0` | 460 | 208 | `-lh5-` | `0000A8DA` | `88d3a074a574ed48dd61f4e20227f4c975b6d99be514236ff88eb9fde194128a` | `002800440064008000a200c600e80108` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns1` | 124 | 97 | `-lh5-` | `0000B21D` | `6190f7bcb55762dd80fc17dc78ce09fa594a1c3b0000a15eef5ac956d8f716cd` | `5270636b00000082ec00280052008200` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns2` | 114 | 72 | `-lh5-` | `00005741` | `c0e7a3ca3a54e8ec0101751e030ee40a6af87c0d5ea4ed8799630688bf997bde` | `00280048007200720072007200720072` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns3` | 252 | 146 | `-lh5-` | `000008C9` | `ad9f16a72d8966e8821a923f6926dc5b43241e63b2ec1227b1ec7d5327db1ff0` | `5270636b00000102ec0028004c007000` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns4` | 277 | 183 | `-lh5-` | `00002BFF` | `9742e7cbad37fa482460278b0bd6bebf8d2f263584a1ebed9d3d241c30d1054b` | `5270636b0000011aec00280052007600` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns5` | 248 | 141 | `-lh5-` | `0000BBBD` | `02c68a8b74a30a0e924d7be835291b37a0d27e06f4c6acdaa795689afdd2cdfa` | `00280050007000a000ce00f800f800f8` |
| `TestDrive2&DataDisksHD\scen3\scen\euro_vectorsigns6` | 344 | 213 | `-lh5-` | `00002758` | `6506c01e90033c19c3cd1d04ef7671745ef92601150e87068051d3bed471c5b3` | `5270636b0000015cec00280044005e00` |
| `TestDrive2&DataDisksHD\select.dat0` | 150 | 94 | `-lh5-` | `0000A2A4` | `56ceb2da50af16b678909d67f7c907acc9e57050c2f0ec85e03678507fcef586` | `00000000000000000000000000000000` |
| `TestDrive2&DataDisksHD\sfx\accolade` | 22661 | 16605 | `-lh5-` | `00003444` | `51f74486a2c58f18aff17412d4d52c5c38c0362e8e001bec9c34a05b3c4cd76f` | `5270636b0000605cef464f524d000060` |
| `TestDrive2&DataDisksHD\sfx\Bump` | 346 | 346 | `-lh0-` | `00009897` | `554ce62c168482e59168231ac0d3aef46fe27e0a79b6d241317de237914f776a` | `0000015424b800fbfaeee8e5dad1cbc1` |
| `TestDrive2&DataDisksHD\sfx\crash` | 16096 | 14532 | `-lh5-` | `0000267D` | `756d68eb81f2f08c54049a84fdef8d62ca17ef13228758f6f445702279e90aa7` | `00003eda14ce0b0602fffafe0100fdf3` |
| `TestDrive2&DataDisksHD\sfx\gameover` | 12916 | 10712 | `-lh5-` | `0000D9C6` | `f63bce28fc705f9fa2c18af3e12b3bc40161a89414af89a3f10a0e1895372390` | `464f524d0000326c3853565856484452` |
| `TestDrive2&DataDisksHD\sfx\radar` | 3360 | 3150 | `-lh5-` | `00006722` | `b1a145ea65a9b9ba11ac402ef4ce4b0d4af44e5f34c00051e1ae061f1085b4dc` | `00000d1a4e20010101020501f0f81518` |
| `TestDrive2&DataDisksHD\sfx\shortcrash` | 5150 | 4757 | `-lh5-` | `0000E78D` | `859d7f3df4278e1d09509efc2cadbd3ebd13661fa5be752fb86e14fb7f419cfb` | `0000141814ce2c2211f8f8020e141504` |
| `TestDrive2&DataDisksHD\sfx\siren` | 30 | 24 | `-lh5-` | `0000070C` | `73a25aace0a691d45caf332345f015caf67cacbee84c2eec195ba8790a3ea812` | `000000181c2200407f4000c080c00040` |
| `TestDrive2&DataDisksHD\sfx\song` | 26852 | 20732 | `-lh5-` | `00008EDD` | `1360eb722fe6c1d7efc76d6c427150063ce63e77e134d1136ab7c733cd6cfc5d` | `000003f3000000000000000300000000` |
| `TestDrive2&DataDisksHD\sfx\Squeal` | 910 | 900 | `-lh5-` | `0000B9CD` | `accdafdc9cd3503ddf6c8f2f13c20522deb45f300f0c3d14ab8947d6011bf04c` | `000003882710fc08151b1302e7e0ec05` |
| `TestDrive2&DataDisksHD\sfx\starter` | 25932 | 20612 | `-lh5-` | `0000B6E9` | `a75145dfcb9a5e4a37fd167c0b5d607216616363885eb8dcd0a4512a958a9ba8` | `464f524d000065443853565856484452` |
| `TestDrive2&DataDisksHD\sfx\test_drive_ii` | 15523 | 11844 | `-lh5-` | `0000E75A` | `0f999d15140b54c55e5a26805057c2f3bccac8ac9527762329912c24b3d7e293` | `5270636b0000405cef464f524d000040` |
| `TestDrive2&DataDisksHD\sfx\the_duel` | 10059 | 8011 | `-lh5-` | `00002EFE` | `cda17ddc37dd5dd7692b8f7b70df21beeb86dcbad0cb184c1a075c84b5440196` | `5270636b00002b96ef464f524d00002b` |
| `TestDrive2&DataDisksHD\TestDrive2&DataDisksHD` | 513 | 216 | `-lh5-` | `00008611` | `e3148b771b822f5f28b32a7f89dec695c6720228129a359c6e4d76fdd67344ab` | `3b20637265617465732061737369676e` |
| `TestDrive2&DataDisksHD\TestDrive2&DataDisksHD.info` | 8667 | 4257 | `-lh5-` | `0000E918` | `e18b7e0bff936e49f6dafe09e91e36337628b1f173743e25c5b422f913a8fa49` | `e310000100000000000c001b00080008` |
