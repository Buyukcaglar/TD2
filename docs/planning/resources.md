# Test Drive II resource findings and decoding plan

Inspection date: 13 October 2026. The raw reference manifest records path, size, SHA256 and first 32 bytes for every source file. The resource observations record every graphics pair, catalog text, duplicate group and small-file observation. File names and byte prefixes below are observations; consumer behavior and schema meanings remain future recovery work.

## 22 October 2026: candidate schemas and decoder reuse

The [complete upstream formats/tools review](kylofon-formats-tools-review.md) provides specific schema/decoder candidates for packed wrappers, both codecs, archives/sprites, car records, ordered `.SS` labels, routes/traffic/signs/fonts, selection/scores and PC Speaker events. Use these candidates to replace open-ended rediscovery with consumer-based admission and corpus checks in P2-01..P2-09. Earlier observations below remain the historical supplied-file snapshot; upstream names and prose do not establish accepted local format meanings.

Prioritize both PCS prefix families, sprite count/mode discrepancies, CAMA's extra 49 bytes, short DAT copies and heap-tail lifetime, missing SGN companions, ordered repeated `.SS` labels, VOICES adjacency and every executable-embedded media span. Our existing raw loader/codec comparisons and upstream Python tools are not receipts for decoding every supplied resource. Preserve the249-DOS-file closure gate, bounded parsing, original-read-only policy and external resource packaging rules. The [gap register](evidence/kylofon-gap-register-v1.json) gives acceptance conditions.

## DOS inventory

| Family | Files | Bytes | Investigation |
| --- | ---: | ---: | --- |
| `.EXE` | 4 | 323,446 | Packed EGA/CGA/Tandy programs, launcher, embedded resources |
| `.PCS` | 82 | 539,656 | Probable CGA presentation family, prove from loader paths |
| `.PES` | 82 | 716,336 | Probable EGA presentation family, prove from loader paths |
| `.BIN` | 26 | 11,217 | Twelve car files, twelve `O` companions, songs and voices |
| `.SS` | 12 | 836 | Car-associated text metadata; semantics unproven |
| `.DAT` | 26 | 16,221 | Catalogs, selections, disk ID, route data and high scores |
| `.FNT` | 3 | 2,410 | Scenery-associated fonts or glyph definitions, prove format |
| `.SGN` | 14 | 3,311 | Scenery-associated sign records with readable text |
| **DOS total** | **249** | **1,613,433** | Every file requires a final disposition |
| Amiga `.lha` | 1 | 1,412,072 | 352 installed-file members; see Amiga report and inventory |

## Catalog and content observations

`CARS.DAT` is DOS-style text ending with byte `1A`. It supplies these identifiers and names, rather than an inferred vehicle list:

| ID | Catalog name |
| --- | --- |
| F40 | Ferrari F40 |
| P959 | Porsche 959 |
| CAMA | Camaro ZL-1 |
| DODG | Dodge Charger |
| GOAT | Pontiac GTO |
| GT50 | Mustang GT500 |
| STNG | Corvette Stingray |
| VETT | Chevy Corvette ZR1 |
| ROSS | Ferrari Testarossa |
| COUN | Lambo Countach |
| LOTU | Lotus Turbo Esprit |
| RUF | Ruf Twin Turbo |

`SCENES.DAT` supplies `CCC Calif_Challenge 7`, `ec_ European_Challenge 6`, and `TDS2 Master_Scenery 6`. Corresponding numbered DAT files are present for all 19 listed sections. Case differs between catalog text and file names; preserve this in the lookup specification and reject ambiguous matches.

`SELECT.DAT` contains `0 0 0 RUF P959 TDS2`. The meanings and write behavior of the three numbers are unproven. Three `*HISC.DAT` files are each 340 bytes and have different contents; treat them as supplied mutable-state evidence, not uniformly pristine defaults. `DISKID.DAT` is nine bytes with no established encoding.

The Amiga archive contains base scenery plus `scen1`, `scen2` and `scen3`. The user confirms the extra scenery is **Northern Germany Challenge**. The fourth tree is a local candidate, with seven numbered road records against six in `scen2`; byte-identical scenery catalogs and reused `euro_` names make filename-only identification unsafe. The final game must load Northern Germany Challenge when its complete necessary user supplied data validates. See the Amiga report for all namespace and member evidence.

## Graphics and shared compression investigation

All 82 PCS stems have PES companions and all 82 PES stems have PCS companions. Pairing establishes corresponding names, not equivalent geometry or one shared codec. PCS files divide into 72 starting with `82` and ten starting with `01`; all 82 PES files start with `82`. The ten alternate-prefix PCS members are `EC_0` through `EC_5` and `EC_CAR1`, `EC_CAR2`, `EC_CAR3`, `EC_ICON`. Numbered route DAT files also begin with `82`.

These observations suggest a shared compressed wrapper and possibly an alternate encoding, but no compression algorithm or length-field meaning is established. Do not interpret the first words as width/height or import a common codec until executable consumers prove the layout.

| Example | PCS bytes | PES bytes | Reason to inspect |
| --- | ---: | ---: | --- |
| ACCOLADE | 823 | 1,412 | Small title asset pair and short headers |
| TESTDRV2 | 3,250 | 3,514 | Both start `82 A2 2A 00`, subsequent data differs |
| ROAD | 7,079 | 7,933 | Shared gameplay presentation and ordering |
| F40DASH | 7,613 | 12,845 | Car-specific dashboard masks and metrics |
| EC_0 | 27,691 | 33,020 | PCS prefix `01`, PES prefix `82`; alternate path |
| GAMEOPT | 2,067 | 3,309 | Menu/interaction alignment |

Future decoding sequence:

1. Locate the open/extension-selection path for each executable profile.
2. Identify wrapper dispatch, nested codecs, allocation sizes and exact consumed ranges.
3. Decode the smallest representative member of each proven family using a bounded reader.
4. Recover sprite/image framing, palette sources, masks, pivots, dimensions and drawing commands from consumers.
5. Compare resulting indexed pixels and masks to the original renderer at controlled checkpoints.
6. Extend to every pair and exceptional member, recording truncation, trailing bytes and unsupported variants explicitly.

Some identical files have different names: the first two `CCCCAR` PCS/PES pairs equal their `TDS2CAR` counterparts, and `CCCCAR3.PCS` equals `TDS2CAR3.PCS`; its PES counterpart is not listed as identical. Aliasing must follow verified hashes, not similar names. Keep separate logical IDs even when storage can be shared.

## Car records and animation metadata

Eleven main car `.BIN` files are 847 bytes; `CAMA.BIN` is 896 bytes. Every `*O.BIN` is 32 bytes. Numeric sequences in those files look structured but their units, signedness, field lengths and purpose remain open. Recover field usage from the C translation before labeling a sequence a torque curve, gear table or opponent speed profile.

Each `.SS` begins with three ASCII numbers and concatenated four-character `wnd`/`fac` labels, ending in CR LF and `1A`. In these files the first number equals the total label count. `F40.SS` and `LOTU.SS` have ten `wnd` and six `fac` labels. The second and third values vary; no angles, delays or frame meanings have been established. Some ordered labels repeat, so a set-based parser would lose information.

Future schemas must connect these files to their dashboard/rear/road/stat resources, preserve label order, and explain every exceptional length. Validate both rendering changes and vehicle behavior independently.

## Routes signs and fonts

There are seven `CCC`, six `EC_` and six `TDS2` numbered DAT files. SGN companions exist for all seven CCC and six EC_ sections, but only `TDS20.SGN` exists for master scenery. Investigate shared, embedded, optional or absent sign sources; this inventory alone does not prove the remaining five files are missing.

SGN files begin with a sequence of little-endian-looking offsets and contain readable sign text; `CCC0.SGN` includes `WELCOME TO` and `CALIFORNIA`. Validate the offset table, zero entries, record layout, text control bytes, coordinates and glyph references through actual consumers.

`CCC.FNT` and `EC_.FNT` are byte-identical at 1,012 bytes; `TDS2.FNT` is 386 bytes. Fonts may combine offsets and vector/bitmap data; format and glyph coverage are unproven. Do not replace them with a modern font in a fidelity mode.

The normalized native route representation must preserve original distance/coordinate units, order of events, section links, objects/signs, road geometry, collision-relevant placement and progression. Northern Germany Challenge needs the same contract when imported from Amiga data, even if its source framing differs.

## Audio resources

`SONGS.BIN` is 618 bytes and begins with offset-like words and repeated numeric patterns. This is not enough to identify a sequencer format. `VOICES.BIN` is exactly two bytes, `0D 0A`, so it is not a substantive standalone sound bank. Effects, waveform patterns or sequencer tables may be embedded elsewhere; trace their consumers and device paths.

The DOS audio target is PC Speaker music and effects. Recover its reachable code, resources, speaker/PIT behavior, effects priority and timing; validate the sequencer event stream separately from final audio output.

The Amiga archive has Hunk, IFF and custom audio candidates. In particular `sfx/song` is a Hunk load-file candidate and must enter the executable-format investigation queue. Enumerate its HUNK_CODE/HUNK_DATA sections and actual entry/consumer before classifying replay code; its signature alone does not prove code-bearing content. Decoding samples alone will not recover music timing or channel behavior.

## Format documentation and closure

Each future format specification must include input edition/hash, consumer function IDs, byte layout, endianness, units, cross-file IDs, compression details, maximum bounds, validation rules, trailing/unknown bytes and evidence confidence. Record the assets embedded in executables with extraction locators and transformation provenance too.

Maintain a row for every supplied file/member: identity, role, consumer, schema, decoder status, corpus validation, original comparison and final packaging policy. Explained metadata/placeholders/unused duplicates count as understood only with evidence; undecoded game payload remains open. Loaders should tolerate legitimate admitted variants while rejecting corrupt lengths and incomplete mandatory sets without partial state updates.
