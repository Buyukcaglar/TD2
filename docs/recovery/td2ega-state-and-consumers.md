# EGA state ownership and raw resource consumers

2026-10-13, P1-05 in progress. This report records reviewed instruction observations and open contracts. It does not close the complete state machine or resource-consumer gate.

The initial-image [control map](evidence/td2ega-control-map-v41.json) has 439 registered candidates, 44 explicit indirect sites plusone saved-near return in the separate mutable-state review, and 28 open bounds/writer obligations. Its 92,274 syntactic code bytes leave 4,222 unclassified prefix bytes and 33,744 principal initialized-data candidate bytes. [Verification](evidence/td2ega-control-map-verification-v5.json) checks mapping identities, ten table sets and eight unique byte-ring call sites. Every candidate still needs its own semantic disposition before P1-11.

## Top-level ownership

Startup `13A8:03F8` creates the principal near-data/stack group and calls `0000:07B3`. Main initializes graphics, callback input, vector services, raw audio pointers and a graphics object; discovers/chooses media paths; reads selection/catalog state; then repeatedly calls `00C0:039C` and `019E:06C5`. The latter reaches `0267:15E4`, which loads selected resources and calls `06C9:1B2C` at `0267:1C32`. Semantic names for every submenu/session transition are not yet admitted.

Main's exit branch at `0BE4` calls `610A` (guarded vector 08/PIT/speaker cleanup), `68C4` (vectors 09/16 restoration), then the selected graphics cleanup path and RETF. The escaped-key branch at `0AC1` leads to a confirmation loop; `0BC9/0BCF` compare y/Y before the selection-write path at `0BDC`. These are static control edges, not observed interactive sessions.

The timer installer `06C9:6059` eventually writes vector 08 to `06C9:61BF`. That handler saves general/segment registers, establishes group DS, updates counters, conditionally invokes the saved old vector through `6230`, and walks a registered far-callback array at group `5F12`. Main registers `06C9:75EA`; other admitted setters register `0143:019E`, `06C9:6269` and `06C9:403B`. The last updates simulation fields and state. Application return values alone therefore do not account for all state writes.

No timer frequency is assigned here. The installer writes the passed divisor to port 40h and computes a signed division of 65536 by that argument for a down-counter. Raw divisor, signed-division preconditions, interrupt masking, saved-vector behavior, callback lifetimes and event order belong to P1-07. This verified callback path is distinct from the physical086C readers.

## Main dispatch byte

`06C9:1B2C` repeatedly calls its drawing/update helpers, reads signed byte DS:`5490`, loops when zero, exits the dispatch path when negative, and otherwise jumps through DS:`2302 + 2*value`. The first ten entries correspond to values 0..9, though zero is locally handled before dispatch. Observed direct writers now include values 0..9 and FFh. Initialization/reset sites write zero; simulation paths write 1..9; several termination paths write FFh.

| Dispatch value | Target | Visible action |
| --- | --- | --- |
| 0 | `1BAC` table entry, locally bypassed | Normal loop while zero; exit work is also reached through other branches |
| 1 | `1C51` | Calls `374F`, then exit work |
| 2 | `1C02` | Calls `3532`, then shared counter/continuation logic |
| 3 | `1C23` | Calls `3643`, then shared continuation |
| 4 | `1C2A` | Increments DS:`8658`, calls `36E0`, then shared continuation |
| 5 | `1C35` | Calls `371F`, then shared continuation |
| 6 | `1C3C` | Calls `372B`, then shared continuation |
| 7 | `1C43` | Calls `3737`, then shared continuation |
| 8 | `1C4A` | Calls `3743`, then shared continuation |
| 9 | `1C59` | Calls `3713`, then shared continuation |

The shared logic decrements DS:`8424`, either enters reset work at `1C60` or continues according to states 4/9 and the outer loop. State labels such as crash, repair, refueling or finish still require their parameter/resource/condition evidence. This table deliberately does not invent those labels. There is no local positive upper-bound guard at `1BA8`; all direct/indexed writers, reset copies and aliases must establish the supported domain before closure.

The **initial-image CLC tail** has an additional anomaly: after loading/sign-extending the state byte at `1BF0`, it restores SI/DS/BP, clears carry, overwrites AX with2, sets ES=2 and writes word2 to physical0086h, then RETFs. [Twelve isolated initial-tail cases](evidence/td2ega-state-return-tail-validation-v2.json) verify that byte state and absence of relocation. A later [main-called mutator review](td2ega-mutable-platform.md) proves that13A8:002E can instead write RETF at1BF7, bypassing those instructions. [2,048 mode-specific epilogue cases](evidence/td2ega-state-tail-modes-v1.json) confirm that the RETF mode returns the sign-extended state and preserves incoming ES/CF, while the CLC mode retains the low-memory write. The caller stores AX at0267:1C37. Preserve the active code-state context; neither return interpretation is unconditional. Physical0086h remains distinct from the086Ch reader.

## Raw resource interfaces

The [consumer inventory](evidence/td2ega-resource-consumer-map-v39.json) covers all 249 DOS file identities, 47 raw/control interface entries, 44 lexical filename candidates and 20 immediate literal-argument candidates. Lexical matches are not final consumer admission; unbound dynamic/catalog/embedded consumers remain explicit. In particular the lexical `h.PES` match is not an admitted filename: the actually referenced extension strings are `.PES` and `.ESH`.

The [ownership review](evidence/td2ega-ownership-review-v2.json) records eight scoped resource families, 26 direct state-byte writes and initial byte-source provenance. The [resource registry](resources.json) assigns stable IDs to 249 file identities and the external 258-byte initialized byte-source span. Family consumer IDs are candidates; formats and perfile behavioral gates remain pending. An inconsistent consumer-image hash was explicitly rejected before writing an ownership result.

| Interface | Reviewed raw boundary |
| --- | --- |
| `0000:0297` | Near filename, media selector, operation selector; checks cache/media paths and builds the resolved near filename at group `8644`. Returns status, not a FILE pointer. Stack-local strings require DS=SS on this path. |
| `13A8:0A6E` | Near filename and near mode string; obtains a runtime stream slot and calls `0E20`; returns AX near stream pointer/handle or zero. The runtime stream ABI is distinct from AX:DX far resource storage. |
| `06C9:5E1C` | Opens a near filename, seeks to end/start, closes, rounds byte length to paragraphs and returns the low 16-bit paragraph result in AX. Width/truncation must be preserved. |
| `06C9:5E8A` | Reads exactly four header bytes; forms a 24-bit quantity from bytes 1..3, rounds to paragraphs, returns AX. This is a consumer observation; no whole-file schema or codec is admitted. |
| `06C9:6AA2` | Near filename plus offset/segment destination; DOS open/read/close, 4000h-byte chunks, destination segment advances by0400h after each full read. Returns the original offset in AX and segment in DX, restores DS on success. Error transfers to the original fatal-report path. |
| `06C9:6D18` | Named cache lookup, paragraph allocation, raw read. Returns AX:DX far storage, with the cache/allocator's descriptor ownership effects. |
| `06C9:6D50` | Named cache lookup or allocation/raw read; wrapper/pass-count handling, selector dispatch through CS:`6E2E` to `6B02` or `7C16`, and subsequent buffer bookkeeping. Full codec algorithms/bounds remain open. |
| `06C9:71B4` / `70A3` | Search/transfer/allocation bookkeeping over 18-byte named descriptors. Entries contain name bytes, paragraph-size/segment fields and status words. `71B4` may move a cached resource and change descriptor ownership; it is not a pure lookup. |
| `1748:000E` | Near graphics name. Dotless names try extension table `.PES`, `.ESH`, null terminator at DS:`68A4`; cached and filesystem paths differ. `.PES` takes packed loader `6D50`, conversion `C838` and temporary allocation release `7490`; other selected extensions take raw loader `6D18`. Returned storage stays opaque here. |

Main loads `voices.bin` at `083B`, stores its pair at group `942A/942C`, and passes it to `75C8`, which stores segment/offset at `65F7/65F9`. It loads `songs.bin` at `084E`, stores `8640/8642`, and passes it with selector1 to `758A`. That consumer, guarded by group `5EFB == 3`, reads a four-byte pair at `base + 4*selector`, stores active/restart offsets at `65ED/65EF/65F1/65F3`, stores the source segment at `65F5`, and sets sequencing flags under CLI/STI. Timer callback `75EA` subsequently reads those sources and writes PIT/speaker ports. This establishes an audio data path, not audio output or complete sequencer semantics. The two-byte supplied VOICES.BIN remains an exception requiring bounds/path explanation.

## Filename producers and write custody

Reviewed builders include selected-car `.bin` at `0267:189F..18DA`, opponent `o.bin` at `195F..199F`, selected-route section `.dat` at `1A03` onward, route `.sgn` at `1B7C` onward and `.fnt` at `1BE8..1C23`. `.ss` builders occur in `0143:00C2`, `0143:01F4` and `019E:0BAC`. These link resource families to instruction sites; full catalog-to-file coverage and raw record bounds are still pending.

Catalog/selection literals pass through `0000:0297` from `0432:00BA` (cars), `01C3` (scenes), `02CF` (selection read) and `038D/03A5` (selection write path). `0645:000F` and `0221` combine the selected route name with the high-score suffix. The high-score path contains the literal length154h (340 bytes); field interpretation and persistence acceptance remain later work.

The media/configuration code also constructs nine 13-byte graphics names beginning at DS:`03E4` and other executable-resident name tables. Both PCS and PES literals occur in EGA's supplied image; this is EGA code evidence, not CGA recovery. Presentation text, graphics tables, initial byte-ring data and other original embedded media remain external to distributed source.

P1-05 remains open for the complete state/ownership model, every dynamic/cached/embedded consumer, all write paths, resource alias/lifetime bounds and the byte source's reset/scheduling contract. No full resource decoding, CGA work, DOS session, native Windows gameplay, rendering/audio output or gameplay/fidelity acceptance has been performed.

Additional bounded consumer/state contracts are documented in [rawloader](td2ega-raw-load.md), [file/headerparagraphhelpers](td2ega-file-paragraphs.md), [audio metadata](td2ega-audio-metadata.md) and [near primitives](td2ega-sim-primitives.md). These preserve errorcarry/count/partialstate differences andconditionalSS assumptions; they do notclose allcaller lifetimes orcomplete P1-05.

[Timercontrol/callertail review](td2ega-timer-control.md) confirms3FD9setup registers6269/403B after601C;1BEBcalls601C andclearsthefirstcallbackpair beforeeitherreturntail. Laterstale callbackrows do notimplylivecallbackownership becausefirstsegment0terminatesthewalk. Actualsessionguards/movingresourceexclusion remainopen.
