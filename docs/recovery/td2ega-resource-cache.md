# EGA raw resource storage, names and ABI

2026-10-13. P1-05 raw ownership review, using the admitted unrelocated image. All addresses below are module-relative. These are instruction contracts and scoped ABI observations; no real resource codec or DOS game session was executed.

The principal group contains 50 eighteen-byte descriptors from `68E2` through `6C54`, including two sentinels and **48 usable slots**. Initial pointer words are `6C66=6C68=68E2` and `6C6A=6C6C=6C54`. The first sentinel initially has paragraph size0, segment0, status2; the last has size0, segment0, status1. `6F1E` supplies the actual pool segment bounds after DOS allocation/resize and clears interior statuses. Those OS success/failure conditions remain platform contracts.

| Descriptor offset | Observed field |
| --- | --- |
| `00..0B` | Twelve name bytes, copied from basename storage |
| `0C..0D` | Paragraph size, little endian |
| `0E..0F` | Segment start, little endian |
| `10..11` | Status word: observed writes0 (free),1 (cached),2 (active); compactor tests bit0 |

The segment-oriented storage is separate from the near descriptor array. Resource offset zero is a valid allocation address. A C representation must not turn every AX=0 result into host NULL.

## Name and storage operations

`7083` returns a near basename pointer after the last colon or backslash. It does not case-fold the name. `71B4` and `7273` compare name bytes directly for up to twelve bytes; a dot or null in the stored name can terminate a match when the requested basename ends. Case-insensitive filesystem lookup and this byte-sensitive cache identity must remain distinct.

`70A3` appends an active descriptor, copies twelve name bytes, writes paragraph size/segment/status2, and evicts or advances cached descriptor ownership when necessary. Its [bounded C allocation prefix](td2ega-cache-allocate.md) passed73,654 isolated comparisons, including partial mutations before failure. Space/descriptor failure reaches the original fatal path; external cleanup remains open. Do not replace this with an unbounded allocator without a later behavior decision.

`7273` is an existence/status query: success returns AX=1 with incoming DX unchanged; failure returns AX=DX=0. A status0 descriptor aborts the search, and the end sentinel is checked once only when start=end. It does not return the cached resource pointer and does not perform the transfer done by `71B4`. Its [bounded C query contract](td2ega-cache-query.md) has passed 1,258 isolated comparisons.

`71B4` acquires a matching cached block into the active side. It clears the old status, writes an active descriptor with status2 and a new segment, copies the payload through `6FE8`, adjusts/evicts overlapping cache records, compacts through `7147`, and returns AX=0 with DX selecting the acquired block. It is a moving, mutating operation; an old cached pointer is not a stable ownership token.

`7147` scans cached descriptors backward. It accumulates sizes of noncached holes, shifts retained descriptors, copies names/size/segment/status and moves payloads through `7030`. It finally updates the cached-boundary pointer at `6C6A`.

`72C6` finds an active descriptor by the supplied far pointer's **segment** (the offset is not the search key), marks it free, and conditionally transfers it into the cache with status1 and a moved payload. It can return the original offset in AX and the new cached segment in DX; the fallback sets the argument copy of the returned segment to zero. It trims the active top over free descriptors.

`736B` has a different release/compaction policy. It can shift existing cached descriptors and data to preserve the released block in cache, but sets its returned segment argument to zero and never replaces that zero with the cached segment. Its return is AX=original offset, DX=0. It must not be collapsed into `72C6` merely because both can cache a block.

`7490` discards an active allocation by marking status0 and trimming the active top if needed; it does not move payloads into cache. It searches by segment, even in free interior rows, and uses a separate fatal path on an unknown allocation. Its [bounded C discard prefix](td2ega-cache-discard.md) passed 69,209 isolated comparisons.

`6FE8` copies paragraph-sized storage forward in chunks of up to1000h paragraphs (8000h words), advancing source/destination segments. `7030` copies backward, beginning at the end of the paragraph span, using STD and restoring DF=0 before return. Preserve their direction/overlap preconditions, 16-bit truncation at64KiB, DS restoration and ES clobber rather than assuming a universal memcpy contract.

## Packed-loader stack convention

`6D50` has a cache-hit early-return path and an uncached decode path. The latter pushes three words before the far call to `6AA2` at `6DA8`, then executes **ADD SP,8** at `6DAD`. `6AA2` returns with ordinary RETF and no argument cleanup. The subsequent saved-register pops are therefore shifted by one word.

[Sixteen scoped ABI cases](evidence/td2ega-packed-loader-abi-v2.json), at two load segments with two stack fills, execute only the `6D50` body while stubbing the named helper calls with ordinary far returns. They cover cache hit, both dispatch targets, and a synthetic two-pass path. Cache hit restores SI/DI; uncached cleanup puts the incoming SI into DI and the BP-0Ah local word into SI. BP, SP and the far-return target remain restored. In the one-pass fixture the local word retains its initial stack fill; in the two-pass fixture it contains the derived source segment.

The codec AX/DX values in these cases are **synthetic mock outputs**, not admitted codec postconditions. No codec instructions, file data or DOS service execute. The result establishes the stack-cleanup mechanism under those explicit helper ABI assumptions; it does not establish a live resource decode or complete `6D50` contract. A later caller-liveness review must determine how its clobbers affect each supported path. Do not silently change ADD SP,8 to6 or infer SI/DI preservation from the presence of PUSH/POP alone.

A later [bounded stage/composition review](td2ega-prefix-stage.md) adds48 cases with actual codec/cache/allocator/copy instructions and synthetic file services. It verifies one-pass6B02 and two-pass7C16→6B02 return composition and retains the SI/DI shift. It also identifies DS=SS for6B02's header-to-stack copy and the7C16 low-word-zero extra65,536-byte write. These scoped results do not admit every wrapper path, resource grammar or caller allocation.

## Remaining ownership work

The initialized byte source at group `66E6/66E8` is outside the descriptor array and startup BSS clear. No direct reset writer has been recovered. Do not introduce a per-race reset by assumption. Indexed reads also require alias review: the audio path reads words at `663B + 2*index`, so the accepted index domain must be established before declaring that table independent of the adjacent cursor/ring state.

Full active/cached pointer lifetimes across every menu/session transition, callback inhibition during moves, stack-local near-pointer bounds, all descriptor-state domains, codec return/size coupling and original I/O failure paths remain open. This report explains named operations without closing P1-05, P1-11, phase2 decoding or any runtime/fidelity gate.
