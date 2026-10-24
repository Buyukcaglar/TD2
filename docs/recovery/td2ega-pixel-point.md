# Word-port and plane-byte operations atBA3C

`06C9:BA3C` has a full-SS C contract for three caller-owned words: an unsigned
x word, a wrapped y/table index word and the low byte of a color word. It uses
x&7 for the mask index and x>>3 for the byte offset. The row word comes from
the wrapped CS lookup selected through AF44. Coordinate units, clipping,
dimensions and the row table's valid extent remain open.

The first current CS:AF3C word selects one branch. If it is A000, five actual
word-sized OUT instructions bracket a byte read into CH and a write of the
full CL byte. Otherwise four current CS plane-word slots are read in order,
with zero slots skipped. Each consumes one CL bit and performs either a
byte read/AND/write or an atomic byte OR transaction. The upper color nibble
remains in CL after the four shifts; it is not discarded on entry.

The typed RAM adapter preserves CPU state. Its byte effects are followed by
the original MOV/OR instruction's idempotent store during comparison, so the
original CPU write count and flags remain observable. This bounded profile
does not model actual EGA controller, latches, bus cycles or a renderer.

The C17 `/W4 /WX` build passed5,328 comparisons,298,780 original instructions
and all61 sites. Whole bus, live SS saves/far frames, registers, CF/IF/DF,
device requests and counters match. Coverage includes12,864 word OUTs,
4,672 OR transactions,2,400 DS=SS cases, four changed root returns and108
pre-RET qualifications. All37 native checks and static word/byte proofs
are recorded separately. The three known callers next execute ADD SP,6.

RS279 records the initialized eight-byte mask candidate at68CE..68D5.
Its source index bound0..7 is proved; runtime DS, all writers, plane/row
bindings, storage lifetime and exclusion remain open. The selected build
caches the original branch when reporting a pre-RET qualification, so later
adapter writes to CS:AF3C cannot change the reported return site.

Historical CPU stack faults and A20, actual DOS sessions, renderer, audio,
complete state-machine validation, gameplay and fidelity remain unqualified.
CGA recovery remains behind EGA portable code-contract closure. Physical086C
remains a distinct unassigned read.

Evidence: [comparison](evidence/td2ega-pixel-point-validation-v1.json),
[context](evidence/td2ega-pixel-point-context-v2.json),
[native diagnostics](evidence/td2ega-pixel-point-native-diagnostics-v1.json).
