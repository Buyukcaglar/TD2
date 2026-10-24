# EGA audio pointer and flag ownership

2026-10-13. Five bounded metadata helpers have native C interfaces and
[15,312 original-instruction comparisons](evidence/td2ega-audio-metadata-validation-v1.json).
[The build](evidence/td2ega-audio-metadata-build-v1.json) uses the pinned C17
compiler. Nine native-only argument/range diagnostics are separate. Source
bytes, original state and stack are disjoint synthetic views; no audio plays.

| Entry / function ID | Observed state effect | Interrupt policy |
| --- | --- | --- |
| `758A` / `FN-EGA-000189` | Only when DS5EFB=3: select two words at external source+4*selector; copy to65ED/65EF and65F1/65F3; set source segment65F5, flags65D2 and5EFC to1 | CLI during reads/publication, endsSTI |
| `75C8` / `FN-EGA-000190` | Store supplied source segment/offset at65F7/65F9 | IncomingIF unchanged |
| `7946` / `FN-EGA-000196` | Store queued segment/offset at5EF2/5EF4 and set5EFD=1; only if5EFC=0 also copy to5EEE/5EF0; it does not set5EFC | CLI during updates, endsSTI |
| `7971` / `FN-EGA-000197` | Clear5EFD only | IncomingIF unchanged |
| `7977` / `FN-EGA-000198` | Store active segment/offset at5EEE/5EF0 and set5EFC=1 | CLI during updates, endsSTI |

These are opaque original far-data coordinates, not host pointers or accepted
file schemas. In particular75C8 does not inspect the supplied two-byte
VOICES.BIN; later reads and valid event indexes remain unresolved.

758A performs two16bit shifts and an offset addition modulo65536. Its source
view is a full64KiB segment; the second word uses the16bit effective offset
`first+2`, so selection can wrap between words atFFFE and0000. Individual word
reads beginning atFFFF are outside the bounded native profile. Native status2
rejects such reads; that diagnostic is not original behavior. A mode other
than3 does not touch source memory, ES or AX. The source view must be disjoint
from native metadata/result and from the original mutable state in this
profile. Actual aliases and caller source bounds still need proof.

All five functions preserve BP/SI/DI/DS/SS/DX/CX and DF on normal far return.
758A changes ES and BX only on its active branch and returns the second selected
word in AX; otherwise those registers are unchanged.75C8/7946/7977 leave the
supplied offset in AX.7971 leaves AX unchanged. Original arguments remain for
caller cleanup. Native results expose pointer/flag ownership and final IF
effect rather than incidental register/flag values.

Matched metadata updates endingSTI do not restore incomingIF. The native
interfaces model serialized calls and make that effect explicit; they do not
claim concurrent host atomicity or accepted IRQ delivery. [The byte-ring
caller review](td2ega-byte-ring-callers.md) separately proves that the4A41
sampler follows7977 withIF1 and records its nested-call nonserial witness.

The sequencer's indexed accesses at7725/77AD read words from DS663B+2*index.
They are reads, not writers to the byte-ring. Without accepted index domains
they can couple to nearby cursor/ring bytes; the current operand ledger cannot
prove their source bounds. Complete table provenance, command processing,
timer cadence, PIT/speaker effects, actual source lifetimes, audio output and
fidelity remain P1-07/10/11 and later resource-fed obligations.
