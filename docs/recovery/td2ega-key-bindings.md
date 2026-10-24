# EGA key callback bindings

2026-10-13. Complete `06C9:6585` (`FN-EGA-000154`) and its installer
`16FC:0002` (`FN-EGA-000357`) have two native exports. The [C17 build](evidence/td2ega-key-bindings-build-v1.json)
passes [131,104 comparisons](evidence/td2ega-key-bindings-validation-v1.json):
all65,536 key words at two relocation bases, plus32 complete installer cases.
Full group bytes, ordered original writes, return frames, arguments, AX/BX/DX
and preserved registers/IF/DF match. These are synthetic memory comparisons.

For a nonzero low key byte,6585 compares the complete key word with007Fh using
signed JG. It writes the callback offset when the signed key is at most127.
Thus negative key words are admitted. The effective store address is
`uint16(6048h + 2*key)`. This can address group words outside the intended
ASCII callback table. Key834Fh, for example, writes the ring cursor at66E6h.
The supplied callback segment argument is ignored.

For a zero low key byte, the routine extracts the high byte. Values up to84h
read the fixed word at624Ch into BX; this branch performs no binding write.
Higher values leave the extracted high byte in BX. AX is the supplied callback
offset on every path, DX survives, and no CLI/STI occurs. Do not replace this
branch with an inferred extended-key table setter.

The current discovery ledger has exactly six direct6585 calls, all in
16FC:0002. Main calls the installer at0000:080C. Actual argument triples and
ordered writes are compared using the original installer and setter:

| Key | Near callback offset | Group word |
| --- | --- | --- |
| 0A | 645A | 605C |
| 0B | 646F | 605E |
| 10 | 6508 | 6068 |
| 11 | 64C7 | 606A |
| 13 | 6488 | 606E |
| 18 | 6518 | 6078 |

Each installer call supplies relocated6C9 as the ignored segment. The installer
ends AX=6518, BX=0030 and DX=relocated6C9, preserving IF/DF and its outer frame.
These small constant keys cannot exercise the negative-key group aliases and
do not reset the byte ring. The literal834Fh effect is not evidence of a
reachable reset, input exploit or original seed policy. Computed callers and
other indexed/aliased writers remain separate review obligations.

Dispatcher6528 later masks ASCII input to7bits, loads a near offset and performs
PUSH relocated6C9 followed by CALL BX. Its callback must honor that far-return
frame even though the instruction is a near call. Callback bodies, table
writer closure, guards and actual IRQ/lifetime behavior remain open. This
packet admits no keyboard session, platform behavior, renderer, audio,
gameplay or fidelity. Full EGA closure continues to gate CGA.
