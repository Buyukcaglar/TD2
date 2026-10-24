# EGA four-byte directory selection

2026-10-13. `06C9:6E4E` (`FN-EGA-000174`, optional) and `06C9:6E59`
(`FN-EGA-000175`, required) share one native export. The [accepted C17 build](evidence/td2ega-directory-build-v2.json)
passes [11,784 comparisons](evidence/td2ega-directory-validation-v2.json)
against their original instructions. These are literal code effects over
synthetic memory, not acceptance of an archive schema or supplied file.

The selector is four bytes in the principal data group. The routine fills
from its first NUL through byte3 with spaces, in place, before reading the
source count. Comparison is byte-sensitive. A mismatch between a source NUL
and a selector space accepts immediately, ignoring the remaining bytes.
This is more permissive than comparing two normalized four-byte strings.

The header count is read at source offset+4. Names begin at source offset+6.
After a mismatch, the original advances four bytes, decrements AX and uses
signed `JGE`. For counts0..7FFF it can inspect count+1 records. A negative
count inspects one record on mismatch. In particular8000h decrements to7FFFh
with overflow, so JGE fails. The first native build incorrectly tested only
the decremented sign; comparison caught this. Buildv2 preserves SF/OF behavior.
Maximum positive counts and word/near-offset boundaries are in validationv2.

On a match it rereads the header count, reads the32-bit relative value at
matched-name address+4*count and adds it to:

`source_segment*16 + uint16(count*8 + 6)`

The original does not add source_offset to that base. Name/table effective
offsets wrap16bits. A word beginning atFFFFh reads its adjacent physical byte;
the second word's effective start wraps separately. The32-bit sum wraps,
then AX receives its low nibble and DX receives the low16 bits after shifting
right four. No returned payload is dereferenced by this contract.

Optional missing returns0:0. Required missing reaches fatal message651A;
comparison stops before fatal cleanup. Both normal paths restore incoming
DS/BP/SI/DI, leave ES at the principal group, clear DF and RETF with their
three argument words still present. Incidental flags remain caller obligations.

The source view supplies all actual reads. Tests include two relocation bases,
optional/required modes, all256 selector first-byte values, selector padding,
early NUL acceptance, signed count boundaries,32-bit carries, nonzero source
offsets, adjacent word reads and wrapped table/name offsets. Full source and
selector-group bytes, comparison count, far result, arguments and preserved
registers match. Native bounds/work diagnostics are separate.

The16EB:000A/004C callers walk four-byte selector lists and store returned
pairs, using required/optional policy respectively. Their list/output bounds
and actual source ownership remain open. No full resource decode, DOS game
session, renderer, audio, gameplay or fidelity follows from these comparisons.
