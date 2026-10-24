# Nibble-selected plane byte gather

`06C9:AC40` takes four SS words: member offset, member segment, x and y.
It writes raw x/y into the member before reading width/height, captures
those dimensions in SS locals, and shifts only the local x by three.
It then uses a CS row lookup, DSA000, a reread member segment in ES, and
CLD to copy bytes into the member at offset10.

Four header bytes select planes by their low nibbles. Each is fetched by
an overlapping word read; a zero nibble skips ports and copying. A nonzero
nibble indexes CS:[AC0C+index] and emits literal byte OUTs3CE4/3CFvalue.
RS282 records the minimal fifteen-byte initialized index1..15 view. Its
values have the arithmetic lowest-set-bit-index property; real hardware
read-map behavior remains unqualified.

The destination advances across copied rows and adds the captured high
nibble of headerF after every plane, including skipped planes. Source start
and height are reread after ports for each active plane; width is reread
from SS for each row. Copy writes can change those locals, pointer, gap,
counter, saves or return words. Row and byte-plane DEC/JG use signed
overflow correctly: height8000 and counter80 each execute the current
iteration and stop after wrapping to7FFF/7F. Work budgets count plane
heads, row heads, ports and copied bytes.

The C17 `/W4 /WX` build passed3,472 original-instruction comparisons:
449,276 executed instructions and all76 sites. Whole memory, registers/BP,
CF/IF/DF, device requests, counters and control match, including24 changed
root returns and36 pre-RET qualifications. Sixty-five native checks and
static nibble/counter/SP proofs are separate. Actual SS restores and far
return follow all writes. Final ADD SP,12 sets CF for initial SP8..25;
all three known callers immediately ADD SP,8 and replace arithmetic flags.

The static review draft expected twelve instructions in the separateAC64
prefix; the actual count is thirteen. The exact draft/log are retained and
contextv2 corrects that assertion. C, DLL and comparisons did not change.
AC64 has no direct caller in the selected graph; its entry disposition
remains open for P1-11 and is not admitted by this packet.

Member format, actual caller DS/SS, capacities, all writers, ownership,
lifetime, interrupt exclusion, EGA read-map/latch behavior, renderer and
core integration remain open. Raw RAM adapters establish no DOS session,
audio output, complete state-machine, gameplay or fidelity acceptance.
CPU/A20 behavior and physical086C semantics remain unqualified. CGA stays
behind EGA code-contract closure; full resource decoding has not started.
