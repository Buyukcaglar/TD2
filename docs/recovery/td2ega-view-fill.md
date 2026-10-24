# Current-view fill paths

`06C9:843E` takes one SS color word and reads current CS view bounds,
row table and stride. It retains incoming DF throughout. Its initial first
plane selects the hardware path; other planes select one of two software
paths by comparing width with stride. No geometry domain or capacity is
inferred from those tests.

The packed software path retains the low word of signed width-times-height,
fills word pairs and an optional odd byte, and shifts only DL between planes.
The SS color word remains unchanged. The row software path captures width
in BX once per plane, fills bytes row by row, then shifts the full SS color
word after every plane, including skipped planes. Zero/8000 height executes
one row in that path. With DF1, stores move backward while the following
stride addition remains positive.

The hardware path emits four setup ports, then rereads the first plane into
ES. Width40 uses byte MUL40*DL, so height0100 produces zero bytes. Other
widths reread the SS width for each row. Two reset ports follow either path.
Raw RAM adapters own byte/word effects and preserve CPU state; real EGA
write-mode, map-mask and latch effects remain unqualified.

The C17 `/W4 /WX` build passed8,264 original-instruction comparisons:
913,912 executed instructions and all129 sites. Whole memory, registers/BP,
CF/IF/DF, device requests, counters and control match, including52 changed
root returns and444 pre-RET qualifications. Sixty-seven native checks and
static path/SP proofs are separate. They cover DF1 word stepping, color
mutation differences, low-byte multiplication, live width, mutable plane
counter, saved DS, far-return aliases and cached hardware qualification.

Actual SS restores and plain RETF follow all writes. Final ADD SP,0C
sets CF for initial SP8..19. All35 known callers immediately ADD SP,2 and
replace arithmetic flags. No new initialized resource span is asserted.
Actual caller DF/DS/SS, geometry, capacities, all writers, ownership,
lifetime, interrupt exclusion, device hardware, renderer and core integration
remain open. No DOS session, audio output, complete state-machine, gameplay
or fidelity acceptance is established. CPU/A20 behavior and physical086C
semantics remain unqualified. CGA stays behind EGA code-contract closure;
full resource decoding has not started.
