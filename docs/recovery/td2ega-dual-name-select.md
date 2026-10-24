# Dual record name selection

`0000:0651` now composes actual2B40 and2956 helpers in C. It searches
two query names against records at8D24 with a30-byte stride, rereading the
signed count8A7A and actual SS local counter on each iteration. Each query
keeps its last matching index. An unmatched primary defaults to0; an
unmatched secondary defaults to1 only when the count reread after the
primary copy and output is signed greater than1.

The code copies the selected names to8428 and90B0, then rereads each index
and takes the word at record offset26 for outputs8A82 and9264. All four
far calls use actual SS arguments and frames followed by ADD SP,4.
Incoming DF and actual child BP/register/segment state are retained.
One caller uses PUSH CS plus a near CALL to supply a far-return frame.
Both callers next enter0730, whose SUB SP replaces arithmetic flags.

Each record offset uses signed word IMUL with multiplier30. DX/AX contain
the full product; only low AX is added to the near base. The final IMUL's
DX and carry survive the epilogue. Its signed result fits a word only for
operands-1092..1092. The original full-function comparisons include counts
1092..1095, selecting indices1091..1094 across that carry boundary. A
separate SS alias changes the secondary index to negative8D0A, producing
DXFFF2, low product872C and carry1 before the final indexed word read.

The C17 `/W4 /WX` build passed8,192 comparisons,3,270,978 original
instructions and all132 feasible sites in the134-site family fence. The
two excluded copy instructions are the odd-destination path; this parent
always pushes even8428 or90B0 immediately before the far call. Standalone
2956 covers its complete body. Full bus/SS, registers/BP/CF/IF/DF, control
and budgets match, including12 changed child returns,104 changed root
returns and16 multiplication-boundary cases. Twenty-nine native checks and
65,536 static multiplication checks remain separate. Earlier8,176 cases
passed; C and DLL stayed unchanged when the boundary fixtures were added.

All nine principal-coordinate views are beyond the initialized image in
BSS, so they are not embedded-resource span identities or decoded schemas.
Complete callers, writers, valid counts, names, NUL bounds, index domains,
DF assumptions, capacities, ownership, lifetime, interrupt exclusion and
core integration remain open. Historical CPU/A20 behavior remains unqualified.
No DOS session, renderer, audio, complete state-machine, gameplay or fidelity
acceptance is established. CGA remains behind EGA portable code-contract closure.
