# Raw block request composition

`13A8:2852` owns the BP frame used by28C0 and retains its five available
SS words, raw mode, cursor, carry branches and DOS48 fallback. The second
helper path writes the segment key in SS, pushes SI, and rereads that actual
saved word after the child's near RET. The service budget is shared across
the child SETBLOCK and parent ALLOC requests. Both use full returned state.

Failure writes AXFFFF and performs word CWD, preserving the carry from the
actual path. A changed saved SI can select a boundary failure with carry0;
the implementation does not force STC. Allocation success uses returned
DS/SI/DX/AX in the ordered row and cursor writes, then XOR AX,AX. The root
reads saved ES/DI/SI before MOV SP to actual returned BP and its far RET.

The C17 `/W4 /WX` build passed21,440 comparisons,
962,680 original instructions and all92
root/child sites. Full bus/SS, GPR/BP/CF/IF/DF, requests, control and write
counts match. Twenty-one native diagnostics are separate. Earlier runs
needed a missing validator hook and independent first-row fixtures; the
C and DLL stayed unchanged.

The283E caller window and existing RS274 metadata span are recorded.
Complete higher callers, service preservation, metadata writers, valid
domains, capacity, ownership, lifetime, interrupt exclusion and core
integration remain open. Raw child/root targets are exposed after actual
RET and never followed. Synthetic services omit real DOS and INT frames.
No DOS session, renderer, audio, complete state-machine, gameplay or fidelity
acceptance is established. CGA remains behind EGA contract closure.
