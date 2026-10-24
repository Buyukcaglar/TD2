# Stream buffer setup

`13A8:0BE8` now composes the actual26A8 heap family in C. The near entry
accepts one SS stream offset, requests the literal count0200 through a real
far frame, then discards that count with ADD SP,2. It stores only child AX
in the current-DS stream record. DX is retained but ignored by this body;
the returned pair is not silently converted to a host pointer.

AX nonzero sets flag08 and writes size0200 to the side metadata. AX zero
sets flag04, selects the fallback byte offset and writes size1. The stream's
byte at+7 is sign-extended by word CBW and multiplied by six with literal
16-bit operations. All256 byte values yield raw indices-128..127, or offsets
-768..762 in steps of six. This body does not enforce the nominal20-row
extent recorded by RS266. Actual caller index domains remain to be proved.

The final stream argument and pointer field are read again after the
metadata stores. Those stores can change the pointer: with the stream at
6E92 and index0, the6E96 size write changes its pointer field to0200, which
becomes final AX. Actual SS saves and the near return are read after all
writes. This epilogue uses POP SI/POP BP/RET without MOV SP,BP.

The C17 `/W4 /WX` build passed11,056 original-instruction comparisons and
all310 feasible sites in the339-site family fence. Full bus/SS, registers,
BP/CF/IF/DF, required normal ZF, service requests, counters and control match.
The29 exclusions retain the literal2830 parent-argument proof; standalone
2852 covers its complete body. Twenty-three native checks and the256 static
index calculations remain separate from comparison vectors.

The first10,992 comparisons matched but missed nine alignment
failure and scan sites. A trace showed that a focused stream fixture itself
overwrote6F26, redirecting the fallback cursor before growth. The selected
comparison moves that stream off the control fields, uses header0203 for
the fixed0200 request and adds64 scan cases. C and DLL remained unchanged.

Both known callers immediately discard their argument with ADD SP,2,
replacing arithmetic flags. Complete0B42/21D6 callers,0C4E, all metadata
writers, valid indices, DS/SS bindings, capacities, ownership, lifetime,
interrupt exclusion and core integration remain open. Synthetic services
omit real DOS/INT frames; historical CPU/A20 behavior remains unqualified.
No DOS session, renderer, audio, complete state-machine, gameplay or fidelity
gate is established. CGA remains behind EGA portable code-contract closure.
