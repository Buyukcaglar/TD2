# Six RAM and device mask helpers

82D0/8336/839C andAD22/AD8B/ADF4 passed15,268 comparisons against compiled
C17 across all306 instruction locations. Outcomes:8,112 normal nearRET2
returns and7,156 native work prefixes.4,757,078 original instructions executed;
1,581,868 byte writes,366,504 device reads and366,372 device writes matched.
Four cases fully exercised zero-count LOOP behavior across two load segments.
The full1MiB bus, GPR/BP/CF/IF/DF and near-return frames matched without a
scratch-memory exclusion; these helpers have no saved/local stack frame.

The three RAM helpers retain AND/OR/XOR byte effects, rawBX mask selection,
byteDL decrement and overflow-aware JL, word strides and DI wrap. REP zero
counts produce zero writes; LOOP zero counts produce65,536 iterations.
Outer DEC SI/JG rows differ from LOOP rows. REP/STOSB honors incomingDF;
several explicit INC DI loops advance by one regardless ofDF. Those paths
are not normalized to a common host count or direction.

The device helpers expose read/write requests with the exact register source
and order. A middle read can replaceAH before the right-edge operation uses
it. ADF4's aligned path XORsAH withAL but still executes STOSB ofAL. The C
preserves both details. Synthetic flat-bus traces do not establish actual
hardware latch or presentation behavior.

Mask bytes remain external at currentCS82C8 andAD1A. The helpers do not mask
rawBX themselves. Known sprite setup derives an alignment&7, but arbitrary
standaloneBX can read outside the eight-byte candidates; all caller/frame/
writer domains remain open. No original mask byte values are embedded in C.

[Build](evidence/td2ega-mask-span-build-v1.json),
[comparison](evidence/td2ega-mask-span-validation-v1.json),
[native checks](evidence/td2ega-mask-span-native-diagnostics-v1.json),
[mask context](evidence/td2ega-mask-resource-context-v1.json).
Three native-only input checks are separate. Live return frames/executing
code remain separated from outputs in the admitted profiles. Actual sprite
callers, table/output capacities, writers/lifetimes and IRQ exclusion remain
pending before core use. No real device, renderer, resource-fed output, DOS
session, full state machine, audio, gameplay or fidelity acceptance. CGA
remains behind EGA portable code-contract closure.
