# EGA near clamp helper at088E

2026-10-14.FN-EGA-000071 has one
[C17 export](evidence/td2ega-near-clamp-build-v1.json) and
[786 comparisons](evidence/td2ega-near-clamp-validation-v1.json), covering
all30 instruction locations.770 cases return normally through a plain near
RET;16 stop at a bounded instruction prefix. Two
[native-only domain checks](evidence/td2ega-near-clamp-native-diagnostics-v2.json)
are separate. The earlier diagnostic receipt is retained; v2 corrects its
dependency pin to the actual near-clamp validator, without changing the C.

The function startsSI09C4, DX0, DI5 and DF0, and captures BX fromDS5348 once.
Each pass saves AX, computes CX=BP-AX modulo16 bits, and adds AX twice toSI.
LODSW reads a word and advances SI by2. A signed negative value is stored as0;
otherwise a signed value greater than BX is replaced by BX. Negative upper
bounds are retained. Lower-before-upper order means this is not a normalized
min/max clamp, and overlapping passes can transform earlier results again.

LOOP decrements16-bit CX after processing. Initial CX0 therefore processes
65,536 words in each pass; it does not skip the pass. The two full zero-count
cases each execute327,680 word operations across all five passes, with SS
separate from DS so the original data writes cannot corrupt live stack frames.
A negative-bound prefix crosses an entire pass and preserves captured BX
even after the5348 memory field changes.

After each pass the code adds005C-BP twice toSI, restores saved AX and
decrements DI. Normal completion restores incoming AX, leavesSI0D5C and
CX/DX/DI0, preserves BP/DS/ES/IF and leavesDF0. Final CF is the last SI-add
carry. A plain near RET pops two bytes. The original saved-AX local is excluded
from the native bus comparison under an explicit frame/data separation profile.

Actual1F71 loadsAX from currentDS2C2A and setsBP17 before this call.2089
initially writes2C2A=17, while intervening near21C3/2477/2542 remain unrecovered.
Their actual writes and caller bounds must be proved before integration.
The synthetic wide-count cases do not prove that the full-group path is
reachable in a game session, nor that DS=SS is safe for it.

No zero-count fix, inferred array capacity, table layout, decoded resource,
renderer or complete caller/state acceptance is introduced. P1 source and
ownership work remains open. No actual device/IRQ, DOS/Windows gameplay,
renderer/audio output or fidelity is accepted. CGA stays behind EGA closure.
