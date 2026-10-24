# EGA near control operations

2026-10-13. Six complete near entries have six native exports and a
[C17 build](evidence/td2ega-control-ops-build-v1.json) linking the reviewed4612
product helper. [605,384 comparisons](evidence/td2ega-control-ops-validation-v1.json)
execute their original instructions and actual4612. Group/register/frame
effects use synthetic data, without assigning physical units.

| Entry / ID | Preserved effect |
| --- | --- |
| 44A6 / FN-EGA-000372 | Reverse five-byte ES scan and three known DS-table handlers |
| 44D8 / FN-EGA-000373 | Set DX640h and tail into45FC |
| 45BF / FN-EGA-000376 | Byte-coefficient adjustment or caller-DX subtraction tail |
| 45FC / FN-EGA-000377 | Unsigned subtraction/borrow clamp and conditional4612 |
| 4639 / FN-EGA-000379 | Unsigned limits, signed byte decrement and state3 |
| 4AFA / FN-EGA-000382 | Ordered interval fields and state1/9/4 selection |

44A6 tests the full AX for zero. The zero shortcut preserves incoming DF and
DI. Otherwise it scans AL backward over ES33DA..33D6 with STD/REPNE SCASB,
then executes CLD. Remaining CX is doubled to select one of five words at
DS33DC..33E5. ES and DS are distinct views; an AH-only nonzero AX still
searches for AL0. The selected handlers set5490=FF, conditionally toggle33AF
bit0 when90A8=0, or toggle2F58 bit0. Native admission restricts selected words
to the three reviewed handler addresses44BF/44C5/44D2. Unknown target
diagnostics are outside original behavior. The literal five-slot bound does
not depend on ES=DS; actual caller key ownership and table writers remain open.

45FC subtracts caller DX from52CE with an unsigned borrow clamp to zero.
It calls4612 only if the result differs, retaining that helper's AX product
low word, DX clamped high word and CX old target.44D8 supplies DX640h.
In45BF's FF-control tail, the earlier MOV AX,640h is overwritten by45FC;
DX remains the caller's amount. The other45BF path indexes at most63 bytes
from324A, doubles the coefficient when DX0, and applies signed wrapped
adjustment. A subtraction borrow returns a wrapped AX without publishing
52CE. Normal adjustment sets2F5B but does not call4612.

4639 compares the target and limits unsigned. Its below-minimum DEC/JL
counter path stores only when the old signed byte is positive. Old80h
decrements to7Fh with overflow and skips the store. The event path can clamp
332C and set5490=3 without storing the incremented counter. Native code
retains the observed BL even on paths that leave its group byte unchanged.

4AFA first computes and publishes3332/3334/3336 from old52CC+28h and its
wrapped bounds. It may then write52CC=230h while leaving those earlier fields
based on the old value. Signed mode/center and unsigned52CF guards select
states1/9/4 on the original paths. Publication order and unchanged paths
are preserved rather than recomputed after the clamp.

Tests include every16-bit AX scan value, subtraction input and interval word
at two load bases, distinct/shared ES, byte-counter overflow, coefficient
indexes, signed/unsigned thresholds, state modes and varied groups. Full
group bytes, AX/BX/CX/DX, scanner DI/DF, IF and near frames match. Other
entries preserve IF/DF. Incidental arithmetic flag consumers, actual caller
DS/ES, indexed writers, resource schemas, asynchronous state ownership and
the complete state machine remain open. No renderer, audio output, DOS game
session, gameplay or fidelity is accepted. EGA closure continues to gate CGA.
