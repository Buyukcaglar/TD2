# EGA self-modifying line-step contract

2026-10-14.06C9:06C3/FN-EGA-000069 has one
[C17 export](evidence/td2ega-line-step-build-v1.json) and
[12,744 comparisons](evidence/td2ega-line-step-validation-v1.json), covering
all59 instruction locations.10,504 cases return through near RET6;2,240 stop
at bounded work prefixes. Two
[native-only domain checks](evidence/td2ega-line-step-native-diagnostics-v1.json)
are separate. A fresh CPU is used per fixture.

The original receives destination, second endpoint and first endpoint through
SS:BP+4/+6/+8, with implicit CX count and DX denominator. The native API takes
those three words explicitly under a serialized frame/data separation profile.
DS5348 supplies initial signed clipping; output is ES:DI with incoming DF.
Near `RET 6` consumes the return IP and six argument bytes, totaling eight.
BX/CX/DX/BP are restored normally; AX/SI/DI/CF and opcode writes remain.

Both nonpositive endpoints fill0; both at least the signed upper bound fill
that bound. Otherwise an initial STOSW precedes DEC CX and the wrapped signed
endpoint difference. Positive differences write INC AX opcode40 to CS071F
thenCS0735. Negative differences negate the wrapped difference and write48
for DEC AX in the same order. Uniform and zero-delta exits can retain prior
bytes. The [static family review](evidence/td2ega-line-mutation-review-v1.json)
retains both stable pairs and intermediate write prefixes.

Unsigned magnitude-versus-DX comparison selects an inner loop whose threshold
comparison is signed. INC/DEC and SI arithmetic wrap at16 bits. DF selects
forward or backward word stores. A zero denominator can prevent progress in
the slower loop; work budgets preserve that prefix instead of inventing a
normal return. Prefix comparisons also stop between the two opcode writes.
Unknown initial bytes are conditional probes that are rewritten or never
executed, not claims of reachable game code states.

REP with CX0 performs no writes, while LOOP after a zero count executes65,536
iterations. In a nonuniform interpolation path, initial CX1 can produce65,537
word writes including the initial store; initial CX0 can produce65,536. Full
word-count fixtures retain these effects rather than correcting them.

The suite compares all bus effects outside eight live SS saved-register bytes,
including persistent code mutations, register/CF/IF/DF and exact RET6 cleanup.
Other output/code/frame aliases are outside the admitted profile; the two
authored opcode writes are explicit code-write effects. No native host text
is modified, and no canonical image bytes are changed.

[2477's caller contract](td2ega-record-interpolate.md) now composes the five
near calls and SS-previous/DS-current views; actual caller bounds remain open. IRQ/reentrancy/exclusion, prefetch/timing,
source/output lifetime and whole mutable transitions remain open. No renderer,
complete state machine, DOS/Windows gameplay, resource decoding, audio output
or fidelity is accepted. CGA remains behind EGA portable code-contract closure.
