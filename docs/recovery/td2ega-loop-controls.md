# EGA root-loop control interfaces

2026-10-14.06C9:1F60/1F71/1F99 have one
[C17 export](evidence/td2ega-loop-controls-build-v1.json) and
[2,720 comparisons](evidence/td2ega-loop-controls-validation-v1.json), covering
all111 instruction locations. There are4,128 near and11,248 far leaf calls.
Leaf bodies are ABI mocks with reviewed plain RET or plain RETF normal exits.
The distinction is a two-byte versus four-byte return frame, without callee
argument cleanup. All three roots use plain far RETF.

1F60 passes currentDS2A20/2A22 to782C, then cleans four argument bytes.1F71
saves BP/DS/SI, writes5348=80, and calls near21C3/2477/2542. It then loadsAX
from currentDS2C2A, setsBP17 and calls near088E before restoring SI/DS/BP.
Its other returned registers and modeled CF/IF/DF survive. Normal1F60 CF is0;
normal1F71 CF comes from088E.

1F99 saves the same registers and writes0702=28BD. After7D5E receives the
2A20/22 pair, four currentCS AF3C..AF42 words are copied to currentDS5420..26.
Returned DS affects these writes and later reads; final POPDS restores the
root's incoming segment. Tests include explicit CS field updates by the
service before this copy and contrasting DS contents.

The first33D4/33CE gate controls near26D8/284F, optional28F9 by2C98 bit80,
then2958. The fields are reread after services. Nonzero33CE is shifted right
three times. Mode4 invokes91A4, then uses returned DI in a wrapped17-DI
argument. Other modes retain an initial five-word argument set while pushing
five more for89A2. One call observes all10 live words; ADDSP10 removes the
newer five, and the next call receives the older five before another ADDSP10.
This caller lifetime is retained across1,152 such comparison cases.

The tail calls3EFC, reloads the2A24/26 pair through currentDS, calls9CC2 and
cleans its arguments before restoring SI/DS/BP. DI and other service outputs
remain. Normal1F99 CF is0. Fields and shifted values have no assigned physical
units or decoded resource meanings.

Native frames are virtual. Services use provided argument vectors, preserve
SS/SP/control frames and caller words, and return explicit modeled registers
and flags. Code, data and frames are separate in this profile. Five
[native-only diagnostics](evidence/td2ega-loop-controls-native-diagnostics-v1.json)
retain budget and rejected near/far prefixes without original error equivalence.

The actual near helpers, graphics leaves, CS field writers, resource bounds,
state ownership and asynchronous lifetimes remain P1 work. This packet admits
no renderer, device/IRQ, full state machine, DOS/Windows gameplay or fidelity.
CGA stays behind EGA portable code-contract closure.
