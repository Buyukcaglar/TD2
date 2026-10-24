# 26D8, 284F and 28F9 orchestration

Three original near-return bodies passed 8,352 synthetic comparisons against
compiled C17: 8,160 normal RET2 cases and 192 native call-budget prefixes.
All 238 instruction locations were exercised. The comparisons cover returned
registers/CF/IF/DF, full memory outside64 explicitly excluded SS scratch bytes,
near/far frames and retained argument pools. Leaf values remain ABI mocks.

`26D8` branches on raw shared flag words, prepares five-word calls to89A2,
and can retain the first five words while pushing another five. The whole
region path first calls89A2 then conditionally prepares all four four-word
916C calls before executing any of them. Cleanup leaves16/12/8/4 live words
at those four calls. Source reads precede those leaf effects as in the original.
The shifted high-byte/CBW and wrapped offset arithmetic are preserved.

`284F` reads its initial DI through currentCS using2A28 plus doubled2C2A,
loadsES from currentDS2A26 and clearsDF. It clears9BE/9C0 each iteration,
selects currentDS word inputs and raw attributes, and calls near0C17. The
loop tests SI!=34 after adding2; an out-of-range initial value is not clipped.
`28F9` doubles the shared2C30 word before comparing signed doubledSI with it,
calls near0D01 two or three times per iteration, then rereads and logically
halves the shared word. A callback may alter that bound; original ordered
read/write behavior, word wrap and changed returnedDS remain explicit.

The actual0C17 body can discard its near return and jump through DS0702
when its internal limit is reached. This module's service model admits
ordinary leaf returns only; it does not establish that nonlocal continuation
or substitute a normal return for it. Actual0C17/0D01/89A2/916C bodies,
DS0702 writers, lookup bounds, output capacities, producer/SS context and
IRQ exclusion remain pending before core integration. The direct body at
0D01 calls8582; its code contract is a separate next recovery step.

[Build](evidence/td2ega-draw-sequence-build-v1.json),
[comparison](evidence/td2ega-draw-sequence-validation-v1.json), and
[native-only diagnostics](evidence/td2ega-draw-sequence-native-diagnostics-v1.json).
No resource format, device delivery, renderer, game session, full state
machine, audio or fidelity acceptance follows. CGA remains deferred.
