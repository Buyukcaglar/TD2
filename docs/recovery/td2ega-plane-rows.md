# Actual 284F and 0C17 continuation composition

The compiled composition of284F and0C17 passed3,840 comparisons against
actual original instructions, covering all144 locations in the owned-body
fence. Counts:1,056 normal near returns,1,584 external near jumps and1,200
native call-budget prefixes.7,708,936 original instructions executed,
80,168 actual span calls,16,336 row iterations and5,004,032 plane byte writes
matched.6,784 discarded-return continuations were observed.

When0C17 discards its near return and jumps to28BD, the composed C follows
the original row-advance path, skipping any remaining span calls in that
iteration. For example, an early input extent80 can jump after the first
span, whereas monotonic8/16/32/48/64 inputs reach the final80 span first.
A different raw DS0702 target produces an explicit nonlocal result with the
callerSP, rather than a substituted normal return. Native budget prefixes
stop before the next call. No leaf ABI mocks remain in this composition.

Synthetic profiles include early/no-op/large/signed extents, equal and
independent DS/SS mask views, currentCS initial DI lookup, plane/data aliases,
raw SI wrap and out-of-range loop starts. RootCLD is preserved; the helper
reads its mask viaSS and its plane words viaDS. The comparison excludes32
private SS frame bytes and checks the rest of memory and GPR/BP/CF/IF/DF.

DS0702=28BD is the value explicitly written by1F99, but this test does not
close all aliased writers, startup ordering or every caller domain. Plane
segments and inputs are synthetic RAM profiles, with no actual EGA device,
renderer, decoded resources, capacity/producer/lifetime or IRQ admission.
Full state machine, game session, audio output, gameplay and fidelity gates
remain separate. CGA remains behind EGA portable contract closure.

[Build](evidence/td2ega-plane-rows-build-v1.json),
[comparison](evidence/td2ega-plane-rows-validation-v1.json), and
[native checks](evidence/td2ega-plane-rows-native-diagnostics-v1.json).
The helper-suite count includes this stronger caller contract; original-entry
count remains a union and does not count284F or0C17 twice.
