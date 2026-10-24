# EGA global raw-deadline publication and wait

2026-10-14.06C9:7A10/7A27 have one
[C17 export](evidence/td2ega-wait-latch-build-v1.json) and
[3,072 comparisons](evidence/td2ega-wait-latch-validation-v1.json), covering
all21 root/snapshot instruction locations. Actual79C8 executes in original
and native composition. Counter-boundary events update a synthetic bus;
they deliver no interrupt and establish no clock rate or reachable tick history.

7A10 saves BP, snapshots DS5E8C/5E8E through79C8, and only then reads its two
raw distance words through SS:BP+6/+8. ADD/ADC computes a modulo32-bit value.
The low word is published to currentDS6818, then the high word to681A. BP is
restored and plain RETF returns without cleaning the arguments. Final CF is
the ADC carry, IF is1 from79C8, and DF survives.

7A27 repeatedly snapshots79C8 and compares DX with currentDS681A. Equal high
words compare AX with currentDS6818. It returns when the current counter is
greater than or equal to the global deadline by unsigned comparison; CF0,
IF1 and unchanged BP/DF follow. The global pair is reread after each snapshot.
A writer can change the outcome. This differs from7A55/6A6A, which retain
their computed deadline in a local SS frame.

Tests include low-word carry,32-bit wrap, unsigned comparison boundaries,
mutable global deadlines, equal/independent DS/SS, and data/argument aliases.
At SS=DS/SP5E88, the snapshot event updates the same bytes later read as raw
distance. SP6812 aliases an argument and neighboring bytes with deadline
publication; original read-before-write order is retained. Live control
frames and executing code remain separate from data effects.

[Five native-only diagnostics](evidence/td2ega-wait-latch-native-diagnostics-v1.json)
are excluded from original comparison/error equivalence. Frozen counters
retain a waiting state. A budget or rejected boundary does not create a normal
return. Counter services preserve CPU state; their return-register structure
is ignored because only declared bus updates precede the actual snapshot.

Distances10/40 and all other caller values retain unassigned units. No counter
rate, device behavior or IRQ delivery is accepted. The physical086C read
anomaly remains distinct from the owned DS counter and global deadline.
Actual writers, caller/handler lifetimes, full state/core/resource integration
and DOS/Windows gameplay, renderer/audio output or fidelity remain open.
CGA stays behind EGA portable code-contract closure.
