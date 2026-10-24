# EGA owned-counter snapshot and waits

2026-10-14. `06C9:79C8/7A55/6A6A`, `FN-EGA-000199/000203/000167`, have two
[C17 exports](evidence/td2ega-wait-control-build-v1.json) and
[2,912 comparisons](evidence/td2ega-wait-control-validation-v1.json), exercising
all43 instruction locations. Counter streams are explicit synthetic data
boundaries. No IRQ, real clock, keyboard, input session or device executes.

79C8 executes CLI, reads low/high wordsDS5E8C/5E8E into AX/DX, executes STI and
RETFs. IF becomes1 regardless of its incoming value; DF, CF and other modeled
registers survive. Timer handler61BF increments this pair only on its
non-inhibited5EFE path. This is an owned interrupt-counter source, separate
from the external physical086C reader. Neither cadence nor frequency is
assigned by this packet, and host atomicity is not inferred from CLI/STI.

7A55 takes a caller-clean two-word raw distance. It reads79C8, adds the distance
with ADD/ADC modulo2^32, stores that deadline in its SS frame and repeatedly
reads79C8 until the counter is greater than or equal to the deadline by
absolute unsigned high/low comparison. Even distance zero performs the later
poll. Near wrap, a deadline below the starting value can return immediately;
the C does not replace this with a modular elapsed-time test.

6A6A computes the same deadline but first calls69FE on every iteration. A
nonzero returned AX ends immediately, preserving the callback's other modeled
registers/IF/DF. AX0 polls79C8 and either repeats or returnsAX0 on the deadline.
The SS deadline survives returned DS changes. Input services must preserve
frame BP/SS/control integrity; other modeled registers and CF/IF/DF may change.
69FE's actual dynamic target/body domain remains a separate open contract.

Both wait functions restore incoming BP and RETF without cleaning arguments.
Normal exits have CF0. A deadline exit has IF1 from79C8; an early input exit
retains the callback's IF/DF. The native API keeps frame setup, raw32-bit
addition, absolute comparison, current registers and deadline words explicit.
Tests cover carry across words,32-bit wrap, equality/greater/less cases, early
input, timeout, changed DS and exact local/frame/argument witnesses.

[Five native-only diagnostics](evidence/td2ega-wait-control-native-diagnostics-v1.json)
separate invalid frames, frozen counters, budgets and malformed/rejected
services from original return/error equivalence. A frozen counter is not
normalized into successful completion. Counter-boundary adapters update only
the synthetic bus before79C8; they deliver no interrupt and establish no
reachable tick history or asynchronous exclusion.

Units and meanings of distances30/40/1800 and other caller arguments remain
unassigned. The physical086C address/content/writer anomaly retains its own
evidence and open source/timebase obligations. Actual timer configuration,
IRQ nesting, callback lifetimes, all state/resource ownership and full game
behavior remain open. CGA stays behind EGA code-contract closure; no DOS game
session, renderer/audio output or gameplay/fidelity is accepted.
