# EGA timer installation, reset and cleanup contracts

2026-10-13. `FN-EGA-000147/148/149` at `06C9:601C/6059/610A` have
serialized native port/vector/data contracts. [The C17 build](evidence/td2ega-timer-control-build-v1.json)
and [6,656 comparisons](evidence/td2ega-timer-control-validation-v1.json)
cover two code loads, vector ownership combinations, IF/DF, port snapshots,
positive/negative divisor words and2,048 divide-fault prefixes. Six native
argument diagnostics are separate. Ports are synthetic callbacks; no real
hardware, handler or interrupt executes.

6059 divides signed DX:AX=0001:0000 by the supplied signed16bit word.
Zero and quotients outside-32768..32767 fault before any data/port effects.
Thus divisors0/1/2/FFFF fault, while negative words such asFFFE produce the
original negative quotient word. Native code checks those cases explicitly.
It does not substitute unsigned division or silently clamp the argument.
The valid quotient populates5E98/5E9A,5E94=0 and5E95=1.

601C instead selects raw divisor2E9C, sets5E98/5E9A=5,5E96=64h and5E94=1.
It **does not assign5E95**. Both entries then share6099's installation body:

1. CLI; clear first callback offset/segment at5F12/5F14; STI.
2. Read port61, write it with low two bits cleared; writeB6 to port43.
3. Read port21, write it with low two bits set.
4. Clear5E9C and40 histogram words5E9E..5EED. These writes occur withIF1.
5. CLI; perform the separate saved-vector tests and possible installation.
6. Read port21, clear its low two bits and write it; STI.
7. Write raw divisor low byte then high byte to port40.

The original compares the old offset with61BF before conditionally saving it,
then compares the old segment with CS. Only a differing segment saves that
segment and installs CS:61BF. A same-CS vector with a different offset can
therefore skip installation after updating only the saved offset. An old
offset61BF with a foreign segment retains the prior saved offset. Those effects
are preserved and tested; a conventional whole-far-pointer ownership check
would change the supplied code.

610A changes nothing unless the current vector is exactly CS:61BF. On a match
it masks the two port21 bits, CLI, restores saved offset/segment at physical
20/22, clears the two port21 bits, STI, writes zero twice to port40 and clears
the two speaker-control bits. It does not clear callback metadata or restore
the incomingIF; a successful cleanup ends withIF1. An ownership miss preserves
IF and emits no port event. DF remains unchanged on all tested paths.

These effects carry raw numeric values only. Neither a frequency nor a time
unit has been assigned to these counters/divisors, and the separate physical
086C reader is unchanged and unassigned. The native result records ordered
port/IF effects, but serialized snapshots do not establish asynchronous host
atomicity, real hardware delivery or full original IRQ scheduling.

[Sixteen caller-tail composition cases](evidence/td2ega-timer-callback-lifetime-v1.json)
execute actual3FD9..3FF8:601C followed by registrations6269 and403B. The actual
1BEB call to601C then clears the first pair before either mutable state-return
tail runs. Later rows remain stale, including403B, but segment zero in the
first pair terminates the ISR walk. A subsequent75EA registration clears the
next segment and hides that stale403B slot. Combined native timer-control and
callback helpers match those data/port effects. This establishes those local
publication/removal stages, while full session guards, moving-resource
exclusion, callback execution and gameplay remain open.

The divide-fault harness starts a fresh Unicorn CPU after each fenced exception;
resuming the same faulted CPU produced a later emulator fault-delivery event.
No original handler is run or treated as a tested divide-recovery path.
