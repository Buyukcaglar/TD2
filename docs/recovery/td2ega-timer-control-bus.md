# Timer startup and cleanup with actual SS

18 October 2026. The additional [C17 interface](../../src/recovered/td2ega_timer_control_bus.h),
[build](evidence/td2ega-timer-control-bus-build-v1.json),
[3,234 original comparisons](evidence/td2ega-timer-control-bus-validation-v1.json),
[static review](evidence/td2ega-timer-control-bus-context-v1.json) and
[48 native diagnostics](evidence/td2ega-timer-control-bus-native-diagnostics-v1.json)
cover all91 unique601C/6059/610A instruction sites and327,336 instructions.
One new C export models three already registered original entries. Old typed
interfaces, sources and DLLs remain frozen; original entries are counted once.

601C and6059 PUSH actualBP, then POP the actual word and farRET without argument
cleanup. 610A has no save and three farRET exits. CurrentDS and inheritedSS
are independent. All1MiB RAM, GPR/BP/IF/DF, defined CF/FLAGS, CPU writes and
ordered byte ports are compared. Stack, state, IVT and adapter aliases remain.

6059 divides signed65536 by actualSS:[BP+6]. Words0/1/2/FFFF fault beforeIDIV;
these are qualification prefixes with savedBP retained, not delivered faults.
After a valid division, maskF72A excludes all arithmetic flags, includingCF.
The source publishes quotient to5E98/5E9A before rereading the SS divisor at606A.
An aliased argument can therefore change the bytes later written to port40.
No captured-divisor shortcut or postIDIV carry assumption is introduced.

Installer offset and segment guards are independent: a matching segment alone
can skip installation despite a different offset. Cleanup requires the exact
CS:61BF pair, restores saved vector words and leaves callback rows intact.
Raw2E9C/reload5/relay64/PIT and speaker requests retain literal values; no clock
units or physical086C timer semantics are assigned.

The corpus includes144 preIDIV,702 budget and24 preRET prefixes,196 changed
root returns,26 prefixes with unknownCF,402 equalDS/SS cases and24 IVT/frame
aliases. Native diagnostics separately exercise every admitted port failure.
No executing code mutation, real port/device access or historical CPU wrap/
exception qualification is established by these analysis interfaces.

Full native3FD9 producer/614C actualSS publication, stale-row transient windows,
handler lifetime/nesting/allwriters/reset/exclusion, startup-to-exit and core
integration remain open. CGA stays behind EGA closure. No DOS game session,
renderer/audio output, full state-machine, gameplay or fidelity acceptance.
Full resources, native Windows gameplay and Amiga work have not started.
