# Native timer registration tail with actual call frames

18 October2026. The additional [C17 interface](../../src/recovered/td2ega_timer_startup_tail_bus.h),
[build](evidence/td2ega-timer-startup-tail-bus-build-v1.json),
[4,164 original comparisons](evidence/td2ega-timer-startup-tail-bus-validation-v1.json),
[static review](evidence/td2ega-timer-startup-tail-bus-context-v1.json) and
[14 native diagnostics](evidence/td2ega-timer-startup-tail-bus-native-diagnostics-v1.json)
recover3FD9..3FF8, the registration tail of3F40. This is not its earlier
initialization and adds no new original-function identity.

Actual601C and614C C bodies execute under actual inheritedSS farCALL frames.
PUSHCS/PUSHAX supply each callback argument; plain callee farRET leaves it,
then sourceADDSP4 performs cleanup and defines FLAGS. Each retired child
CS/IP/SP is checked before continuation. Full1MiB RAM, GPR/BP/CF/IF/DF,
defined FLAGS, ordered byte ports and independently counted CPU writes match.
All12 root sites and80 admitted union sites execute across433,092 original
instructions. FatalCALL6164 remains a preCALL boundary with its target/stack
retained; the fatal body is not executed.

1,314 cases retire the root,192 report raw child returns,2,570 preserve budget
prefixes and88 stop before the fatal call.1,290 retired cases publish the
expected6269/currentCS then403B/currentCS and zero-segment sentinel.84 root
returns have changed words; they are reported without following. Port-adapter
memory mutations are explicit synthetic profiles, not actual IRQ writers.
Intermediate publication order and unmasked614C remain unchanged.

Earlier3F40 initialization,1C8F/1B2C/main startup-to-exit, all writers/reset/
storage lifetime/IRQ delivery-nesting/exclusion and core/P1-GATE remain open.
Physical086C stays unassigned. CGA remains behind EGA closure. No DOS game
session, renderer/audio output, complete state-machine, gameplay or fidelity
acceptance; full resources/Windows gameplay/Amiga recovery have not started.
