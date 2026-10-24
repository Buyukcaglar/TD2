# Callback metadata with actual SS and publication prefixes

18 October2026. The additional [C17 entry](../../src/recovered/td2ega_timer_callback_bus.h),
[build](evidence/td2ega-timer-callback-bus-build-v1.json),
[10,392 comparisons](evidence/td2ega-timer-callback-bus-validation-v1.json),
[ABI/publication review](evidence/td2ega-timer-callback-bus-context-v1.json) and
[22 native diagnostics](evidence/td2ega-timer-callback-bus-native-diagnostics-v1.json)
retain614C/6180 actualSS arguments/savedBP/farwords, full1MiB RAM/GPR/BP,
CF/IF/DF and defined FLAGS. Old typed interfaces/sources/DLLs are unchanged;
both original entries are counted once.46 instruction sites execute across
257,058 original instructions; fatalCALL6164 is separately a preCALL boundary.

614C scans five current segment words. At a zero segment, it reads the offset
argument, stores it, clears the segment, rereads the segment argument, publishes
it, then clears the following segment. Earlier writes can alter the second
argument. No CLI/STI or atomic operation is added.60 original/native IF1 prefix
witnesses stop before6179, after6176 published the segment while the next stale
segment remains nonzero. These establish an intermediate source state; they
do not prove actual IRQ feasibility or a historical failure. Caller exclusion
and handler lifetime remain open.

Five occupied rows produceAX5FE8/PUSHAX before farCALL16A7:0002.1,322 prefixes
retain this stack state and relocated target without executing the fatal body
or inventing a normal error return.6180 captures both arguments before scanning,
matches offset then segment and can match a zero-segment row. A match executes
CLI, shifts remaining words in source order, clears the last pair and STI; it
enables IF even if inputIF was zero. An unmatched search preserves IF.

The corpus includes3,312 actualSS alias cases,216 changed root returns and192
qualified preRET stops. Budget heads at each metadata store preserve visible
publication prefixes. The source far return reads actual words afterPOPBP;
arguments remain for caller cleanup. Native diagnostics are separate from
original comparisons and real scheduling.

Native3FD9 startup producer, complete startup-to-exit/fatal bodies, every writer/
reset/storage lifetime/IRQ nesting/exclusion and core/P1-GATE remain open.
Physical086C remains unassigned. CGA stays behind EGA closure; full resources,
Windows gameplay and Amiga recovery have not started. No DOS game session,
renderer/audio output, complete state-machine, gameplay or fidelity acceptance.
