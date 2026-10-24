# Handler continuation with partially exposed child FLAGS

18 October2026. The additional [C17 entry](../../src/recovered/td2ega_timer_handler_bus_flags.h),
[build](evidence/td2ega-timer-handler-bus-flags-build-v1.json),
[4,570 comparisons](evidence/td2ega-timer-handler-bus-flags-validation-v1.json),
[static liveness review](evidence/td2ega-timer-handler-bus-flags-context-v1.json),
and [nine native diagnostics](evidence/td2ega-timer-handler-bus-flags-native-diagnostics-v1.json)
retain all71 original61BF/6230 sites and241,742 original instructions. The
older handler entry/source/header/DLL remain frozen. Original entries are
counted once. No raw resource or interface identity is added.

Recovered state-register-only children expose CF/IF/DF, while their incidental
arithmetic bits may be unexposed. The new entry accepts maskF72B, retaining
arithmeticCF, IF/DF and the explicitly named system/reserved-bit profile while
excluding PF/AF/ZF/SF/OF. Word0ED7/bit1 and register/flag consistency still apply.
Child prefixes retain this partial mask and actual current/retired coordinates;
the interface does not manufacture missing bits to make composition pass.

For a normal callback, actual621B ADDDI4 defines every arithmetic flag before
the next ORAXAX. The mask regainsFFFF, then logic masks onlyAF. After the oldIRQ
bridge, no instruction consumes those missing bits before the caller's CMP.
FinalIRET reads actual SS FLAGS.96 original-comparison profiles cover partial
retired callback/oldIRQ masks; native diagnostics separately check partial
child prefixes/raw returns and exact flag-regaining at a DI cycle budget.

This remains serialized source/compiled-C evidence. Actual full403B simulation,
mode/record/nonlocal/FN3 consumption under the published caller, realIRQ/nesting,
all writers/reset/storage lifetime/exclusion, core integration and P1-GATE are
open. Physical086C remains unassigned. CGA stays behind EGA closure. No DOS game
session, real-device/audio output, complete state-machine validation, gameplay
or fidelity acceptance is established. Later resource/Windows/Amiga phases
have not started.
