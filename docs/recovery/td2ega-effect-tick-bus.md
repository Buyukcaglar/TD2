# EGA effect callback with actual SS and literal command words

18 October2026. The additional [C17 interface](../../src/recovered/td2ega_effect_tick_bus.h),
[build](evidence/td2ega-effect-tick-bus-build-v2.json),
[16,710 original comparisons](evidence/td2ega-effect-tick-bus-validation-v2.json),
[static review](evidence/td2ega-effect-tick-bus-context-v1.json), and
[22 native diagnostics](evidence/td2ega-effect-tick-bus-native-diagnostics-v1.json)
cover all140 source sites and389,648 original instructions at two relocation
bases. The original6269 entry is counted once; its older interface remains frozen.

6269 takes a far frame and no arguments, with no own saves/CALLs/IF-DF changes.
The new bus interface retains currentDS, inheritedSS, all CPU writes, actual
far words after body effects, GPR/BP/CF/IF/DF and defined arithmetic FLAGS.
150 cases change root coordinates; those actual words are reported and never
followed. NativepreRET qualification after prior effects covers SP>FFFC.

The initial passing16,314-case proposal retained the readonly command mapping.
Its complete C/header/recipe/DLL/object/maker/log artifacts were archived before
literal dispatch was added. V2 keeps every case/assertion and adds396 table
profiles. It reads the currentCS6334 word after NEG/bound/SHL, dispatches by
recognized target offset even when words are swapped, and reports unsupported
targets before632F JMP. There are330 literal-table cases,66 CS-table/SS-frame
aliases, and100 unknown-target prefixes. Source instruction bytes stay immutable.
These profiles do not close the actual all-writers/valid-domain obligation.

The nonzero countdown path compares oldAX against current5EF8 after decrement
and store.1,316 normal returns retainCF1; other normal exits killCF through
byte logic. JS afterDEC tests the result sign, including8000->7FFF. Logic/SHL AF
is masked. SHRAX,CL flags are dead before XORBH, so no observable undefined
shift flags are fabricated. IF/DF remain unchanged in this serialized profile.

SS may alias state, source operands or CS command-table words. CurrentDS can
differ from principalDS. Ordered byte ports can mutate RAM in explicit service
profiles; own CPU writes remain independently counted.634 budget prefixes,
168 preRET qualifications and100 unsupported-command prefixes retain partial
effects and remain distinct from source errors. No elapsed units are assigned.

RS298 records the initialized256-byte raw word envelope5F2E..602D. Positive
notes1..127 consume words1..127; note0 bypasses the first word. The raw words
feed low/high OUT42 bytes. Initialized identity and code footprint do not prove
runtimeDS binding, values/units, format, capacity, ownership, all writers,
storage lifetime or sound output. Payload stays external; full decoding is P2.

Actual6269-first then403B callback-order composition, full403B simulation/mode/
record/nonlocal and byte-source consumption under61BF, realIRQ delivery/nesting,
writers/reset/lifetime/exclusion and core/P1-GATE remain open. Physical086C stays
literal and unassigned. CGA stays behind EGA closure. Full resource decoding,
Windows gameplay and Amiga recovery have not started. No DOS game session,
renderer, audio output, complete state-machine validation, gameplay or fidelity
acceptance is established.

## Actual registration order and both callback bodies

The separate [14,560-case ordered caller comparison](evidence/td2ega-timer-callback-order-v2.json)
executes the original3FD9/601C/614C registration slice to produce6269 followed
by403B and its zero-segment sentinel.32 producer executions cover78 sites and
6,752 instructions; these source-only producer counts are recorded separately
and do not establish native startup or real IRQ delivery. Their resulting
callback rows are preserved while explicit synthetic state fields vary.

Actual61BF then invokes actual6269 and actual403B early/paused bodies. The
native side invokes both recovered C bodies, checks each retired state/frame
and independently counted writes, then executes the C handler continuation.
The original side executes both original bodies and their actual far returns
and handlerIRET. No generic callback RET or C-valued mock replaces these bodies.
The comparison covers2,220,480 original instructions and367 sites, including
all140 effect sites, full1MiB RAM, GPR/BP/CF/IF/DF, defined caller OR flags,
ordered byte ports and CPU/modeledINT writes. Source/native stack data includes
the first callback's register changes and the second callback's actual DI4.

Two relocation bases, distinct/equalSS, SP68/A3CE/E000/FFE0 and DF0/1 are
covered. A3CE remains a static startup candidate rather than an observed
runtime stack.14,560 supplementary cases are excluded from helper totals.
Full403B simulation/mode/record/nonlocal and byte-source consumption under this
caller, oldIRQ delivery/nesting, every writer/reset/storage lifetime/exclusion
and whole-core/P1-GATE remain open. No DOS game session, real devices/audio,
complete state-machine validation, gameplay or fidelity acceptance is inferred.
