# EGA 403B controller with actual SS and callee bodies

18 October 2026. [C17 interface](../../src/recovered/td2ega_state_tick_bus.h),
[build](evidence/td2ega-state-tick-bus-build-v1.json),
[original comparison](evidence/td2ega-state-tick-bus-validation-v5.json),
[static context](evidence/td2ega-state-tick-bus-context-v2.json), and
[native prefix diagnostics](evidence/td2ega-state-tick-bus-native-diagnostics-v2.json)
establish the bounded whole403B contract. The35 C files and39 headers were
compiled with C17/W4/WX/O2 and remained unchanged through validation.

The25,024 comparisons execute 24,854,592 original
instructions at two relocation bases and all eight stable input branch forms.
All80 root sites and11 root CALL sites are exercised. The caller corpus covers
1249 of 2813 sites in the
recursive callee fence; independent accepted callee contracts retain their own
coverage and qualifications. No all2813-site caller-coverage claim is made.

403B takes a far frame and no source arguments. It PUSHes DS/ES/DI/BP before
loading relocated principal DS/ES, inherits SS, invokes11 possible near CALLs,
then POPs actual BP/DI/ES/DS words and executes plain far RETF. SourceSP46..FFE0
admits the deepest supported mode-child frame. Actual child retired CS/IP/SP
is checked before continuation; changed returns are reported and never followed.
The56ED585A POPAX discards its53A6 return word, and585B near RET already returns
to403B4117. Appending another53A6 RET would corrupt the source convention.

CF/IF/DF, GPR/BP, whole1MiB RAM, control coordinates, root-call counts and CPU
writes are compared. Actual4E27 PUSHF/4E58 POPF storage and actual69B7 code are
included. Undefined AF is represented by explicit0/1 stored-word profiles
after actual PUSHF or at modeled INT entry, without writing EFLAGS in a CODE
hook. Modeled INT frame writes are counted separately. Incoming arithmetic
flags at420A are dead before its first CMP; motion's later full terminal flags
still reach6601. Root CLD is conditional and does not justify a blanket DF0
caller assumption. System-word POPF, unknown targets, divisions and budgets
retain explicit native qualification prefixes, distinct from source errors.

Limits apply per component invocation. The historical field record_calls is
the record child iteration limit; root_calls alone counts the parent's CALLs.
The earlier harness charged parent4117 CALL to child record_steps, and its
exact failed maker is retained. The24,768-case v4 run matched every comparison
but correctly failed the nonlocal coverage gate. A64-case independent probe
established actual585A/B producers, then v5 retained all old cases and added
256 comparisons across all forms/loads. Separate6824 early-path probes and
28 native prefix checks are excluded from helper-vector totals.

No directCALL403B is present in the selected graph. Actual3F40 registration
publishes far6269/currentCS then403B/currentCS;61BF walks far callback pairs.
The prior removal review proves sentinel effects under bounded serialized
profiles. Actual handler-to403B composition, feasible IRQ delivery, nesting,
all near-table/resource writers, source resets/interleaving, storage lifetime
and core integration remain open. Key callback bodies remain typed ABI effects
plus synthetic far RETs. Transitive resource consumers retain raw-data scope.
The BSS942E counter and literal physical086C read have no assigned timer units.

CGA stays behind EGA portable code-contract closure. Full resource decoding,
Windows gameplay and Amiga recovery have not started. No DOS game session,
real BIOS/device/IRQ delivery, renderer, audio output, complete state-machine
validation, gameplay or fidelity acceptance is established. P1 remains open.

## Actual handler caller: early and paused paths

The separate [12,800-case caller comparison](evidence/td2ega-timer-state-tick-prefix-v2.json)
executes actual61BF, actual403B/412C, paused420A with modeledINT16 and actual69B7,
5A6F/control helpers, actual403B far RET and the caller's actualIRET. It compares
the full1MiB bus, GPR/BP/CF/IF/DF, defined caller-OR flags and all CPU/modeledINT
writes across two loads, distinct/equalSS, SP68/A3CE/E000/FFE0 and DF0/1. All256
3368 bytes and paused1/2/4 profiles produce227 exercised sites and1,570,592
original instructions. Actual403B receives the caller's IF0/real far frame and
returns its actual saved words. Unexposed child arithmetic bits are dead at
the immediately following621B ADDDI4; no full child-FLAGS claim is inferred.

The403B-only callback row is synthetic. This does not prove the actual6269-first
registration order, complete simulation/mode/record/nonlocal paths under61BF,
shared byte-source consumption/reset/lifetime/exclusion, nested IRQ delivery,
or whole-core feasibility. A3CE is a static startup stack candidate, not an
observed runtime stack. These12,800 supplementary cases are excluded from
helper totals and do not close P1 or any runtime/gameplay/fidelity gate.

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
