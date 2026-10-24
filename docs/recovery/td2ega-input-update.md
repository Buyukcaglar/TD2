# EGA composed input-update contract

2026-10-13. Complete near `06C9:420A` (`FN-EGA-000367`) has one native
export, a [C17 build](evidence/td2ega-input-update-build-v3.json) linking nine
recovered C translation units, and
[571,392 comparisons](evidence/td2ega-input-update-validation-v3.json).
The original caller and thirteen callee entries execute actual instructions;
the native composition calls their recovered C. BIOS, port201 and far callback
bodies remain explicit synthetic adapters.

When33D4 is zero, the routine obtains direction bits through6620, stores33B1,
translates through6828 and consumes the pushed argument with POP BX. That
POP is not a restore of incoming BX. Button bits are included only on the
original90A8 path, and the resulting AL is published to33B0.3352 increments
modulo65536. The unsigned0960h threshold and input/activity branches retain
their original counter reset and5490=FF publication order; no time unit is
assigned to the counter.

4281 updates control state and clobbers BP with its initial332C word.43C3 is
called only when the then-current3365 is nonzero.448A publishes the eight-byte
signed sum and copied52CE value while leaving AX=52CE, BX8 and DX=sum. The
composition preserves these scratch outputs before invoking06B3:0008 and
its callee-clean2EE8 multiply helper. These details matter to the later
BIOS request and are not discarded as incidental state.

A nonzero33D4 skips that initial chain. Both paths then call6601, preserving
its explicit DS=SS key-consumption gate. A nonzero returned AX with the selected424A/4275 branch-form condition
sets5490=FF. The final44A6 scan reads ES bytes and DS target words separately.
Its AX0 shortcut preserves DF; otherwise it ends DF0. Native results expose
AX/BX/CX/DX/BP/DI/IF/DF rather than assuming all caller registers survive.

Fixtures cover pause branches, both DS/SS and DS/ES relationships, idle wrap,
busy callbacks, every direction mask and varied field states at two load
bases. Ordered adapter events, full nonstack group state, independent ES,
registers and near/far frames match. When DS=SS, the72-byte live/historical
stack span is checked through frame and register witnesses separately from
the other65,464 group bytes. The test uses the actual thirteen callee entries,
not return-value mocks for the arithmetic/control routines.

Actual callback bodies, table writers, field/resource initialization and the
403B caller's IRQ/lifetime ownership remain open. The byte ring780E is neither
called nor integrated here. This isolated composition is not a complete
state-machine test, portable game core, BIOS/input/device session, renderer,
audio output, gameplay or fidelity acceptance. Full EGA closure still gates CGA.

The branch-form interface introduced in version2 requires an explicit `td2ega_mutable_control` input. At42AD, the
initial JA skips the early reset when8A9A>1; prepared JNE skips it when8A9A!=1.
At424A/4275, initial JBE suppresses stateFF for8A9A<=1; prepared JNE
suppresses it for8A9A!=1.43C3 is unchanged. Both42AD forms and all eight
root combinations are compared using separate original-code instances. Only
initial0/0/1 and prepared2/2/2 are established stable mutator outcomes; mixed
forms do not prove transition reachability. Unsupported native forms return
diagnostic2 before field writes. The [initial-only version1 history](evidence/td2ega-initial-input-contract-history-v1.json)
preserves exact archived sources/scripts/recipes and frozen old receipts.

The latest BIOS response contains AX/ZF/IF/DF. All responseflags mustbe0/1;
returnedIF/DF propagate before subsequent input/control calls. The comparison
retains historicalpreserving, AH1IF1 andsyntheticDF-toggle profiles. Exactolder
[IF/DF-preserving contract history](evidence/td2ega-bios-flag-contract-history-v1.json)
is archived withfrozenreceipts. [2,876 separate installed-handler compositions](evidence/td2ega-installed-keyboard-poll-v1.json)
executeactual65C5/6601+69B7 andnativeinput/keyboard code, confirmingAH1IF1
withouta realBIOS/keyboard/IRQ/inputsession. That poll-onlyrecord isseparatefromthelaterrootcomparison below; neither
closes callback/resource/fullstate domains.

[9,984 separate root/installed-handler comparisons](evidence/td2ega-installed-keyboard-update-v1.json)
nowexecute420A,13actualcalleeentries and69B7, withnativeinputupdate/keyboard
C composition. Initial/preparedstablebranchforms, paused/activity/DS-SS/ES
profiles andmissingcallback/disabledgameport areexplicit; actualIRQ/nesting,
callbackbodies, fullmutatortransitiongraph/resource/state/game acceptance remainopen.
