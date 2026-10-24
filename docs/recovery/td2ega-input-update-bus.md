# EGA whole420A with actual SS and interrupt FLAGS storage

18 October2026. The additional [C17 interface](../../src/recovered/td2ega_input_update_bus.h)
composes near420A and14 actual original callee bodies. The
[build](evidence/td2ega-input-update-bus-build-v2.json),
[91,808 comparisons](evidence/td2ega-input-update-bus-validation-v3.json),
[static review](evidence/td2ega-input-update-bus-context-v1.json) and
[29 native diagnostics](evidence/td2ega-input-update-bus-native-diagnostics-v3.json)
cover all663 admitted sites and 20,696,482 original instructions,
at two load addresses and all eight stable branch-form combinations.
The same original entry is counted once. Older group interfaces remain frozen.
No resource span is added. Result is68bytes; sourceSP24..FFE0 admits actual
DS-independentSS frames and memory aliases without a live-stack exclusion.

The root has37 instructions, four near CALLs, four far CALLs and a plain near
RET. Its actual callees preserve their near/far frames, plain RETF versus
multiply RETF8, installed69B7 IRET versus RETF2, register effects, source reads
after aliased writes and retired return coordinates. Each child is checked
before continuation. 4219PUSHAX supplies the6828 argument;421FPOPBX consumes it.
The final near root word is reported even when changed and is never followed.

Motion's full terminal SUB/CMP FLAGS word feeds6601 before its MOVAH1/INT16.
The CMP operand is captured before a lower clamp writes it back. Modeled INT16
writes FLAGS,CS,nextIP and executes actual69B7; its frame writes are counted
separately from source CPU hooks. Undefined AF uses explicit0/1 storage profiles;
no CODE hook rewrites EFLAGS. Motion's incoming arithmetic bits have no consumer
before its first SUBSP4 defines them. Other field/scanner interfaces expose
CF/ZF/IF/DF and conservatively mask unexposed arithmetic flags.

Typed key callbacks remain explicit ABI effects plus private generic RETF,
with synthetic returns excluded from original-instruction counts. Their real
bodies/UI callees remain open. Port201 responses and interrupt delivery are
synthetic serialized profiles. No real IVT ownership or device/IRQ history is
inferred. Native budgets, failed adapters, unqualified returns and unknown
scanner targets are diagnostic prefixes, distinct from original errors.

The first new bus build reversed the prepared JNE skip conditions. Full
comparison caught an extra write that a prior identical publication could hide
in final RAM. Both424A/4275 conditions were corrected and a fresh build made;
the failed source/header/recipe/DLL/objects/makers/logs are retained. All91,312
v2 comparisons then matched but covered645 sites. An independent124-case probe
matched the18 missing sites. V3 retains all previous cases/gates and adds31
rare profiles across every form/load: manual mode2/action33AF, large byte MUL,
port timeout and candidate-countdown flush. Compiled C/DLL bytes stayed fixed
through the coverage refinement.

The [counter review](evidence/td2ega-input-update-bus-counter-review-v2.json)
qualifies two inherited names: `root_RETF` counts82,528 actual near root RETs;
`actual_far_calls` counts574,424 aggregated direct near and far CALLs. There
are15 direct CALL sites across the composition:8 near and7 far. A dynamic
far-only total is unavailable. The3,808 near callback CALLs are separate.
There are2,112 raw child returns,448 changed near root words,7,072 budget
prefixes and96 unknown scanner prefixes. These are bounded fixture results.

RS271 andRS291..297 are transitive raw consumer views conditional on actual
DS/ES/SS and caller bindings. They do not establish formats, ownership,
capacity, all writers, lifetime or exclusion. Full403B, actual callback bodies,
startup/resource lifetime and P1-GATE remain open. Physical086C is unassigned.
CGA stays behind EGA portable code-contract closure. No DOS game session,
renderer, audio output, complete state-machine validation, gameplay or fidelity
is established. Full resource decoding, Windows gameplay and Amiga recovery
have not started.
