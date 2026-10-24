# Actual fill and sprite caller chain

The [comparison receipt](evidence/td2ega-fill-sprite-composition-v1.json)
records3,072 synthetic26D8 roots with actual recovered89A2 and all four916C
children. The original executed2,809,712 instructions and966 of3,006 locations
in the conservative shared-body fence. This is scoped coverage, not an
all-path claim. There were3,072 rectangle calls,12,288 sprite calls,672 actual
near mask calls and1,536 copy dispatches. The15,360 far boundaries retain
the original5-word rectangle arguments and16/12/8/4 live sprite argument pools.

The bridge materializes every child far return and prepared argument word
in shared SS memory before invoking its recovered C body. The comparison
checks argument pools and boundary registers, actual sprite far-return words,
the root's plain near return, returned GPR/BP/CF/IF/DF and all bus bytes outside
128 private SS scratch bytes. That exclusion covers the outer root's virtual
argument-pool implementation; the standalone sprite receipt separately
compares its complete SS frame. It does not admit stack/output aliases.

Synthetic profiles cover two load segments, shared/separate DS and SS, four
plane configurations, four source-header forms, three vertical positions,
four horizontal positions and incoming CF/IF/DF combinations. They match
31,488 byteOUT events,57,024 device reads and52,416 device writes. The adapter
is a flat synthetic bus; it does not model or establish actual EGA latches.

Only normal child outcomes enter this composition. Divide faults, budgets
and raw unsupported transfers retain separate helper receipts. These vectors
are excluded from helper-suite totals. Actual producers, all writers, source
ownership, bounds, lifetimes, interrupt/reentry exclusion and complete state
transitions remain open. No supplied-resource decode, actual DOS session,
renderer, audio, gameplay or fidelity acceptance follows. CGA remains behind
EGA portable code-contract closure.
