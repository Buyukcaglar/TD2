# Raw block metadata tail

`13A8:280E` calls the actual2830 wrapper and consumes its explicit ZF.
It retains real SS saves and the nested near/far call frames. A set ZF
skips the metadata body. Otherwise it saves DI, computes SI from the actual
child AX/DX, performs three ordered word stores, subtracts DI and decrements
DX. DEC supplies returned ZF while preserving subtraction carry. POP AX
reads the actual saved DI word; POP CX/DX read the root saves.

The27AD and27FF callers immediately use ZF through27B0 JE and2802 JNE.
The27A1 caller instead executes CMP AX,SI before its conditional branch.
`zero_flag` is valid only after a completed root near RET. Diagnostic
prefixes and changed child returns do not expose an admitted root ZF.

The C17 `/W4 /WX` build passed27,408 comparisons,676,102 original
instructions and all101 feasible sites in the130-site family fence.
The29 parent exclusions retain the existing fixed-mode1 argument proof;
the standalone2852 packet covers its complete body. Full bus/SS, GPR/BP/
CF/IF/DF, required ZF, request ABI, control and write counts match. Twenty
native diagnostics are separate.

The initial comparison encountered Unicorn's unmapped high linear data
address. The declared serialized20-bit bus now uses two guest views of
one1MiB host allocation, without a memory-read hook. Five separate mapping/
ISA checks verify alias visibility and a word store crossing FFFFF into
address zero. A native diagnostic also checks that crossing store. This
selects an analysis profile; historical CPU, A20, segment limits and hardware
bus cycles remain unqualified. Distinct opcode forms use fresh emulator
instances. The C and compiled DLL did not change during the fixture repairs.

Complete26F1/27D4/26A8 callers, metadata writers, valid domains, capacities,
storage ownership, lifetime, interrupt exclusion and core integration remain
open. Synthetic DOS services omit real INT frames. Raw return targets are
exposed after RET and never followed. No DOS session, renderer, audio output,
complete state-machine, gameplay or fidelity acceptance is established.
