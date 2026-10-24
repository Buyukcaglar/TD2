# Raw block alignment and retries

`13A8:27D4` saves CX, reads the raw DS[DI-2] word and conditionally adjusts
CX from its low flag bit. It explicitly compares DX with current ES[6F36],
starting from7FFF and shifting right. The ES override and actual saved-CX
alias are retained; this is no fixed global-DS assumption.

Each attempt checks both word additions for carry before complementing and
applying the mask. It calls the actual280E body with real SS frames and
consumes its required ZF. A failed attempt complements the child's actual
returned DX and shifts it before retrying. The implementation does not cache
the mask across that call. Service budgets are shared across retries, while
child call and scan budgets retain their individual scopes.

Normal ZF0 comes from a child success branch; exhausted/overflow paths XOR
AX to zero and return ZF1. The immediate27B8 JE requires that flag. A
successful path can return AX0 with ZF0, so AX cannot substitute for ZF.
The final CX restore and near-return word remain actual SS reads.

The C17 `/W4 /WX` build passed18,128 comparisons,1,107,852 original
instructions and all130 feasible sites in the159-site family fence. The
29 parent exclusions retain the fixed2830 mode1 proof; standalone2852
covers its complete body. Full bus/SS, GPR/BP/CF/IF/DF, required ZF,
requests, control and counts match. Twenty-three native diagnostics and
65,536 static initial-mask checks are separate.

RS275 records the initialized candidate word at6F36, consumed through
actual ES. Its runtime binding, writers, units and lifetime remain open.
Complete26F1/26A8 callers, metadata capacities and ownership, historical
CPU/A20 qualification, interrupt exclusion and core integration remain
open. Synthetic services omit real DOS and INT frames. No DOS session,
renderer, audio, complete state-machine, gameplay or fidelity gate is
established. CGA remains behind EGA portable code-contract closure.
