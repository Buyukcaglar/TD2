# Block wrapper and required ZF

`13A8:2830` takes raw size in AX, a segment key in DS and metadata DS in
ES. It forms five SS arguments for the actual2852 far call, changes DS
through PUSH ES/POP DS, and retains the real near/far stack frames. ADD
SP,8 consumes four arguments; the fifth becomes the actual DS restore.
POP DX reads saved AX, and POP BX reads saved BX.

The wrapper compares the child's DX with FFFF before those pops. Failure
keeps that comparison's ZF1 and skips OR DX,DX. Other paths set ZF from
actual restored DX. Both normal paths return CF0. The immediate callers
at26BD JNE and2813 JE require ZF, so the C result explicitly exposes
`zero_flag` with `flags_valid=1` on completed root returns. Diagnostic
prefixes and changed child returns leave `flags_valid=0`.

The literal argument frame fixes mode1 and the zero high-word guard before
any service. Distinct prologue stack writes cannot change those words.
Consequently24 of the parent's53 sites are feasible here; the remaining
29 have an entry-specific disposition. The standalone2852 packet covers
its complete body. This wrapper composition contains83 feasible sites in
the112-site family fence.

The C17 `/W4 /WX` build passed21,104 comparisons,755,270 original
instructions and all83 feasible sites. Full bus/SS, GPR/BP/CF/IF/DF,
required ZF, requests, control and write counts match. Coverage includes
11,888 far calls,7,280 nested near calls,2,422 synthetic DOS4A services,
822 changed child returns and530 changed root returns. There are2,608
failure cases with nonzero restored DX and226 success cases with zero
restored DX. Twenty native diagnostics are separate. The earlier passing
comparison had an ambiguous DS label; v2 distinguishes metadata DS=SS
from initial DS=SS and adds direct saved-AX mutations. C/DLL stayed unchanged.

Complete26A8/280E callers, all metadata writers, valid domains, capacities,
ownership, lifetime, interrupt exclusion and core integration remain open.
Raw targets are exposed after RET and never followed. Synthetic services
omit real DOS and INT frames. No DOS session, renderer, audio output,
complete state-machine, gameplay or fidelity gate is established.
