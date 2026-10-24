# Public segmented heap wrapper

`13A8:26A8` now has a C contract composed with the actual2830 and26F1
families. It accepts one SS count word, saves BP/SI/DI, fixes BX to6F26,
and initializes the raw control/header words when current DS:[6F26] is zero.
The initializer's JNE consumes the required ZF returned by2830. Its failure
path returns AX/DX zero through the actual saved SS words.

Initialization rounds the returned AX with INC AX/AND AL,FE, retaining AH,
and writes through current DS. After the child returns, both the count read
at SS:[BP+6] and the epilogue use the actual returned BP. A verified alias
case changes the child's saved BP to8000: the parent reads the count at8006,
then restores BP and the far-return pair from8000..8004. No initial BP,
argument or return pair is cached across the children.

Before26F1, ES is set to actual DS. The public wrapper preserves that
child's AX-offset/DX-segment or zero pair and CF/ZF through POP/MOV/RETF.
It does not branch on the heap result's ZF. A nonzero allocation with DS
equal to SS can have ZF set. The final CB instruction is a plain far return:
it consumes four frame bytes. The count remains caller-owned; the two known
callers0BF0 and0D66 immediately execute ADD SP,2, replacing arithmetic flags.

The C17 `/W4 /WX` build passed10,992 comparisons, all270 feasible sites
in a299-site family fence, full bus/SS, registers/BP/CF/IF/DF, required ZF,
service requests, control and counters. The29 exclusions retain the literal
2830 fixed-argument proof; standalone2852 covers its complete body.
The comparison includes32 changed-BP argument/epilogue cases. Twenty-two
native interface diagnostics are separate. Earlier v1 passed10,960 cases;
its coverage key `root_near_return` was a label error for actual26ED far RET.
Selected v2 corrects the label and adds the BP cases. C/DLL stayed unchanged.

RS274/275/276 remain raw metadata candidates. This closes the public
initializer body, while all other writers, valid domains, capacities,
ownership, lifetimes, complete0BE8/0C4E callers, interrupt exclusion and
core integration remain open. Synthetic DOS services omit real INT frames;
the serialized20-bit RAM profile does not qualify historical CPU/A20 behavior.
No DOS session, renderer, audio, complete state-machine, gameplay or fidelity
acceptance is established. CGA remains behind EGA portable code-contract closure.
