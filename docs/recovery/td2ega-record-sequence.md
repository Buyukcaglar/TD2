# Record adjustment and selection sequence

`FN-EGA-000127` (`06C9:5ADA`) is a far entry with no SS arguments. It
saves SI/DI/BP through actual SS, calls actual `5B5A` twice with DS record
bases `39A3` and `3813`, then calls actual `5C30` for both arrays. Nonzero
DS:3379 enables two further `5C30` calls using another raw AX/DX pair.

Origins and count words are reread in source order. Selected SI minus
the record base is stored to DS:330E/330C and, on the optional path,
3312/3310. The callee's BP clobber is retained until the parent's actual
POP BP. No sortedness, alignment, valid count, distance unit or capacity
is inferred. `5C30` shifts the count right by three and executes LOOP at
least once: a zero result means 65,536 iterations.

Every child uses a real SS near-call frame and near RET. The parent restores
BP/DI/SI from real SS and uses plain RETF, consuming four frame bytes.
Root minimum SP24 ensures the frozen child minimum SP16. Native parent
CALL budgets and per-child loop budgets stop at different original sites.
Changed child CS/IP/SP is exposed after RET and never followed.

The clean C17 build passed 23,556 original-x86 comparisons, 8,099,480
instructions and all 134 parent/child sites. Full bus, SS saves and
near/far frames, GPR/BP/CF/IF/DF, control and write counts match. There
are 33,356 actual near calls, four complete zero-count selector runs,
512 minimum-SP24 cases, 224 raw child returns and 48 altered root
returns. Twelve native interface diagnostics are separate. No leaf
return-value mocks or excluded SS scratch region were used.

The direct caller `1B2C:1B44` has a recorded instruction window. Its full
state body, field producers, all writers, record bounds, alias lifetime,
interrupt exclusion, other FLAGS requirements and core integration remain
open. This bounded sequence does not establish a complete state machine,
DOS session, renderer, audio output, gameplay or fidelity. CGA remains
behind EGA portable code-contract closure; full resource decoding remains
reserved for its later phase.
