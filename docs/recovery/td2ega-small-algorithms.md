# Signed clamp, byte ratio and raw label padding

| Entry | Instruction-derived contract |
| --- | --- |
| 06C9:08CB | Two flag masks at DS133C control signed AX/SI/field clamps. Preserve raw field comparisons and last unsigned-comparison carry. Near RET2, no stack argument. |
| 06C9:52FD | Signed-overflow-aware CX-DX branch, then wrapped-word comparisons, AX-BX and AX+5 wrap, byte quotient guard and DIVCL. Final XORAH clears CF on the division path. Near RET2. |
| 0432:0061 | One SS near buffer. Replace underscores during an unbounded scan, then pad while the SS word counter is signed below18. Reread counter and argument after writes; finally write NUL. AX remains unchanged, BX is the final counter, SI/BP restore from actual SS; plain far RETF4 with caller cleanup. |

The label routine pads to a minimum, not a maximum. Strings already at
least18 bytes are retained. A counter that wraps negative can cause padding
through word wrap; buffer/stack aliases can change the counter or pointer.
No host string routine or signed-overflow normalization is substituted.

The clean build-v1/comparison-v1 passed 94,528 cases and 89 executed sites
out of90 ledger sites, with 59,830,272 original instructions. Full bus,
actual SS saves/near-far frames, GPR/BP/CF/IF/DF, counts and control are
compared. There are 89,040 return operations, 5,488 label prefixes, 9,472
byte DIV executions and sixteen completed negative-counter label cases.
Fifteen native rejection/minimum-stack/budget checks are separate.

The block at06C9:5303 is unreachable from52FD: adjacent JLE and JG test
complementary conditions without a flag-changing instruction between them.
Eight separate Boolean cases verify that predicate. A separate 14,848-case
algebraic check proves the byte-DIV guard excludes zero denominators and
overflowing quotients in its admitted3..60 count domain. These checks are
not added to native comparison totals; the block is not declared globally dead.

Sixteen direct caller sites and their immediate post-call windows are
recorded. Some MOV/RET/callee chains propagate flags, so full caller liveness
remains open. Field units/types, real caller bounds, all writers/lifetime,
exclusion and core integration also remain open. No DOS session, device,
renderer, audio, complete state-machine, gameplay or fidelity gate is
established. CGA remains behind EGA portable code-contract closure.
