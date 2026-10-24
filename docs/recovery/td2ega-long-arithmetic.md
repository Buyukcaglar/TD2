# Signed long quotient and remainder

`FN-EGA-000343` (`13A8:2E42`) computes a raw signed long quotient;
`FN-EGA-000345` (`2F1C`) computes the corresponding remainder. Four SS
words hold numerator low/high and denominator low/high. Negative operands
are rewritten as magnitudes in those actual argument words. Quotient sign
combines both operand signs; remainder sign follows the numerator.

The fast path uses two unsigned word DIV instructions. The slow path uses
SHR/RCR pairs to normalize both operands, divides an estimate, calls the
unchanged recovered `2EE8` multiplication C, then compares and corrects
the product. Its source-proven ABI adapter retains AX/BX/CX/DX effects,
real SS frames and saved BP. No host signed-division behavior is substituted.
In particular, raw `80000000 / FFFFFFFF` returns quotient `80000000` and
remainder zero, without creating a host signed-overflow fault.

Both roots and the multiplier use literal RETF 8. The child consumes its
four argument words plus far frame; post-child SP is pre-CALL SP+8. Root
normal SP is entry SP+12. The implementation adds no flag-changing ADD SP
cleanup. Rewritten operands remain visible in the popped argument storage.

The selected C17 build/comparison-v1 passed 140,416 cases, 7,925,630
instructions and all 165 feasible sites from a 170-site ledger. Five
multiplier fast-path sites cannot execute from these parents: a call is
made only with nonzero denominator high word, preserved in the first
operand, and zero second high word. That proof is limited to these parent
guards; the standalone multiplication unit covers its other branch.

Full bus, SS operands/saves/frames, GPR/BP/CF/IF/DF, control and write
counts match. Coverage includes 43,708 actual multiply calls, 1,984 estimate
corrections, 70,208 minimum-SP32 cases, 16,000 seeded random cases and
384 overflow-boundary returns. Mathematical bit patterns are additionally
asserted in the 99,004 completed cases, without adding vectors. Fifteen
native interface/convention diagnostics are separate.

Zero-divisor comparisons stop before the faulting DIV and exception
delivery. The 6,912 fault prefixes occur at the first fast-path DIV.
Successful DIV FLAGS are undefined and unadmitted; other source operations
define CF at admitted prefixes and return. Identical negative remainder
bits can have different fast/slow return CF, which is preserved. Native
budgets before normalization or before a prepared CALL are distinct from
faults and normal returns.

All 17 direct call sites are in `0267:0039`. Their instruction windows
retain argument pools and callee cleanup. In each, returned arithmetic
FLAGS are redefined before reading them, either by the caller or by a
verified neutral callee-entry prefix followed by a flag-setting instruction.
That closes only these direct flag-liveness edges.

The full enclosing caller, argument storage ownership, source C types,
new caller domains, alias lifetime, IRQ exclusion, exception handler and
core integration remain open. No actual exception delivery, DOS session,
renderer/audio output, complete state-machine, gameplay or fidelity gate
is established. CGA remains behind EGA code-contract closure.
