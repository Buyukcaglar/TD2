# EGA signed-motion and low32 multiply contracts

2026-10-13. Complete `06B3:0008` (`FN-EGA-000364`) and `13A8:2EE8`
(`FN-EGA-000344`) have two native exports, a
[C17 build](evidence/td2ega-signed-motion-build-v1.json), and
[423,670 comparisons](evidence/td2ega-signed-motion-validation-v1.json)
against their actual instructions. The motion routine invokes the actual
multiply helper in the original and its native counterpart in C.

2EE8 accepts two32-bit stack bit patterns and returns their low32-bit product
in DX:AX. It returns through RETF8, consuming its four-byte far frame and
eight argument bytes. BX is the second operand's low word. CX is preserved
when both high words are zero; otherwise it contains the wrapped cross-term
sum. The native unsigned32 multiplication preserves the same modulo result.
Seventeen discovered calls remain subject to their individual caller review;
this packet does not automatically accept those callers.

06B3:0008 shifts335A logically by nine, derives a wrapped error from signed
byte30E4 and an arithmetic shift of2F4A, and sign-extends336D before multiplying
by120. Opcode98/99 behavior is16-bit CBW/CWD here, verified against execution;
disassembler CWDE/CDQ labels do not override that operand mode. Native SAR
uses explicit unsigned operations with sign fill, avoiding host signed-shift
or signed-overflow assumptions.

The damping branch uses wrapped16-bit absolute values and signed thresholds.
Absolute8000h remains8000h and can pass the signed bound. That behavior is
preserved. The branch reduces2F4A and2F46 by arithmetic-shift fractions,
conditionally clears the latter and skips the general path's later clamps.
It returns AX0, retains incoming BX and exposes the original local error.

The general path retains unsigned friction multiplication and signed error
correction. Its factor is100h minus the logical30E6>>10, giving193..256 for
any16-bit input. It invokes2EE8 with a sign-extended correction, extracts
product bits8..23 into AX and the high byte into DX, clamps the signed step
to±0A00h, adds it modulo65536 to2F46, then applies the signed±0E80h field
clamps. Addition wrapping occurs before comparison. Numeric constants have
no inferred angle, distance, rate or other physical unit.

Tests include complete low-word domains for multiply fast/cross paths,
32-bit boundaries and varied products, all signed input-byte pairs, wrapped
absolute/damping and clamp boundaries, logical shift/factor boundaries and
varied groups at two load bases. Full group bytes, AX/BX/CX/DX, preserved
registers/IF/DF, original stack locals, product observation and far frames
match. Actual field initialization, caller flag uses, asynchronous state
ownership and the complete simulation remain open. No renderer, audio,
DOS session, gameplay or fidelity is accepted. EGA closure continues to gate CGA.
