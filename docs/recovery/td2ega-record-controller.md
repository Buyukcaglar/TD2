# Record controller and saved FLAGS

`FN-EGA-000387` (`06C9:4D3F`) is a near entry with no SS arguments.
Its two do-once loops update raw eight-byte records under DS. The first
subtracts DS:8432 from a low word, increments CH only on borrow, and
decrements the high word. The second adds the low word, tests CH, then
decrements CH only and increments the high word. Source comparisons and
wrap adjustments retain their signed or unsigned conditions. Angle words
move by 20 with literal clamps -600/-200 and 200/600. These are raw values;
no physical unit or record type meaning is assigned.

Each loop rereads its end word at the tail. Zero and unaligned ends retain
their original wrap or cycling behavior. A native work budget stops before
the next loop iteration or CALL. All ten possible near calls execute the
frozen `4F92`, `5022` and `5446` C bodies, including their real SS frames,
register clobbers, record writes and near returns. The root minimum SP20
preserves the frozen child minimum SP16 even with PUSHF outstanding.

The first `4F92` return feeds PUSHF at `4E27`. The source-defined flag view
supplies its known bits; the caller supplies AF as 0 or 1 when XOR leaves
AF undefined. This analysis CPU profile sets bit1 and clears TF, IOPL, NT
and reserved high bits. It establishes no historical CPU policy for those
bits. The saved word remains in actual SS. POPF at `4E58` rereads it after
all intervening writes, and the following JNE consumes the restored ZF.
The other three JNE consumers also use the actual child ZF.

Aliases matter before and after the child call. In explicit fixtures:

- Root SP52DE, SP3350 and SP52E0 overwrite the child near-return word;
  the altered return is exposed before POPF and its target is never followed.
- Root SP334E and SP3356 preserve the child return but leave FF9C or
  47A5 at the flag slot. Native status5 stops before POPF because the
  resulting TF/IOPL/NT context is unsupported. No trap or mode effect runs.
- Root SP52DA with an initial zero root target and the selected raw pair
  leaves 0040 at the flag slot. POPF consumes the changed ZF/IF/DF. The
  root later exposes its altered FFE6 return target after the actual RET.
- SP33BA affects the first child's byte33B9 guard through its CALL frame;
  that changes the earlier path. It cannot be treated as a private flag slot.

The C17 `/W4 /WX` build passed 18,752 comparisons, 5,604,720 original
instructions and all 335 root/child sites. Full memory, SS, GPR/BP,
CF/IF/DF, defined normal-return FLAGS, control coordinates and write/call
counts match. Coverage includes 26,624 actual near calls, 6,720 PUSHF
words, 9,312 minimum-SP20 cases, 48 raw child returns, 16 altered root
returns, 16 supported flag-slot aliases and 32 boundaries before unsupported
POPF. The 520 AF1 cases explicitly stimulate an ISA-undefined bit in the
original model; they do not identify a real CPU's AF choice. Fifteen native
interface diagnostics are recorded separately.

The direct caller is `403B:4117`, followed by a call to `595F`. Its complete
FLAGS liveness, DS/SS setup, storage bounds, all writers, interrupt exclusion,
CPU-profile binding and core integration remain open. No private SS region
or leaf return-value mock was used. This packet does not establish a complete
state machine, DOS session, renderer, audio output, gameplay or fidelity.
CGA remains behind EGA portable code-contract closure; resource decoding,
Windows-host gameplay and Amiga recovery retain their later gates.

The later [pair-controller review](td2ega-pair-controller.md) closes the
local arithmetic-status liveness question: actual595F starts with XOR BP,BP,
before any status read. IF/DF and the complete403B caller remain open.
