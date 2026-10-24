# Current-DS near string scan

`FN-EGA-000329` (`13A8:29B4`) accepts one SS word naming an offset
in the current DS view. It sets ES=DS, AL=0 and CX=FFFF, then uses
REPNE SCASB without clearing DF. DI wraps as a word in either direction.
NOT CX / DEC CX / XCHG CX,AX computes the returned count; CX ends at zero.
DX receives the incoming DI, which is restored. The saved BP lives in SS.
The plain far return consumes four frame bytes; the caller cleans its argument.

The count is bounded at 65,535 comparisons. A NUL in the final eligible
position and no NUL in that span both yield AX=FFFE. Their last comparison
carry differs: zero for the matching NUL, one for no match. This is retained
without inventing an error or substituting host `strlen`.

The native C17 build and 896 original-instruction comparisons cover all 15
instruction sites and 6,310,336 executed instructions. Fixtures use two
relocations, separate/equal DS and SS, both DF values, word-offset wrap,
terminator positions and missing terminators, and before-scan diagnostic
budgets. Full memory including the BP save, caller frame, argument and guard,
GPR/BP/CF/IF/DF, scan counts and far-return coordinates are compared.
There are 320 far returns and 576 diagnostic prefixes. Eight invalid native
interface checks are recorded separately.

Static caller candidates are recorded in the context receipt. Actual caller
capacity/NUL/DF/other-FLAGS requirements, DS/SS correspondence, all writers,
lifetime and core integration remain open. These checks establish no actual
DOS session, device, renderer, audio, complete state machine, gameplay or
fidelity acceptance. CGA remains behind EGA portable code-contract closure.
