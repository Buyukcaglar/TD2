# Raw handle-close wrapper

`FN-EGA-000310` (`13A8:223E`) takes one SS word. It compares that raw
handle with DS:6DA2 as unsigned. Rejection sets AX0900/CF1 and enters
the shared error tail without a DOS request. Acceptance sets AH3E while
preserving AL and invokes the synthetic DOS boundary. The pinned historical
MS-DOS source identifies service3E as CLOSE.

The adapter explicitly returns GPR/BP/DS/CF/IF/DF and memory effects while
preserving SS/SP/CS control. On success the wrapper clears a byte using the
returned DS and returned BX at wrapped offset `BX+6DA4`. It then returns
AX0/CF0, retaining returned DX. It does not restore or reread the original
handle before that store.

Failure calls the actual frozen `094A` C mapper through its SS near frame.
Normal mapper return sets AXFFFF and uses word CWD for DXFFFF. The tail
executes MOV SP,returnedBP, actual POP BP and plain RETF. Its four-byte far
frame is consumed; the caller cleans the argument. Root minimum SP20
preserves the mapper's minimum SP16. Altered mapper/root returns are exposed
after RET and never followed.

The C17 `/W4 /WX` build passed 32,768 original-x86 comparisons, 628,672
instructions and all 45 wrapper/mapper sites. Full memory, SS, GPR/BP,
CF/IF/DF, service requests, return coordinates and write counts match.
Coverage includes 9,216 synthetic service calls, 22,400 actual mapper calls,
3,392 raw mapper returns and 3,936 altered root returns. Fourteen native
interface diagnostics are separate. Callback memory writes are distinguished
from writes executed by the recovered instructions.

The single caller `0978:09C4` sign-extends byte `[SI+7]` with word CBW,
pushes it and calls this far entry. ADD SP,2 at09C9 cleans the argument and
replaces arithmetic status flags before OR AX/AX and JL. The complete parent,
record schema, handle writers, capacity, ownership, lifetime and interrupt
exclusion remain open. No host stream type or named host error is inferred.

The boundary models the instruction after INT, without real interrupt entry
frames or an actual DOS/file operation. Native budget and adapter failures
remain separate from original rejection/error/return paths. This packet does
not establish DOS-session, renderer, audio, state-machine, gameplay or fidelity
acceptance. CGA remains behind EGA portable code-contract closure; complete
resource decoding, Windows-host gameplay and Amiga recovery retain later gates.
