# Plane-byte copy with live SS locals

`06C9:C784` has a bounded C contract for six caller-owned words. It performs
signed SAR3 on the width into an SS local, and writes the shifted source and
destination x words back into the caller's arguments. Source/destination row
lookups use current CS pointers. The source stride derives from literal40;
the destination stride derives from current CS:AF4E.

After setting DS=A000 and executing CLD, four plane iterations each issue
two byte OUTs before reading the current plane word. Zero planes skip copying.
For other planes, the height argument is loaded once per plane; each row
rereads the width local, copies forward, then rereads both stride locals.
SS writes during copying can therefore change later rows and planes.

The row body executes once for zero or negative height. The DEC/JG condition
uses the signed overflow flag:8000 decrements to7FFF with OF set and exits
after one row. A signed width that becomes FFFF is used as the unsigned REP
count65535. The host work budget counts row heads as well as ports and copied
bytes, preserving bounded prefixes even when width is zero.

The C17 `/W4 /WX` build passed3,184 comparisons,449,552 original instructions
and all74 sites. Whole bus, live SS, registers, CF/IF/DF, requests and counters
match. Coverage includes107,500 byte-copy transactions,1,200 DS=SS cases,
four changed root returns,48 pre-RET qualifications,32 final stack-add carry
cases and480 height8000 cases. All36 native checks and static height/SP proofs
remain separate. The four known callers next execute ADD SP,12.

The typed raw RAM adapter owns each byte-copy transaction; the original
MOVSB still executes its idempotent store during comparison. This preserves
forward overlap and the original CPU write/register effects. Actual EGA read
selectors, latches, bus cycles and renderer behavior remain unqualified.
No new resource span or codec is inferred. CS row/plane/stride writers,
caller coordinate bounds, storage lifetime and exclusion remain open.

Historical CPU faults and A20, actual DOS sessions, renderer, audio, complete
state-machine validation, gameplay and fidelity remain separate gates. CGA
recovery remains behind EGA portable code-contract closure. Physical086C
stays unassigned.

Evidence: [comparison](evidence/td2ega-plane-byte-copy-validation-v1.json),
[context](evidence/td2ega-plane-byte-copy-context-v1.json),
[native diagnostics](evidence/td2ega-plane-byte-copy-native-diagnostics-v1.json).
