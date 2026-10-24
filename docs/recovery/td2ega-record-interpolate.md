# EGA record interpolation at2477

2026-10-14.FN-EGA-000090 has one
[C17 export](evidence/td2ega-record-interpolate-build-v1.json) and
[864 comparisons](evidence/td2ega-record-interpolate-validation-v1.json), with
actual06C3 in both original and native execution. All130 caller/helper
instruction locations execute.480 cases return normally;384 stop at bounded
work prefixes. Two
[native-only domain checks](evidence/td2ega-record-interpolate-native-diagnostics-v1.json)
are separate.

The function setsES=DS, DF0, BP0 andSI2. It reads current records through
SI/defaultDS and previous records through BP/defaultSS. Equality of their
height words skips the record without updating BP. Otherwise signed SUB/JGE
of the current value and previous running-minimum word controls interpolation;
overflow follows the original flags rather than the wrapped result's sign.

A negative result becomes a wrapped count. The direct-copy branch tests
**CL==1**, not CX==1: a count257 can still copy only six words. The six ordered
current-DS loads/stores retain source/output aliases. Other negative cases
prepare five three-word argument sets from currentDS, previousSS and output
destinations, then copy a word attribute through REP STOSW.

All15 argument words are captured before the attribute output. Five actual
06C3 calls consume them in reverse row order; each near RET6 removes three
words, leaving saved SI for POP. The C preserves snapshots even when attribute
or line writes change source records. Overlapping output rows expose call
ordering, and live stack/frame accounting agrees at normal returns and
prefixes, including inside the self-modifying callee.

The suite includes8,568 RET6 helper calls,312,936 attribute words and202,744
line words. Persistent INC/DEC opcode pairs and their partial write forms are
compared. Source and output share a mutable bus; other live frame/code aliases
are excluded. The native stack is virtual, with SP0140..FFF0 admitted to keep
composed child frames within their own profile. Plain root RET pops two bytes.

21C3 is a reviewed producer of these fields, but actual1F71/2542/268A ordering,
SS/DS correspondence, field/count/output bounds and IRQ/reentrancy/exclusion
still need closure. A synthetic contrast does not establish actual DS=SS.
These tests do not admit complete state/core integration, resource decoding,
renderer/audio output, a DOS session, Windows gameplay or fidelity.
CGA remains behind EGA portable code-contract closure.
