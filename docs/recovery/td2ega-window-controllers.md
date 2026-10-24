# Threshold-window writes and a conditional near call

The earlier `4AFA` group-view translation and receipts remain frozen.
This packet adds actual SS/return and defined-flag coverage; only `4B5D`
adds a new unique original entry.

`4AFA` writes center=`52CC+40`, lower=`center-90` and upper=`center+90`,
with word wrap, before reading signed CL from `3371`. Negative CL values
return after those writes. CL1 can clamp52CC to560 while later tests retain
the original center. The marked CL1 path selects state1 using different
flags from the ordinary state1 path. CL2 selects4; the other admitted paths
select1 or9 with signed word comparisons. The translation retains these
branch and flag differences.

`4B5D` loads AL while retaining AH, decrements AL and tests its low nibble.
Only raw input bytes1,17,..241 admit its guards. It tests a center of -500
or -900, then +500 or +900 if necessary, through actual `4D26` and its
real SS frames. A successful guard makes an actual near CALL to `4A2E`.
That extra frame is preserved; this entry does not tail-jump to the byte
source. A failed gate or guard consumes no source byte.

[57,568 comparisons](evidence/td2ega-window-controllers-validation-v2.json)
cover both entries and their actual guard/control/setter/ring family at
two load addresses, across all185 sites. Whole RAM, registers/BP, CF/IF/DF,
root ZF, CALL budgets and actual return coordinates match compiled C17.
[337 native checks](evidence/td2ega-window-controllers-native-diagnostics-v1.json)
and [static review](evidence/td2ega-window-controllers-context-v2.json)
are separate. The first57,488 comparisons matched but lacked the inherited
negative-state7 site; 80 added boundary cases close that gap. C and DLL
are unchanged, and the earlier validator/log are retained.

Writes can alter a real return address. The composed `4A2E` can return
to a changed near IP through its byte/word state writes or indexed late
writer. The parent reports that completed return and does not continue at
4B99. Actual child far/near aliases and changed saved SI are also retained.
Entry0 admits SP0..FFFE, including near-RET SP wrap from FFFE to0. Entry1
requires SP22..FFE0 so the child enters with at least20. These are bounded
ABI domains, not a qualification of every historical CPU stack behavior.

The graph finds `4AFA` callers46B0 and48A2, and `4B5D` caller48A5.
Their continuations replace arithmetic flags before use. Actual caller
DS/SS/SP, all field writers, shared-source reset/seed, storage lifetime,
IRQ scheduling and core integration remain open. RS271 records the direct
window writes; inherited source/table writer relations remain conditional.
No new resource span or supplied-resource decoding is claimed.

No DOS game session, renderer, audio output, complete state machine,
gameplay or fidelity acceptance is established. Physical086C remains
unassigned. CGA stays behind EGA portable code-contract closure; full
resource decoding, Windows gameplay and Amiga recovery have not started.
