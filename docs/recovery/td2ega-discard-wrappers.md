# Actual nested discard callers

`06C9:0083` reads the current DS words09B4 and09B2, pushes them and calls
actual782C/7490. It drops four argument bytes before its plain far return.
`38D4` similarly reads2F62/2F60, calls782C, then retains those four bytes
while pushing the current2F6A/2F68 words and making a second actual call.
Only afterward does ADD SP,8 remove both argument pairs. Pointer words remain
unchanged by these wrappers; that does not establish a valid later lifetime.

One global call budget covers outer782C calls and nested7490 calls. One search
budget covers all7490 search and trim iterations across both invocations.
Raw child returns are inspected after RET and never followed. Fatal prefixes,
budget prefixes and pre-RET qualifications propagate before normal cleanup.
The full live SS frames and current DS reads preserve aliases at every level.

The C17 `/W4 /WX` build passed4,592 comparisons,187,508 original instructions
and all64 feasible sites of a65-site fence. The remaining site is the prepared
fatal call at74B3, which is explicitly unexecuted. Whole bus, registers,
CF/IF/DF, control and counters match. Coverage includes7,984 actual far calls,
608 DS=SS cases,296 fatal prefixes,16 changed child returns,24 changed root
returns and88 normal final stack-add carry cases. All39 native checks and
static SP arithmetic proofs remain separate.

The known1B2C caller reaches601C, whose60A9 AND replaces arithmetic flags
before a conditional branch. Actual IRQ delivery and exclusion remain open.
Mutable descriptor-pointer writers, object/arena storage bounds, ownership,
lifetime, counter units and fatal cleanup remain unclosed. The underlying
discard APIs and their accepted receipts are frozen and linked as dependencies.

No new media span or codec is inferred. Historical CPU stack faults and A20,
actual DOS sessions, renderer, audio, complete state-machine validation,
gameplay and fidelity remain unqualified. CGA recovery stays behind EGA
portable code-contract closure; physical086C remains unassigned.

Evidence: [comparison](evidence/td2ega-discard-wrappers-validation-v1.json),
[context](evidence/td2ega-discard-wrappers-context-v1.json),
[native diagnostics](evidence/td2ega-discard-wrappers-native-diagnostics-v1.json).
