# EGA BIOS and direction-input wrappers

2026-10-13. Complete `06C9:65C5`, `6601` and `6620`
(`FN-EGA-000155/000410/000411`) have three native exports. The
[C17 build](evidence/td2ega-input-poll-build-v2.json) links the reviewed
[dispatcher](td2ega-key-dispatch.md) and [gameport](td2ega-gameport.md).
[24,630 comparisons](evidence/td2ega-input-poll-validation-v2.json) execute
the original wrappers and actual helper instructions; BIOS, port responses
and far callback bodies are explicit synthetic adapters.

65C5 probes INT16/AH1. If a key is available, it reads with AH0 and calls6528.
Otherwise it samples6686. Any returned button bit30h maps to000Dh; other
results select a word at6254+2*(result&F). Equality with6274 suppresses the
return to AX0. A changed word is stored at6274 and returned. Disabled gameport
can still feed this mapping; a zero raw result is not an unconditional bypass.

6601 probes first and returns AX0 when empty. With a key pending, it loads
BX=SS and CX=DS. It consumes and dispatches the key only if those segments
are equal. Otherwise it returns the probe AX without reading the queued key.
This condition is preserved explicitly; DS=SS is not imposed on unrelated
analysis ranges or callers.

6620 ORs masks from ten nonzero group bytes, returning the resulting word:

| Byte | Mask | Byte | Mask |
| --- | --- | --- | --- |
| 62F3 | 10 | 62D6 | 20 |
| 6301 | 09 | 6302 | 01 |
| 6303 | 05 | 6307 | 04 |
| 630B | 06 | 630A | 02 |
| 6309 | 0A | 6305 | 08 |

Only a zero result calls6686. All1,024 boolean masks are tested with three
nonzero byte values, both DS/SS relationships and two load bases. Other
fixtures cover BIOS high/low-byte domains, guard state, callback returns,
empty/available queues, gameport button combinations and repeated mappings.

Ordered service requests/results, helper invocation counts, AX/BX/CX/DX,
IF/DF, far returns and preserved registers match. Where DS=SS, the bulk
group comparison excludes the72-byte live/historical stack span around SP;
far frames and the private pushed/masked key argument are checked separately.
Other65,464 group bytes match. For independent SS, all65,536 group bytes match.
Native code retains shared field views while the original stack witnesses
remain separate evidence, not emulated host stack storage.

The current BIOS adapter preserves nonresponse registers and returns explicit IF/DF. Actual
BIOS/keyboard handler state, callbacks changing segments, physical gameport
timing, IRQ schedules and every caller remain open. No DOS game session,
renderer, audio, gameplay or fidelity is accepted. Full EGA code closure
continues to block CGA.

The latest BIOS response contains AX/ZF/IF/DF. All responseflags mustbe0/1;
returnedIF/DF propagate before subsequent input/control calls. The comparison
retains historicalpreserving, AH1IF1 andsyntheticDF-toggle profiles. Exactolder
[IF/DF-preserving contract history](evidence/td2ega-bios-flag-contract-history-v1.json)
is archived withfrozenreceipts. [2,876 separate installed-handler compositions](evidence/td2ega-installed-keyboard-poll-v1.json)
executeactual65C5/6601+69B7 andnativeinput/keyboard code, confirmingAH1IF1
withouta realBIOS/keyboard/IRQ/inputsession. That poll-onlyrecord isseparatefromthelaterrootcomparison below; neither
closes callback/resource/fullstate domains.

[9,984 separate root/installed-handler comparisons](evidence/td2ega-installed-keyboard-update-v1.json)
nowexecute420A,13actualcalleeentries and69B7, withnativeinputupdate/keyboard
C composition. Initial/preparedstablebranchforms, paused/activity/DS-SS/ES
profiles andmissingcallback/disabledgameport areexplicit; actualIRQ/nesting,
callbackbodies, fullmutatortransitiongraph/resource/state/game acceptance remainopen.
