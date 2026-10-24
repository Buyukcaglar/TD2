# Current-stream byte reader

`13A8:18B0` increments current DS:[83EE], selects the near stream offset at
current DS:[83F2], decrements its count and tests SF. This preserves the
literal `8000 → 7FFF` fast path despite signed overflow. Count0 and
8001..FFFF take the fallback. The counter remains a raw word with no timing
units or complete purpose assigned.

The fast path reads the cursor into SI, increments the cursor, then fetches
the byte at the saved offset. Pointer aliases can change that byte before
the fetch. SUB AH,AH returns the unsigned byte with CF0/ZF1. The fallback
rereads DS:[83F2], pushes it, and calls actual0B42 with its allocator and
reader family. After a normal child return, ADD SP,2 defines CF0/ZF0 for
the admitted SP domain. Both paths restore SI from actual SS and execute
plain RETF. Ten known callers construct that far frame with PUSH CS followed
by a near CALL. BP has no wrapper-owned save.

The C17 `/W4 /WX` build passed27,528 original-instruction comparisons and
all514 feasible sites in the543-site family fence. The29 exclusions retain
the allocator's fixed parent-argument proof. Whole memory, registers/BP,
CF/IF/DF, root ZF, service requests, counters and control match. Thirty-one
native checks and the16-site static review are separate. Those checks cover
count/counter cancellation, cursor self-aliases, saved SI changing stream
selection, counter writes changing actual far-return words, nested budgets
and propagated reader qualifications.

The first attempt passed its per-case comparisons through profile70000,
then failed an inherited fixture assertion: count8000 correctly bypassed
the allocator. Its exact validator and log are retained. Dedicated child
fixtures now explicitly start at count0; boundary cases retain8000. The
selected comparison uses the unchanged C and DLL.

The ten callers replace arithmetic flags before using them; the first
caller's INC/JE uses newly defined ZF and both continuations then CMP.
RS266 and RS262 gain conditional indirect consumers; no new initialized
resource span is asserted. Actual caller DS/SS/SP, all global and stream
writers, valid indices, storage, capacities, ownership, lifetime, interrupt
exclusion and core integration remain open. Synthetic DOS services omit
real INT frames. CPU/A20 behavior, physical086C semantics, full resource
decoding, a DOS session, renderer, audio, complete state-machine, gameplay
and fidelity acceptance remain open. CGA remains behind EGA code-contract
closure.
