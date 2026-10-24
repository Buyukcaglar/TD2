# EGA 3532 and3643 state sequences

2026-10-14. These two roots have one
[C17 export](evidence/td2ega-state-sequences-build-v1.json), with
[972 comparisons](evidence/td2ega-state-sequences-validation-v1.json) and
143/143 root/helper instruction locations exercised. Actual5C98 executes in
both original and recovered native composition. Most other far leaf bodies
remain ABI services, with reviewed plain RETF normal exits.

3532 passesDS:549F to7977, runs its initialization leaves, and retains the
first pair of arguments while calling7DBC thenA718 before ADDSP8. Its outer
DI loop ends at exactly7. BP-indexed count, pointer-table and point reads use
SS:DI+2E22, SS:DI*2+2C9E and SS:BP+SI/+2. The byte counter is written and
decremented through currentDS2E29. A starting zero executes256 iterations
unless a writer intervenes. Independent SS/DS fixtures preserve this split.

The first point word becomes a five-word8582 call argument after SUBAL13,
CBW and SHLBX. The second executes SUBAL13 without another CBW: its AH and
the replacement BH retain the first coordinate's high byte. The C preserves
that asymmetry. Tests cover both sign boundaries and wrapped point offsets;
no geometry, scale or corrected coordinate interpretation is assigned.

After each point sequence, raw BIOS10 block pointer2E08 or2E10 is selected by DI parity.
DI is pushed across7A27/1F99/391F/0094 and restored before incrementing. The
root does not save/restore its incoming BP, SI or DI. Its tail increments
word536C and calls7A55 with raw distance60; timing units remain unassigned.

3643 sets byte2E29 to10 and saves SI **after**7977. It executes actual5C98,
then initializes DI/SI to0. For DI below12, calls80CA andAA12 retain four live
argument words before ADDSP8. Later iterations call9CC2. 808A receives the
currentDS2FD8/2FDA pair and raw240/27 values. DI advances by4, and at24 resets
to12 while SI becomes1. After7A27, the byte counter decrements; zero increments
536E and restores the saved post7977 SI. Both roots use plain RETF.

Services can return changed DS and modeled CF/IF/DF. Counter writers, saved
DI clobbers, returned segments, point arithmetic, loops and exact argument
lifetimes are compared. Native virtual stack frames remain separate from
the bus, so services consume supplied arguments and preserve control frames.
[Five native-only diagnostics](evidence/td2ega-state-sequences-native-diagnostics-v1.json)
are excluded from original comparison/error equivalence. A writer holding
the byte counter away from zero does not become a successful native return.

Actual leaf bodies, SS caller provenance, embedded point/block/resource
bounds, state transitions and asynchronous lifetimes remain P1 obligations.
These comparisons establish neither rendering nor a complete state machine.
No DOS session, audio output, Windows gameplay or fidelity is accepted.
CGA remains behind EGA portable code-contract closure.

The [callee/resource review](evidence/td2ega-sequence-resource-context-v1.json)
corrects the earlier text label: ABFA setsES=DS, AX1002 andDXnearargument,
then invokes BIOS10. The pointer/count extent metadata does not establish
the actual BIOS block read size or decoded graphics.

A separate [288-case platform composition](evidence/td2ega-sequence-platform-composition-v1.json)
executes actual7A10/7A27/7A55/79C8,6A3B, installed69B7 andABFA with these
sequences and5C98. It replaces those body mocks with recovered native callees.
Counter updates and interrupt frames remain synthetic; BIOS10 and remaining
graphics/state leaves remain ABI mocks. This adds no helper-total vectors
and admits no real clock, IRQ, device, renderer or full state machine.
