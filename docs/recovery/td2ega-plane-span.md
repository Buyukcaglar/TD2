# Plane RAM helper and explicit near continuation

`06C9:0C17` and `0D01` passed9,504 synthetic comparisons against compiled
C17. All100 owned-body instruction locations were exercised:8,488 near
returns and1,016 discarded-near-return jumps,782,472 original instructions,
502,848 plane byte writes and1,600 far8582 ABI calls. These are RAM bus
effects with synthetic plane segments; no EGA device or renderer was run.

`0C17` compares signedAX against currentDS9C0, updates the raw extent and
selects four palette bytes. Its mask lookup at `[BP+5468]` defaults to **SS**.
The plane segment words and palette fields use currentDS. The initial C
translation usedDS for that mask and failed an independent DS/SS fixture.
Its source/header/DLL are retained privately. Buildv2 contains the corrected
SS read; the selected comparison pins that DLL. A separate instrumentation
correction changed a REP write-count hook address; it did not change C.

The body performs four ordered masked point writes, then optional repeated
bytes through four reread plane segment words. Saved first-plane ES is reused
for its REP. CH is cleared before the REP count, retaining only CL. DF is
preserved, so the four runs support either direction; DI arithmetic wraps
as a word. Data-plane aliases with palette/extent fields retain their original
read/write order. Live SS control frames remain separated in these tests.

When the terminal subindex equals8, the body clears9BE and advancesDI. If
the reread extent equalsDS5348, it restores savedSI, discards the original
near return address and jumps through currentDS0702. Native status1 returns
that raw nextIP and the resultingSP. Native status0 means an ordinary near
RET. Arbitrary synthetic target values test transport only: the admitted
writer/reachability domain remains open. Candidate graph ranges also contain
0Bxx/28xx caller continuations; the recovered0C17 body stops at its JMP
boundary and does not claim those ranges as one ordinary returning function.

`0D01` compares signedDX/AX and either returns or pushes five words for an
ordinary far8582 service call, then caller-cleans10bytes and near-returns.
The leaf remains an ABI mock. No physical size, mask-table capacity, resource
format, caller producer/lifetime, exclusion, complete state machine or core
acceptance follows from these tests.

[Buildv2](evidence/td2ega-plane-span-build-v2.json),
[comparison](evidence/td2ega-plane-span-validation-v1.json), and
[native checks](evidence/td2ega-plane-span-native-diagnostics-v1.json).
No actual DOS session, hardware/IRQ delivery, graphics/audio output, gameplay
or fidelity acceptance. EGA contract closure still precedes CGA.
