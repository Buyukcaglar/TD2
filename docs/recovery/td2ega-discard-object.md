# Far-descriptor discard and actual SS frames

`06C9:782C` now has a full-bus C contract with actual7490 instructions.
Its two caller-owned SS words point to an ES:DI descriptor containing a
DS:SI far address. After saving BP/DS/SI/DI, it reads the object word atSI+2,
adds13, doubles the low word and subtracts the wrapped result from CS:B269.
It then restores cache DS from the live saved SS word and calls7490 with
the object's offset/segment. Those operations retain their exact order.

The child ignores the offset, searches downward in18-byte rows from current
DS:6C68 and excludes DS:6C66. A segment match does not require nonzero status.
It clears status atrow+10; a top match trims free predecessors and updates
6C68. Unknown segments prepare the actual segment/message arguments and stop
before the fatal call at74B3. Fatal cleanup remains unexecuted.

The C17 `/W4 /WX` build passed2,696 comparisons,134,320 original instructions
and all51 feasible sites of the52-site parent/child fence. The remaining site
is the explicitly unexecuted fatal call. Whole bus, actual SS saves/far frames,
registers, CF/IF/DF and counters match. Coverage includes1,360 DS=SS cases,
344 fatal prefixes, four changed child returns,12 changed root returns,
96 pre-RET qualifications and16 final ADD SP,4 carry cases. All38 native
checks and the static65,536-word/SP proofs are recorded separately.

Selected-status writes can overwrite live child or root far-return words.
CS:B269 can overwrite the root return IP or the saved DS subsequently used
for cache lookup. A native diagnostic expectation initially missed the latter
case's immediate fatal prefix on a zero-filled bus; its repaired receipt
preserves the failed script and leaves C/DLL unchanged. The first build's
unused-local `/WX` failure is also retained before the selected second build.

The earlier metadata-only cache-discard API and evidence remain frozen.
This additional view preserves aliases outside that API's disjoint arena.
Known caller arithmetic-flag consumers were reviewed, including the registered
near CALL plus pushed-CS path through6559. Indirect domains/all writers,
counter units, descriptor/object bounds, storage ownership/lifetime, exclusion
and fatal cleanup remain open. No new resource codec or media span is inferred.

All16-bit SP body effects remain modeled; a four-byte far frame crossing the
qualification boundary stops before RET. Historical CPU faults and A20 remain
unqualified. No actual DOS session, renderer, audio, complete state-machine,
gameplay or fidelity acceptance is established. CGA recovery remains behind
EGA portable code-contract closure; physical086C stays unassigned.

Evidence: [comparison](evidence/td2ega-discard-object-validation-v2.json),
[context](evidence/td2ega-discard-object-context-v1.json),
[native diagnostics](evidence/td2ega-discard-object-native-diagnostics-v2.json).
