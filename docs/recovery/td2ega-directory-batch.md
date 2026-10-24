# EGA directory-list callers

2026-10-13. Complete `16EB:000A` (`FN-EGA-000355`, required) and
`16EB:004C` (`FN-EGA-000356`, optional) share a native composition linking
the [directory lookup](td2ega-directory.md). The [C17 build](evidence/td2ega-directory-batch-build-v1.json)
passes [8,000 comparisons](evidence/td2ega-directory-batch-validation-v1.json)
against both original callers and their actual lookup callees.

The caller walks four-byte selectors while each current first byte is nonzero.
Each successful lookup stores AX then DX into a four-byte output row, advances
its local index and adds four to the selector word in its own caller argument.
That argument mutation is externally visible. A required missing selector
enters the lookup's fatal651A path; earlier outputs, selector padding and
argument changes remain. Optional missing stores0:0 and continues.

The views must retain aliases. Writing an output can change the next selector's
first byte, end the loop early, or overwrite a source count/relative-offset
field used by a later lookup. The native implementation reads the shared view
again after each publication. It does not precompute the list or directory.
The tests exercise current/next/previous selector outputs, shared archive
count/table writes, disjoint views and word/output near-boundary wrapping.

An empty list invokes no helper and preserves incoming AX/DX/DF. A nonempty
normal path returns the last lookup's pair and clears DF through the helper.
BP/SI/DI/DS and the outer return frame survive. Source/output argument words
remain unchanged; the selector argument at entrySP+8 advances modulo65536.
The native result exposes this word and the completed local count.

This admitted profile requires the outer DS to be the principal group: the
outer loop/output use DS, while the inner selector uses fixed principal ES.
SS is independent and disjoint. Each invoked selector is a nonwrapping
four-byte span; the group view includes the adjacent physical byte needed
for a word beginning atFFFF. Source/group aliases use shared backing storage.
Actual caller DS, list/output/source bounds and moving-resource ownership
still require closure. Native bounds/work diagnostics are outside original
error equivalence.

The comparisons use two load bases, empty/varied lists, required/optional
policy, partial failure state and full source/group bytes. They accept no
supplied archive, actual IRQ exclusion, fatal cleanup, renderer, audio, game
session or fidelity. EGA code-contract closure continues to gate CGA.
