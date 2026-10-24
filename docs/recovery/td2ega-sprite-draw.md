# Three sprite entries and copy kernels

916C,91A4 and91D6 plus independent copy-kernel frames passed17,424 comparisons
against compiled C17.8,572,498 original instructions executed;1,086 of1,088
owned sprite locations and200 near-helper locations were exercised. The two
remaining pointer assignments,93B8/94F3, are statically unreachable under the
verified initialized mode3 frame and declared writer separation. They are not
claimed dynamically tested. Other caller families use different mode values.

Outcomes:14,832 normal far returns,2,496 native work prefixes and96 raw
unsupported-indirect boundaries.4,848 actual near-mask calls,134,752 byteOUT
events,260,934 device reads,276,982 device writes and769,214 total byte writes
matched. Full1MiB memory includes the materialized saved/local SS frames and
near return words; no stack scratch bytes were excluded. Independent kernels
and synthetic device traces do not establish actual graphics or gameplay.

916C and91A4 consume four SS words: source offset, segment and coordinates.
916C subtracts header origin words;91A4 uses the coordinates directly.91D6
consumes **two** SS words, the source far pointer, and reads stored coordinates
from header+8/+A.4,768 root cases use those minimal two arguments, leaving
guard words where coordinates would otherwise sit. All normal entries retain
plain farRETF4 and restore DS/SI/DI/BP from their actual SS saved words.

The body uses DS for the source packet, SS for BP locals/vectors and explicit
CS for masks, selector and dispatch tables. Byte MUL uses AL; raw full-word
extent/crop arithmetic and the low-byte products remain distinct. It builds
plane vectors in SS, calls the actual near82D0/8336/AD22/AD8B bodies and
dispatches to currentCS copy kernels. Root CLD and direct-kernel DF behavior,
word offsets, cropped source reads, REP/LOOP/count distinctions, ordered
aliases and far-return transport match. There are no ABI-value helper mocks.

The initialized40-byte selector span has bounded nonzero-nibble indices and
decreasing RAM/hardware selection masks. Generated fixture clear-mask upper
bits differ from the initialized bytes; all64 nibble/index AND operand
effects are equal and independently verified. The copy dispatch tables at
CS9562/9572 have eight supported targets each. These static identities do not
prove all writers, frame/output capacities, source lifetimes or IRQ exclusion.

Unsupported raw dispatch targets are returned with the unchanged body frame
and target coordinate. They do not become original errors or normal returns.
AND/OR/XOR caller/kernel families from7DBC/A718/BB08 remain unclosed. The
conservative graph includes those shared kernels; this contract does not
admit the whole union as one ordinary returning function.

[Buildv2](evidence/td2ega-sprite-draw-build-v2.json),
[comparisonv3](evidence/td2ega-sprite-draw-validation-v3.json),
[native checks](evidence/td2ega-sprite-draw-native-diagnostics-v1.json),
[frame/table context](evidence/td2ega-sprite-context-v1.json).
The earlier build/validator inputs remain archived; the C body was unchanged
when the grouped header comment and minimal91D6 argument fixtures were fixed.
Six native-only rejection checks are separate. No original table values are
embedded in C. Actual resource-fed/device/renderer behavior, full state machine,
DOS session, audio output, gameplay and fidelity acceptance remain open. CGA
remains behind EGA portable code-contract closure.
