# Clipped and raw rectangle code

89A2 and8A0C passed17,328 synthetic comparisons against compiled C17 across
all308 shared-body instruction locations. Outcomes:16,876 normal far returns
and452 native work-budget prefixes;1,553,575 original instructions executed.
The tests matched7,152 caller-argument mutations,12,296 byteOUT events,
61,382 device reads,61,320 device writes and620,218 total plane/device writes.
Prefixes can stop after a read and before a write; the counts remain separate.
No leaf ABI mocks occur inside these bodies.

Both entries use SS five-word arguments and BP locals, saveSI/DI/BP and
return with plain farRETF4.89A2 clips against currentCS bounds, writing changed
x/y/width/height back into the caller's SS argument words. A clipped early
exit can preserve incomingDF.8A0C enters the shared CLD path directly;
the shared body then checks signed positive width/height. DS is preserved.

CurrentDS6838/6840 edge-mask bytes are selected with index&7; currentCS
provides line-offset, plane and stride words. RAM paths retain one-byte,
two-edge-byte and wider edge/REP/interior behavior, ordered aliases and raw
word/DI/count wrap. The wide RAM path shifts the **caller SS color byte**
once per plane, including skipped zero-segment planes, preserving its high
byte. The smaller paths instead shift a captured AL value. These differences
must remain visible when composing retained caller argument pools.

TheA000 path exposes byteOUT and device read-toAH/writeAL operations through
the explicit synthetic adapter. Its interior keeps the original STOSB
increment. Port reset operations and ordered read/write prefixes match.
These comparisons do not establish actual EGA latch/plane/device effects,
a renderer, resource-fed output bounds or presentation fidelity.

[Build](evidence/td2ega-rectangle-draw-build-v1.json),
[comparison](evidence/td2ega-rectangle-draw-validation-v1.json),
[native checks](evidence/td2ega-rectangle-draw-native-diagnostics-v1.json),
[edge-mask context](evidence/td2ega-rectangle-resource-context-v1.json).
Two native-only input checks are separate. SS saved/local control frames and
executing code remain separated from writes; actual caller/producer/capacity,
all writers, alias/lifetime and IRQ exclusion remain open before core use.
No actual DOS game session, renderer/audio output, complete state machine,
gameplay or fidelity acceptance. CGA remains behind EGA contract closure.
