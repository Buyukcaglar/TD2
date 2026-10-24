# 8582 line code and isolated device bus

The complete8582 body passed9,848 comparisons against compiled C17 across
all419 instruction locations.46,133,541 original instructions executed.
Outcomes:7,558 normal far returns,1,024 unsignedDIV fault prefixes and1,266
native work-budget prefixes.712 far8A0C calls remain ABI mocks. Synthetic
device traces include73,088 byteOUT events and32,312 reads plus32,312 writes;
551,273 total RAM/device byte writes matched. These are isolated code and
bus comparisons, with no actual EGA device or renderer acceptance.

The prologue uses SS for caller arguments and BP-based locals, sets DS=CS
for its drawing data and loadsES from CSAF3C. The normal epilogue restores
DS/SI/DI/BP and uses plain farRETF4; it preserves the other observed outputs
and clears carry through stack cleanup in the admitted frame profile.
Horizontal and vertical cases clip signed bounds and prepare five words for
far8A0C. Horizontal SUB/JS uses the wrapped sign, while SUB/JL/JLE branches
retain the original overflow-aware signed relation.

General cases compute wrapped inclusive coordinate counts, choose a major
axis by signed comparison and perform unsignedDIV at86EB/8730 for a raw
fixed-point step. Fraction/coordinate ADD/ADC and LOOP word behavior remain
explicit. Divide failures retain the original register/memory prefix and do
not become normal returns. Arithmetic flags afterDIV are unspecified; carry
is compared with its pre-instruction capture. The primary reference is
[Intel Volume2A, DIV pages3-285..287](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf#page=388).
This architecture reference does not establish historical exception-handler
execution, CPU identity or timing. No local full-PDF identity is claimed.

RAM paths use currentCS line-offset data, externalCS857A eight-byte masks
selected by index&7, and four currentCS plane segment words, skipping zero
segments. The alternateA000 path exposes byteOUT operations and device-byte
read-toAH/writeAL operations through an explicit adapter. RAM aliases and
device traces retain their ordering. No original mask values are embedded
in the C. The isolated adapter models a synthetic flat bus; real latch,
plane/device and presentation behavior remain later integration obligations.

The first native build had incorrect stack accounting at a budget boundary
before a far CALL. Its exact source/header/DLL remain preserved; corrected
buildv2 is selected. Validator attempts expanded horizontal/vertical coverage
and corrected a receipt-writer name collision; selected receiptv4 is complete.
Three native-only invalid input checks are recorded separately.

[Buildv2](evidence/td2ega-line-draw-build-v2.json),
[comparisonv4](evidence/td2ega-line-draw-validation-v4.json),
[native checks](evidence/td2ega-line-draw-native-diagnostics-v1.json),
[external-mask context](evidence/td2ega-line-resource-context-v1.json).
Live SS locals/control-frame aliases are excluded. Actual producer/caller,
all writers, table/output capacities, IRQ exclusion, resource-fed behavior
and actual8A0C integration remain open before core use. No DOS game session,
renderer/audio output, complete state machine, gameplay or fidelity acceptance
is established. CGA remains behind EGA code-contract closure.
