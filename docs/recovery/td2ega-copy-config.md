# Forward copy and CS configuration writers

The [comparison](evidence/td2ega-copy-config-validation-v1.json) passed2,816
vectors and all52 instruction locations, executing4,272,624 original instructions.
It records1,264 normal far returns and1,552 work prefixes,4,233,808 copy units
and4,245,072 bus write events including SS saves. [Eight native checks](evidence/td2ega-copy-config-native-diagnostics-v1.json)
cover invalid interfaces separately.

5D01 takes five SS words: source offset/segment, destination offset/segment
and byte count. It executes forward REP MOVSB after CLD. Count0 writes no
data; it does not acquire7C16's separate extra65,536-byte rule. SI and DI wrap
as words, and every read precedes its corresponding write. It is not a host
memmove. Saved BP/DS/SI/DI are materialized in SS and reread on return.

7D5E takes a two-word source far pointer and copies13 words to currentCS:AF3A,
covering26 bytes. 7918 takes one SS near offset in current DS and copies26
words to the same destination, covering52 bytes. Both set AX/ES to current CS,
clear DF, finish with CX0 and preserve incoming CF. Their saved-register push
orders differ and are retained. Normal returns are plain farRETF4/caller-clean.

The [writer review](evidence/td2ega-copy-config-context-v2.json) verifies19
instruction sites and71 direct call sites:61 for7D5E,6 for7918 and4 for5D01.
The two CS spans include plane segment words, the line-offset base, horizontal
and vertical bound words and the row-stride word consumed by sprite code.
Destination bytes do not intersect syntactic code in the selected initial
graph. This does not establish all mutable-state or table ownership.

Fixtures compare the complete bus including SS saves, returned GPR/BP/CF/IF/DF,
far return words, copy counts and prefixes. They include odd forward overlaps,
source/destination offset wrap, full65,535-byte cases and byte output over
saved SI/DI words with unchanged return control. The fixed copies exercise
current-DS and far-source contrasts, including overlapping CS configurations.
Native work prefixes retain the in-progress frame and remaining CX.

The copied state remains external; no initialized configuration or media
payload is embedded. Actual producer/argument/output bounds, all CS writers,
lifetimes, interrupt/reentry exclusion and complete caller/state/core integration
remain open. No actual device, renderer, audio, DOS session, supplied-resource
decoding, gameplay or fidelity acceptance follows. CGA remains behind EGA
portable code-contract closure.
