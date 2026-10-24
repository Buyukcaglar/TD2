# Actual configuration caller and nested far return

[1,288 comparisons](evidence/td2ega-config-apply-validation-v1.json) connect
the actual3EFC root with actual7D5E, executing33,552 original instructions
and all23 locations. There are512 normal root far returns,768 copy-work
prefixes and8 raw child-return transfers. [Eight native checks](evidence/td2ega-config-apply-native-diagnostics-v1.json)
cover invalid interfaces separately.

3EFC reads currentDS9B4 first and pushes that segment word, then reads/pushes
DS9B2 as source offset. It pushes its actual current CS and return offset3F09,
then invokes7D5E's recovered13-word copy body. The normal child consumes its
four-byte far frame; ADDSP4 discards the source arguments and determines final
CF. The root then consumes its own four-byte far return. Every SS argument,
call and saved-register word is materialized. There are no leaf ABI mocks or
SS scratch exclusions.

480 fixtures place DS globals and SS frames in overlapping argument/stack
profiles. This retains the first push's possible effect on the second read.
Other profiles exercise overlapping CS source/configuration bytes, source
offset wrap, currentDS/SS contrasts, incoming CF/IF/DF and copy budgets.
The complete bus, returned registers/flags, exact write counts and return
coordinates match.

Eight deliberate SS=currentCS profiles make the configuration output overwrite
the child's return segment. The original is stopped after its actual RETF;
the native result exposes that raw CS:IP and current SP as outcome1. It does
not run the parent's ADDSP4 or invent a successful root return. These are
separate alias boundaries, not supported caller ownership or gameplay paths.
Normal work prefixes remain outcome3 with the actual in-progress child frame.

Actual source producers, allocation/capacity, all configuration writers,
lifetimes, IRQ/reentry exclusion and complete state/core integration remain
open. Raw configuration and media stay external. No actual device, renderer,
audio, DOS session, resource decoding, gameplay or fidelity acceptance follows.
CGA remains behind EGA portable code-contract closure.
