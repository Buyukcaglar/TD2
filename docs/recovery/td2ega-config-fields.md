# Ordered bound words and configuration snapshot

[480 comparisons](evidence/td2ega-config-fields-validation-v1.json) passed
all31 instruction locations and12,600 original instructions:120 bound-setter
fixtures and360 snapshot fixtures. There are248 ordinary far returns,216
snapshot work prefixes and16 raw root-return aliases. [Eight native checks](evidence/td2ega-config-fields-native-diagnostics-v1.json)
cover invalid interfaces separately.

5DFB takes four SS words and writes them in order to CS:AF46, AF48, AF4A and
AF4C. Each argument is read immediately before its corresponding write.
40 SS=currentCS fixtures make earlier writes alter later argument reads;
the resulting word values and final AX match. The setter preserves incoming
DF and CF. It does not clamp, reorder or normalize the raw bound words.

78F8 takes one SS near destination in current DS. It captures incoming DS
in ES, establishes DS=currentCS and copies26 forward words from CS:AF3A.
It clears DF, leaves AX=currentCS/CX0 and rereads saved SI/DI/DS/BP on return.
Odd overlapping CS source/destination and offset-wrap profiles retain word
read-before-write order. This complements7918's reverse-direction state
publication; the52-byte span remains opaque configuration, not a decoded asset.

The comparison checks complete memory including SS saves/control frames,
returned GPR/BP/CF/IF/DF, copy progress and far return coordinates. Intentional
snapshot output over saved registers and the root return frame is stopped
after the original RETF; native output reports the resulting raw CS:IP/SP.
Outcome0 denotes that original far-return operation, not successful gameplay
or acceptance of that alias as an ordinary caller. Copy budgets retain the
in-progress snapshot frame; the finite setter does not consume copy work.

The [static review](evidence/td2ega-config-fields-context-v1.json) checks17
operand/segment sites and18 direct caller candidates. Actual producer/output
bounds, all CS writers, lifetimes, IRQ/reentry exclusion and full caller/state/
core integration remain open. No initialized configuration/media payload is
embedded. Actual device, renderer, audio, DOS session, resource decoding,
gameplay and fidelity gates remain separate. CGA remains behind EGA portable
code-contract closure.
