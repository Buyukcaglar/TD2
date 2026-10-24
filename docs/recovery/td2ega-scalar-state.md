# Bytecase and finite signed/indexed state contracts

[23,680 comparisons](evidence/td2ega-scalar-state-validation-v1.json) passed
all44 original sites and206,448 original instructions. There are23,088 far
returns and592 raw root-return aliases. [Eight native checks](evidence/td2ega-scalar-state-native-diagnostics-v1.json)
cover invalid interfaces separately. The16,384 bytecase fixtures cover all256
input bytes and preserve every tested argument high byte and original upper EAX.

16AA:0002 modifies only the low argument byte61h..7Ah by subtracting20h,
then loads AL and executes unprefixed98 in16-bit context. The result is AX
sign extension of that byte, including FF80h..FFFFh for negative byte values.
CF from the comparisons/subtraction remains observable; no locale mapping or
original source return type is substituted. The argument's high byte remains
unchanged. The native API models16-bit registers; upper EAX preservation is
an additional original-instruction observation.

Capstone reports the same CWDE text for98 and66 98, and CDQ for99 and66 99.
Raw prefixes and operand size determine their effects. The [primary Intel
reference](evidence/intel-sign-extension-reference-v1.json) and [60 full-register
microfixtures](evidence/td2ega-sign-extension-context-v1.json) resolve that
ambiguity. The [four selected snapshot review](evidence/td2ega-operand-width-context-v1.json)
finds no66/67 overrides or explicit32-bit GPR operands, and records217
unprefixed word sign-extension sites per snapshot. This finding does not cover
unclassified bytes, unresolved targets or all mutable transitions.

13A8:2A18 reads a signed index argument and signed currentDS6DA2 limit, rejects
negative indexes, then tests bit40h in DS[index+6DA4]. AX is0/1 and CF0.
13A8:190E returns AX1 when DS83E4 is0; otherwise it decrements DS83DA only
when signed positive, returning AX1 for that path and AX0 for zero/negative.
These fields remain raw state, with no table format or clock units inferred.

0432:1D25 doubles DS8A22 into BX, retaining SHL carry across its MOV stores.
It zeros the indexed DS[BX+40] word, DS8A22 and DS8A8C, then rereads DS8C9E
into AX and stores it to DS8A1C. Post-write aliases can therefore change the
last read. Word-index wrap, signed boundaries, DS/SS/global overlaps and
control-frame aliases are compared in the complete bus. Raw returns stop
after the original RETF and expose their coordinates without executing targets.

The [static review](evidence/td2ega-scalar-state-context-v1.json) verifies24
operand sites and15 direct caller candidates. Actual caller bounds, other
flag consumers, DS/SS correspondence, all writers, lifetimes, IRQ exclusion
and full state/core integration remain open. ISA microfixtures and static
snapshot checks are excluded from native helper totals. Actual device/render/
audio/DOS session, resource decoding, gameplay and fidelity gates remain
separate. CGA remains behind EGA portable code-contract closure.
