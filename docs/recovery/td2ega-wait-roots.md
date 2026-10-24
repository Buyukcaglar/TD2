# Input and raw-counter wait roots

[14,600 comparisons](evidence/td2ega-wait-roots-validation-v1.json) passed
all47 owned instruction locations and184,936 original instructions across
6A30,6A4A,7A3B,C63E and the actual69FE/79C8/C692 child bodies. There are
8,656 root far returns,5,936 prefixes stopped before an outer call and8 raw
counter-return transfers. [Twelve native checks](evidence/td2ega-wait-roots-native-diagnostics-v1.json)
cover invalid interfaces, observer/input failure and excluded dynamic-frame
mutation separately.

6A30 repeats69FE until full AX is nonzero. It accepts AH-only values without
an AL-only substitution.6A4A checks input first, then reads79C8's owned pair
at currentDS5E8C/5E8E and compares it with DS6818/681A. A greater high word
skips the low comparison.7A3B uses that same lexicographic unsigned comparison
once and returns AX0/1. C63E instead readsC692's separate DS5E90/5E92 pair
and requires both DX>=DS68D8 and AX>=DS68D6, even when DX is already greater.
The code's high-and-low condition is retained.

There are25,680 outer calls,16,536 dynamic input calls and9,144 synthetic
counter observations. The dynamic input target is an explicit full returned
GPR/BP/CF/IF/DF ABI service; its fixture RET stub is counted separately from
original instructions. The input target body and real input delivery are not
admitted by this composition. Counter observers mutate the synthetic bus
before the actual reader and preserve CPU state; they are not delivered IRQs.

The bridge materializes outer and dynamic far frames, including69FE's return
offset6A02, before invoking the service. The complete bus including SS frames,
returned GPR/BP/CF/IF/DF, request order, root returns and bounded prefixes match
without SS scratch exclusions. Returned DS/BP and rewritten pointer slots
are exercised. Eight intentional observer writes over a counter's return
frame stop after the original child RETF and expose its raw CS:IP/SP without
executing the parent's comparison or root return. Ordinary input-service
profiles preserve their dynamic return frame; violations are native diagnostics.

The [static review](evidence/td2ega-wait-roots-context-v1.json) verifies24
operand/branch sites and12 direct caller candidates. Both owned readers end
with IF1 through CLI/read/STI; this establishes the modeled flag result,
not actual interrupt exclusion or atomicity. Their pairs remain distinct,
with no clock frequency/timebase assigned. Physical086C is a separate literal
reader anomaly. Other flag consumers, input/counter writers, lifetimes,
IRQ/reentry exclusion, complete caller/state/core integration and resource-fed
phase2/3 checks remain open. No actual device, BIOS/DOS session, renderer,
audio, gameplay or fidelity acceptance follows. CGA remains behind EGA closure.
