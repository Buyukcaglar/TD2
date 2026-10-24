# Signed thresholds and interpolated transitions

`FN-EGA-000384`, `06C9:4B9A`, is a near entry without its own save frame.
It loads DL while retaining incoming DH, selects positive or negative signed
thresholds from current DS flags, and either returns, writes state2, writes
an ordered transition, or examines raw eight-byte rows at `37A6+SI`.
The sign-extended `SUB BX,BA` and `SUB BX,CE` add70 and50 modulo16 bits.
The translation retains their literal carry behavior.

The row path tests a zero header, compares the raw coordinate with an unsigned
upper endpoint, and increments SI by eight with wrap. A selected row uses
wrapped differences, signed IMUL and signed IDIV. Signed division truncates
toward zero; the remainder stays in DX unless the fallback control call
overwrites it. BP and SI can change because the original does not save them.
Even ordered unsigned endpoints can produce a negative signed divisor.

[31,434 comparisons](evidence/td2ega-threshold-transition-validation-v3.json)
cover all108 root/control sites at two load addresses. Whole RAM, registers/BP,
CF/IF/DF, root ZF, actual SS/returns and budgets match compiled C17. The
920 zero/overflow divide cases stop before IDIV; they establish neither
exception delivery nor undefined post-divide flags. Two long fixtures prove
an actual complete8192-row SI cycle plus one head. The first passing receipt
counted the long-fixture tag although an overlapping metadata word selected
a row early. Its exact validator/receipt and the native check that exposed
the gap are retained; corrected fixtures and explicit wrap assertions form
the selected evidence. A misplaced BP summary counter in v2 was corrected
in v3; every comparison and wrap assertion had passed. C and DLL are unchanged.

[Static review](evidence/td2ega-threshold-transition-context-v1.json) and
[59 native checks](evidence/td2ega-threshold-transition-native-diagnostics-v3.json)
are separate. They preserve signed thresholds, ordered state writes, negative
products and divisors, BP changes, real stack aliases and fallback `45FC`/`4612`
flags. The sole known direct caller at48A8 next invokes4C85, whose entry AND
replaces arithmetic flags before use. Complete caller context remains open.

RS283 records only the two initialized zero header bytes at principal-group
`37A6`. This identifies the initial sentinel; it gives no row capacity or
complete table extent. The known7774-byte DAT copy346A..52C7 can replace it.
Valid rows, all writers, field units, ownership, lifetime and exclusion remain
open. No supplied resource has been decoded by this packet.

No DOS game session, renderer, audio output, complete state machine, gameplay
or fidelity acceptance is established. Physical086C remains unassigned.
CGA remains behind EGA portable code-contract closure; full resource decoding,
Windows gameplay and Amiga recovery have not started.
