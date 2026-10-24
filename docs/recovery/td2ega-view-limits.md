# EGA limit stages at 06C9:2542 and 268A

The compiled C17 bodies passed 46,080 private synthetic comparisons against
the original instructions. All 144 instruction locations were exercised.
The test includes all 256 flag bytes, signed owner and bound comparisons,
word wrap, independent and equal DS/SS views, and selectors that alias outputs
written earlier in the same invocation. Both entries use plain near RET.

`2542` reads current DS, retains the incoming high byte of BX when loading the
flag byte, and takes the zero-flag early return. Selected owner heights are
doubled with word wrap. Adjusted bounds use signed comparisons after wrapped
addition or subtraction. Memory bounds are clipped to 0..80; the working DX
can retain the unclipped value on a store-only branch. The bit-80 path updates
owners and calls the actual `268A` body four times. Source reads remain
interleaved with stores, including aliases into freshly written outputs.

`268A` changes AX and carry while retaining the other observed registers. It
combines signed comparisons with unsigned comparison carry. The two flag
masks control distinct lower/upper stages; no generic host clamp substitutes
for their original ordering or reversed bounds.

For the tested complete `2542` invocations with nonzero flags, 2C66 and 2C2C
finish within 0..80. With bit 80 set the four final values do as well. This
does not bound 2C2A: its owner-driven writer preserves a raw word and is
relevant to the subsequent `088E` count. Actual producer/caller invariants,
buffer capacities, stack separation, all writers and IRQ exclusion remain
open before core integration. No geometry, physical units or resource format
is assigned by these numerical tests.

The first compiler recipe failed during setup because of an argument typo.
Its recipe and log are retained. The corrected recipe and successful build
are revision 2; the C/header bytes were unchanged. Four native-only invalid
input checks are recorded separately from the original comparisons.

Evidence: [build v2](evidence/td2ega-view-limits-build-v2.json),
[comparison v1](evidence/td2ega-view-limits-validation-v1.json), and
[native diagnostics](evidence/td2ega-view-limits-native-diagnostics-v1.json).
These establish isolated code contracts only. They do not establish an
actual DOS session, device/IRQ delivery, renderer, audio output, complete
state machine, gameplay or fidelity acceptance. CGA remains behind EGA
portable code-contract closure.
