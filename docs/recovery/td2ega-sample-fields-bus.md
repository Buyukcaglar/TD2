# EGA sample and limit fields with actual SS returns

18 October 2026. Two additional
[C17 interfaces](../../src/recovered/td2ega_sample_fields_bus.h) cover
`06C9:412C` and `06C9:4639` with current DS, independent SS, defined CF/ZF and
the actual near-return word. The earlier group interfaces and their source,
libraries and receipts remain unchanged. Both original entries were already
registered; this packet adds no new unique original entry.

The [build](evidence/td2ega-sample-fields-bus-build-v1.json) and
[40,164 comparisons](evidence/td2ega-sample-fields-bus-validation-v1.json)
cover all 95 sites and 779,586 original instructions at two code loads. They
check the whole 1 MiB bus, GPRs/BP, CF/ZF/IF/DF, write counts and actual return
coordinates. The cases include 880 changed return words, 224 near SP wraps,
576 post-write table aliases, and 224 DEC-80h overflow discriminators.
[Eleven native diagnostics](evidence/td2ega-sample-fields-bus-native-diagnostics-v1.json)
are separate from original equivalence. The
[static review](evidence/td2ega-sample-fields-bus-context-v1.json) records the
instructions, caller windows, lookup footprints and exhaustive byte predicate.

`412C` increments byte `336A`, masks it to five bits and reads a word from
`32AE+2*index`. It moves wrapped word `332A` toward `332C` by 96 using signed
comparisons before and after the adjustment. It **stores 332A before** deriving
the next table index by five logical shifts and AND FFFEh. The following word
read is from `30E8+index`; the code permits 1,024 word positions. With current
48A0h and target zero, the adjusted word is 4840h and that lookup addresses
332A itself. Reading a saved pre-store table snapshot would change BX.

The later `412C` paths retain their ordered byte tests, AL-only decrement with
AH preserved, the raw word-bit tests at `942E` and `3346`, and wrapped double
INC/DEC before signed comparisons against 1800 and 1500. Stores retain the
flags of the actual preceding comparison or test. These constants and raw
fields are not assigned timing or physical units.

`4639` compares AX from `332C` unsigned against lower `23AA` and upper `23A8`.
The below-lower path decrements BL and uses JL, preserving the comparison's
carry. Starting BL=80h produces BL=7Fh with overflow set; JL still takes the
negative path, so the stored counter remains 80h. Starting zero similarly
returns FFh in BL without storing it. The middle path increments the byte
with wrap and checks it unsigned against 30. The limit path rereads the upper
word, conditionally clamps AX, stores `332C`, then publishes state byte three
at `5490`. Unsorted bounds retain the source branch order.

Neither function creates a frame, saves registers, accepts stack arguments or
calls a child. Each executes a plain near RET and consumes the current SS
word. Its data writes may change that word. Native status zero reports that
operation and the actual coordinates, so a parent must check its expected
return before continuing. SP is admitted from zero through FFFEh; invalid
interfaces return status two before effects. DF and IF are preserved.

Two initialized raw lookup views are registered as RS287 and RS288:

- `32AE..32ED`: 64 bytes, accessed as 32 masked words.
- `30E8..38E7`: 2,048 bytes, accessed by the shifted/masked word index. This
  view contains the first view and overlaps state, control tables, record
  storage and other previously registered views. Its upper portion overlaps
  the known DAT copy starting at `346A`; its known overlap writers remain
  conditional on the principal DS/SS binding.

Their byte identities, absence of relocations and code footprints do not
establish runtime capacity, all writers, field units or a resource format.
Payload stays external/private. Full supplied-resource decoding remains a
later phase.

The discovered callers are `403B` at `4046` and `4104`. After `412C`, DEC at
`4049` replaces ZF while preserving CF; the skipped-work epilogue can retain
that carry. The main path's XOR at `4053` replaces arithmetic flags. After
`4639`, the first CMP in the called `4674` replaces CF/ZF. Whole `403B` still
requires the live SS interface for `420A`, full callback context, writers,
storage/lifetime and interrupt exclusion before integration.

No DOS game session, real BIOS/DOS/device/IRQ delivery, renderer, audio output,
complete state-machine validation, gameplay or fidelity acceptance follows
from this packet. Physical `086C` remains unassigned. CGA stays behind EGA
portable code-contract closure.
