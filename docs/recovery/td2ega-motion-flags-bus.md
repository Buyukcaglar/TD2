# EGA motion FLAGS before conditional clamps

18 October2026. The additional [C17 interface](../../src/recovered/td2ega_motion_flags_bus.h)
exposes the actual SS motion entry06B3:0008 and its actual13A8:2EE8 multiply.
The [build](evidence/td2ega-motion-flags-bus-build-v1.json),
[38,560 comparisons](evidence/td2ega-motion-flags-bus-validation-v2.json),
[static review](evidence/td2ega-motion-flags-bus-context-v1.json) and
[22 native diagnostics](evidence/td2ega-motion-flags-bus-native-diagnostics-v1.json)
cover all146 admitted sites and 2,737,384 original instructions
at two load addresses. The same original entry is counted once; older interfaces
and sources remain frozen. Result is52bytes. No resource extent is added.

Normal damping finishes with SUBAX,AX. The general path finishes with
CMPword2F46,F180 before a conditional MOV clamps that field. The new code
captures the operands before the write and exposes the full FLAGS word and
defined-bit mask. MOVSP,BP, POPBP and plain RETF preserve those flags. Before
the0114 CALL, the last NEGDX likewise supplies fully defined arithmetic flags.
Raw child prefixes conservatively mask arithmetic bits outside their contract.

The static review covers all65,536 words: the upper signed comparison can
overflow, but after that clamp the final CMP always has OF0. A lower clamp
changes29,056 original operands; reconstructing flags from the clamped field
would lose the original comparison. Native and instruction fixtures preserve
that distinction. Both incoming AF validity profiles and all256 admitted FLAGS
words are exercised. No CODE hook writes EFLAGS. The executed first probe maker
is archived; a coverage expectation for impossible finalOF1 was corrected to
actual upperCMP OF1 before full validation. C/header/DLL bytes did not change.

Actual SS savedBP, local words, four multiply arguments, far CALL and RETF8
remain materialized. The root uses plain RETF. CurrentDS can differ from SS;
sourceSP20..FFE0 and serialized20bitRAM are explicit analysis preconditions.
No units, actual lifetime, all writers or asynchronous access are inferred.

420A4261 calls motion and4266 immediately calls6601. Its MOVAH1/INT16 stores
the incoming FLAGS word before another arithmetic instruction. This packet
supplies that required component interface; whole420A/403B composition and
caller/writer/storage/lifetime/exclusion proof remain open. Existing raw
resource contracts and actual callback-body obligations retain their scopes.

Physical086C remains unassigned. CGA stays behind EGA code-contract closure.
No DOS game session, real BIOS/device/IRQ delivery, renderer, audio output,
complete state-machine validation, gameplay or fidelity is established. Full
resource decoding, Windows gameplay and Amiga recovery have not started.
