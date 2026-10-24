# EGA input fields with actual SS returns

18 October 2026. Four additional [C17 interfaces](../../src/recovered/td2ega_input_fields_bus.h)
cover near entries `06C9:4281`, `43C3`, `4441` and `448A`, including the actual
near calls to `4612` and `4441`. Current DS and inherited SS are independent.
The earlier group interfaces, source, libraries and receipts remain frozen;
these four original entries were already registered and are counted once.

The [build](evidence/td2ega-input-fields-bus-build-v1.json),
[original comparison](evidence/td2ega-input-fields-bus-validation-v4.json),
[static context review](evidence/td2ega-input-fields-bus-context-v2.json) and
[14 native interface checks](evidence/td2ega-input-fields-bus-native-diagnostics-v1.json)
record the separate evidence scopes. The comparison passed 37,972 cases at two
load segments, exercising all 203 fenced sites and 1,439,764 original
instructions. It checks the whole 1 MiB bus, GPRs/BP, CF/IF/DF, normal-return ZF,
actual CS/IP/SP, write counts and cumulative near-call counts. Coverage includes
568 changed root returns, 16 near-SP wraps, 1,448 before-CALL budget prefixes
and 128 raw child returns. Native diagnostics are excluded from helper vectors.

Entries zero and one require SP from 20 through FFE0h; leaf entries two and
three admit SP from zero through FFFEh. Result size is 44 bytes. Native status
zero reports the actual root near RET, including changed coordinates; status
one reports a child RET after executing it and never follows that raw target.
Status two rejects an invalid interface before effects, and three stops before
a CALL budget is exceeded. A composing parent must check the expected return
coordinates. These are native interface outcomes, not invented original errors.
Other arithmetic flags, asynchronous activity, MMIO read side effects and writes
to executing code are outside this serialized flat-RAM profile.

`4281` retains AH when loading AL and captures BP from `332C` without saving it.
The marked path captures the original masked BX index before assigning AL=5.
Overlapping byte views at `3394`, `339D` and `33A6` each admit code indexes 0..15.
The original JA at `42AD` and prepared JNE form are explicit immutable inputs.
Unsigned bounds, wrapped byte addition, CH/CL, repeat suppression and ordered
publication are retained. The target commit uses a byte selector with BH zero,
then two word shifts to read a word pair at `23C6+4*selector` and `23C8+4*selector`.
CL=1 can still be published when the repeat guard skips the target commit.

`43C3` moves a wrapped signed word pair by six and stores it before rereading
the targets. On a match it publishes BH, then MOV BL retains that same BH.
The following whole-word SHL and `23B8` lookup can address **any even current-DS
word offset from 0000h through FFFEh**. Neither a byte-selector restriction nor
an initialized small-table capacity is justified. The actual `420A` caller's
BH domain and all data producers remain open. BP is preserved without invented
pushes or pops.

Both settling paths use the actual SS near frames for `4612` followed by `4441`.
Those frame writes precede child operand reads. The `4612` normal ZF derives
from the actual selector test or raw product-high comparison with 800; clamping
a value below 800 to 800 does not imply ZF=1. The frozen child implementation
and its RAM-only flag reconstruction are admitted only in this stable-RAM view.

`4441` subtracts with word wrap before its signed CX/DX branch. Its positive
path uses an unsigned 2700 threshold and AH-only subtraction by five; its
negative path retains wrapped NEG, the unsigned 3000 threshold, AL-only byte
subtraction and borrow clamp, unsigned byte multiplication and the 7000 test.
The raw constants have no assigned physical or timing units.

`448A` sign-extends eight bytes at `335D..3364`, adds them with word wrap and
stores `30E4` before copying `52CE` to `30E6`. BX finishes at eight. The final
CMP BL,8 yields CF=0 and ZF=1 even when the final AX is nonzero. CX, SI, DI, BP,
DS, ES, IF and DF are preserved.

Two initialized candidate views are registered without admitting a resource format:

- RS291: ten bytes at `23A6..23AF`, a raw byte/word bound view. `4281` reads
  `23A6`, `23AA`, `23AC` and `23AE`; the previously reviewed `4639` also reads
  `23A8` and `23AA`. They lie outside the known DAT copy at `346A..52C7`.
- RS292: 1,024 bytes at `23C6..27C5`, the byte-selector four-byte target view.
  The overlapping 16-byte secondary views at `2406` and `240F` lie inside it.
  The fixed `43C3` read at `23C8` lies inside, but its variable `23B8` lookup
  has the broader whole-DS footprint stated above.

Their initialized hashes and absence of relocations establish byte identity
and code footprints only. Actual producers, valid domains, writable capacity,
units, all writers, ownership and lifetime are unresolved. The `339x` views and
the eight samples lie in the existing overlapping RS271 state view. Payload
remains external/private; full supplied-resource decoding is deferred.

The direct caller sites are `420A:4251`, `425B` and `425E`; the two calls to
`4441` are at `4335` and `443D`. After `4251`, CMP `3365` replaces CF/ZF. After
`425B`, the entry XOR in `448A` replaces them. After `425E`, far `06B3:0008`
executes PUSH BP / MOV BP,SP / SUB SP,4 before using arithmetic flags. For the
two near control children, callee SP is caller SP minus two, requiring caller
SP at least 22. This is a component condition, not a complete `420A` or `403B`
stack, mutable-code, writer, exclusion or core-integration contract.

Earlier comparison attempt v2 reused a Unicorn code cache across JA/JNE forms;
memory contained JNE while the cached JA still executed. The exact failure,
probe and old validator are retained privately. Fresh CPUs matched both forms
at both loads, and the selected full comparison uses separate CPUs per immutable
form. Attempt v3 matched all 35,092 cases but exercised only 198 sites; v4 adds
the missing control-boundary cases and covers all 203. Recovered C and DLL bytes
did not change. This does not qualify historical CPU self-modification timing.

Whole `420A`/`403B`, mutable transitions, actual caller domains and P1-GATE remain
open. No DOS game session, real BIOS/DOS/device/IRQ delivery, renderer, audio
output, complete state-machine validation, gameplay or fidelity acceptance is
established. Physical `086C` remains unassigned. CGA stays behind EGA portable
code-contract closure.
