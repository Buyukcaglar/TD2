# EGA two-table preparation and byte-source caller

2026-10-13. `06C9:1E59`, `FN-EGA-000083`, has a
[C17 build](evidence/td2ega-prepare-records-build-v1.json) linking the existing
byte-source C and [6,240 comparisons](evidence/td2ega-prepare-records-validation-v1.json)
against the complete caller and actual780E instructions. All64 instruction
locations in both fences execute;648 cases compare original DIV-overflow
prefixes. This is isolated caller composition, without a game core, real
resources or IRQ execution.

The direct caller is1B2C, before its1C8F/1E31 work.1E59 sets ES=DS, clears DF,
negates byteDS920C modulo256 intoDS1A70 and processes two400-byte spans at
offsets3813/39A3. BP+SI accesses default to **SS**. Globals, multiplier380D,
byte source66E6..67E7 and deletion copies use **DS**. The native bus keeps
both segment views explicit; it imposes no global DS=SS override.

Each nonzero first byte denotes another8-byte record; zero ends the current
span. SI0/8/16 are retained without consuming the byte source. Later records
call780E and compare returned AL unsigned withDS1A70. A larger sample keeps
the record; a sample at or below the threshold deletes it by forward-copying
`400-(SI+8)` bytes fromDS:BP+SI+8 toES:BP+SI. SI is restored, CX becomes1000
and the current SS record is rechecked. With DS!=SS, the deletion view need
not modify the record being tested; that difference is preserved.

Deletion does not clear the last8 bytes. A full unterminated table andFFh
threshold can therefore repeatedly copy a nonzero record without advancing.
[Three native-only diagnostics](evidence/td2ega-prepare-records-native-diagnostics-v1.json)
retain that nonreturning profile under an explicit budget. Budget exhaustion
is not normalized to a successful original return or resource-validity claim.

Kept records multiply their SS word at+2 by unsignedDS380D, divide the32-bit
product by CX1000 and add3B51 modulo65536 to the quotient before storing it
back through SS. Quotient overflow triggers original #DE before the field
write. The comparison preserves AX/DX's product prefix and unrecovered live
BP/frame at that point, using a fresh synthetic CPU after every fault.
First-table word+6 becomesFF38; second-table word+6 becomes00C8 and its first
byte increases by4 modulo256. Field units and high-level record meanings are
unassigned.

Final SI values publish toDS5354/5356. Normal RETF restores incoming BP while
exposing AX/BX/CX/DX/SI/DI/ES and DF0. Deletion ends DI atBP+392, notBP+400.
For terminated, nonaliased DS=SS tables, the comparisons also check that
sample consumption equals `max(first_count-3,0)+max(second_count-3,0)`.
Threshold changes affect retained records but preserve that consumption
count within this profile. This does not assign RNG/seed meaning to780E.

Synthetic shifted-SS fixtures show field writes aliasing the DS ring cursor
or published count words. They demonstrate conditional address effects, not
actual caller reachability, a canonical ring reset or an accepted startup
profile. The direct sampler writes and broader indexed/reset-writer review
remain separate. No asynchronous interleaving is delivered by this packet.

The selected-route setup's7774-byte copy toDS346A..52C7 covers these tables
and multiplier when DS=SS. That establishes a conditional raw consumer path
for the19 numbered route-file candidates; it admits no decoded file schema,
perfile content or resource-fed behavior. Actual caller segments, bounded
termination/division values, callback exclusion, source initialization,
ownership and full state transitions remain open before P1-GATE. CGA remains
behind EGA code closure. No DOS game session, renderer/audio output or
gameplay/fidelity acceptance is established.
