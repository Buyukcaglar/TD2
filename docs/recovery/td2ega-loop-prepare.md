# EGA loop record preparation at2089

2026-10-14.FN-EGA-000088 has one
[C17 export](evidence/td2ega-loop-prepare-build-v1.json) and
[4,264 comparisons](evidence/td2ega-loop-prepare-validation-v1.json).
All108 instruction locations execute. There are4,248 normal original returns
and16 bounded prefixes stopped before the next original record instruction.
Prefixes establish matching earlier effects, not an original error/normal return.
Two [native-only domain checks](evidence/td2ega-loop-prepare-native-diagnostics-v1.json)
remain separate from that total.

The function assignsES=DS, clears DF and zeroes17 words at2C64..2C85. It then
publishes raw80/17 setup fields, copies bytes and words, and applies DEC, NEG
and arithmetic right shift with16-bit wrapping. It uses currentDS for the
3813/39A3 records, globals and indexed output. The1E59 preparer uses SS for
its BP-based records. Actual integration therefore needs equal segments or
proved corresponding views/copies; independent-segment probes do not prove
the real caller relation.

Both record loops execute once before comparing SI with current5354/5356.
SI advances by8, and DI is shared across both passes. A zero extent still
processes one record. The code has no destination-capacity clamp. Reads and
writes share the mutable bus: an output can affect later source records,
current extent fields or globals. The C retains the source+6 read after
the first two output stores. Large alias fixtures compare this order.

Each record subtracts a raw low word and propagates borrow through SBB of
the high word. NEG acts on that high word. JGE tests SF against OF: NEG8000
leaves SF=OF=1 and skips adjustment despite the wrapped negative result.
Other positive pre-NEG high words take the adjustment by380D. An unsigned
adjusted result at most25 emits a doubled value, BP word and source+6 word
at27F6+DI/+2/+4, then increments DI by8. These raw fields have no assigned
vehicle, road, coordinate or physical units in this packet.

The tail publishes DI at28BE and two further raw delta/field pairs at28C0..C6,
then copies bytes to2C9C/D. BP, SI, DI and ES are not restored. Final CF is
the last SHL carry, IF survives, and DF is0. Plain RETF pops four bytes. The
entire bus, including root frame and guards, agrees with original execution.

Conditional DAT consumer links retain their pending resource format and
caller gates. Actual record/output bounds, all writers, preparation-to-loop
context, downstream graphics/state meaning and full code integration remain
P1 work. No full resource decoding, device/IRQ, renderer/audio output,
complete state machine, DOS/Windows gameplay or fidelity is accepted.
CGA stays behind EGA portable code-contract closure.
