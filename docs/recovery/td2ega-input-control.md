# EGA input-control state transitions

2026-10-13. Complete near `06C9:4281/43C3` (`FN-EGA-000368/000369`)
have two native exports, a [C17 build](evidence/td2ega-input-control-build-v2.json)
linking4612/4441, and [544,544 comparisons](evidence/td2ega-input-control-validation-v2.json)
against their original instructions and actual callees. These are synthetic
shared-group contracts, with no inferred field units or full simulation claim.

4281 captures DL/DH from3365/3366 and loads BP from332C. BP remains that
initial word even if a later helper changes332C. It selects literal input,
automatic and latch paths, preserving AL/AH/CL/CH separately. Indexed input
tables use the masked low nibble. The alternate record path loads a byte into
CH, wraps CH+7 into BL, then scales the resulting byte index by four. The
other path wraps an8-bit addition before its unsigned maximum comparison.
The native implementation preserves publication and latch order rather than
normalizing the fields to a guessed control model.

43C3 publishes2F5A/336B and advances2F4C/2F4E by wrapped steps of six, using
the original signed comparisons and the distinct23C8 reference. On an exact
target-pair match with no30h input bits, it stores BH into both3365 and3366.
Those stores are not unconditional zero clears. It then writes336C=1 and
loads BL from2F56 while retaining BH. If BL differs from BH, the whole BX is
doubled and used for a wrapped word read at23B8+BX. A high byte can therefore
select group data outside the small intended table, including fields just
published. The shared view and read order remain literal.

Both paths invoke4612 and4441 only where the original does, exposing their
AX/BX/CX/DX effects.43C3 preserves incoming BP;4281 clobbers it. Neither uses
BP as an SS-based memory pointer here, so these contracts do not impose DS=SS.
SI/DI/DS/ES/SS and IF/DF survive, and the balanced near frames return normally.
Incidental arithmetic flag consumers still need actual caller review.

Tests include all65,536 retained-BH/low-index pairs and65,536 alternate byte
index/value pairs at two load bases, every input byte across branch profiles,
signed step boundaries and varied state. Full64KiB group output, scratch
registers, BP and near frames match. Actual caller ranges, field/table
initialization, resource ownership, asynchronous IRQ effects and the complete
state machine remain open. No BIOS/device/input session, renderer, audio,
gameplay or fidelity is accepted. Full EGA closure continues to gate CGA.

Version2 requires an explicit `td2ega_mutable_control` input. At42AD, the
initial JA skips the early reset when8A9A>1; prepared JNE skips it when8A9A!=1.
At424A/4275, initial JBE suppresses stateFF for8A9A<=1; prepared JNE
suppresses it for8A9A!=1.43C3 is unchanged. Both42AD forms and all eight
root combinations are compared using separate original-code instances. Only
initial0/0/1 and prepared2/2/2 are established stable mutator outcomes; mixed
forms do not prove transition reachability. Unsupported native forms return
diagnostic2 before field writes. The [initial-only version1 history](evidence/td2ega-initial-input-contract-history-v1.json)
preserves exact archived sources/scripts/recipes and frozen old receipts.
