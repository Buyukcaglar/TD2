# Byte-source caller and state adjustments

`FN-EGA-000381`, `06C9:4A2E`, sets DX to `0640` hexadecimal (1600),
calls actual near `45FC`/`4612`, publishes the `DS:5494` far pair through
actual `7977`, then calls `FN-EGA-000003` at `780E`. The setter executes
CLI, stores segment then offset, sets its flag and executes STI before
returning. The byte-source call therefore has IF=1. This is an instruction
result; actual interrupt delivery and exclusion remain open.

The complete 72-site root and its four actual callees passed
[28,984 original comparisons](evidence/td2ega-sample-adjust-validation-v2.json):
1,683,520 instructions and all 117 sites. Whole RAM, registers/BP, CF/IF/DF,
root ZF, CALL counts, actual SS frames and return coordinates match compiled
C17. [Static review](evidence/td2ega-sample-adjust-context-v1.json) covers the
three direct callers and their dead arithmetic flags. Eighty
[native checks](evidence/td2ega-sample-adjust-native-diagnostics-v2.json)
are separate. The original comparison refinement added saved-SI aliases;
the native expectation correction retained the failed script and log.
Neither changed C or the DLL.

Signed AL positivity admits 1..127. After the current DS guard, an eight-bit
counter increments with wrap; unsigned values above four select state 8.
The next byte and word adjustments store `2*old+25` and `2*old+1000`, but
compare `2*(old+25)` and `2*(old+1000)`. These are distinct wrapped values.
The subtract-75 path uses an unsigned threshold. The +/-37 path compares
the signed, already wrapped result against +62 or -62. No clamp is added.

The final path stores byte 1 at current `DS:33BF + zero_extended(DS:2F56)`.
For AL101..127, guard `8A9A=0`, wrapped counter <=4 and `90A8=0`, all 256
raw selectors address `33BF..34BE`. When DS binds principal group `178F`,
selectors 0..48 overlap RS271, 135..150 RS272, 151..160 RS273 and 161..170
RS270. The last three are initialized near-control tables. This records a
conditional writer; it does not prove those selector values are admitted
by real callers or close indirect bounds, all writers or table lifetime.

The original `PUSH SI` can alias the cursor or selected byte. For example,
SS=DS/SP66EC changes the popped SI to3455; SP672B/cursor003E changes it
to34AD. SI preservation in the original isolated leaf receipt applies to
its disjoint stack fixtures. The unchanged pure C transformation remains
valid for its explicit state domain; the new composition models literal
SS ordering separately. Altered near/far child returns are reported after
the actual return instruction and are never followed.

This adds no resource span and no RNG purpose. Caller DS/SS/SP domains,
shared source/reset/seed, all writers, selector validity, storage ownership,
lifetime and IRQ scheduling remain open before core integration. No DOS
game session, real device effects, audio output, complete state machine,
gameplay or fidelity acceptance is established. Physical086C remains
unassigned. CGA stays behind EGA portable code-contract closure; complete
resource decoding, Windows gameplay and Amiga recovery have not started.
