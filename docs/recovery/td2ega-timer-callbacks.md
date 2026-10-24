# EGA timer callback metadata and publication

2026-10-13. `FN-EGA-000150` (`06C9:614C`) and `FN-EGA-000151`
(`06C9:6180`) have bounded native metadata contracts. [The build](evidence/td2ega-timer-callbacks-build-v1.json)
and [7,232 original-instruction comparisons](evidence/td2ega-timer-callbacks-validation-v1.json)
cover two loads, all 32 live/empty segment patterns, all five target positions,
missing/duplicate/zero pairs, arbitrary following words, IF/DF combinations and
deterministic random cases. Four native-only argument diagnostics are separate.
No callback or actual interrupt executes in these cases.

The original uses five four-byte slots at principal DS:`5F12..5F25`.
Each pair is offset then segment. The next pair's segment at `5F28` supplies
the final terminator; its offset at `5F26` is not initialized by these helpers.
Native state has twelve explicit words. These words are opaque original code
addresses, not host function pointers. A nonzero segment admits dispatch even
when its offset is zero; zero segment terminates the ISR walk.

Addition scans five segment words and selects the first zero. It writes the
offset, clears that slot's segment, writes the supplied segment, and clears the
following slot's segment, in that order. It does not execute CLI or STI. A
following occupied slot can therefore be hidden; the helper does not repair
holes, deduplicate entries or reject a supplied segment of zero. A later
interrupt can see different stages of publication. The ordered native write
record preserves those effects for a future integrating scheduler; a single
host call is not a proof of original concurrent atomicity.

When all five segments are nonzero, the original loads the fatal-message
offset `5FE8`, pushes it and calls `16A7:0002`. The 304 fenced full cases stop
before that call, with no callback metadata writes. Native status 1 denotes
that prefix, not a successful return from the original fatal routine. Complete
fatal cleanup/nonreturn behavior remains a platform obligation.

Removal searches exactly five offset/segment pairs, including holes, and
matches the first duplicate. A missing match leaves memory and IF unchanged.
A match executes CLI, copies every later slot left through slot four, clears
slot four's offset and segment, then unconditionally executes STI. It leaves
the sixth pair unchanged. It does not restore the caller's incoming IF.
Native output records the ordered writes and final interrupt-enable effect.
All writes of a matched removal were observed with IF=0; addition writes retain
incoming IF. DF is unchanged on both helpers.

Both are far functions with offset/segment words at SS:BP+6/+8 and caller
argument cleanup. BP, SI, DI, DS, ES and SS are preserved on normal return.
Addition clobbers AX to supplied segment, BX to selected slot and CX to remaining
slots. Removal returns AX as the last shifted segment when shifting occurs,
otherwise the requested offset; DX is the requested segment, CX=0, and BX is
slot four on a match or the word after slot four on a miss. The native API
exposes metadata effects rather than the original incidental register values.
The input state, output result and active original stack must be disjoint.
Null native inputs have an explicit diagnostic outside the original contract.

The ISR at `61BF` saves the original frame, sends port20 value20, establishes
principal DS, and executes STI at `61D2`. It executes CLI before each far
callback at `6217`, but callees such as `7946` and `7977` end with STI. Thus an
entire callback cannot be assumed to run with interrupts disabled. The
byte-ring helper itself has no CLI/STI and uses shared principal DS state.
Actual callback nesting, hardware delivery and supported interleavings remain
open; these metadata tests neither inject nor accept them.

This closes local five-slot scan and write-order contracts only. Indexed or
aliased writers, all caller lifetimes, fatal cleanup, full ISR/PIT/speaker
contracts, timer units, game execution and fidelity remain separate gates.
Physical `086C` has no assigned timebase.
