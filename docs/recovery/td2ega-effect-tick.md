# EGA PC Speaker effect callback

2026-10-13. `06C9:6269`, `FN-EGA-000403`, has a
[C17 build](evidence/td2ega-effect-tick-build-v1.json) and
[14,562 comparisons](evidence/td2ega-effect-tick-validation-v1.json), exercising
all140 instruction locations in its conservative fence. Synthetic bus and
port requests establish serialized code effects, without device/audio output.

When5EFB bit0 is clear, it clears5EFC, active segment5EEE and countdown5EF6,
then clears port61 bits0/1. Otherwise a nonzero countdown is loaded into AX,
decremented and compared in its original pre-decrement form with5EF8. Equality
clears the port bits; other values return immediately without port requests.
That threshold comparison is not a test of the new countdown.

With countdown zero, the source is5EEE:5EF0. Nonnegative note bytes consume
three bytes: note and a word duration. Note zero sets5EF8=0 and silences the
speaker. Other notes load CL from5EFA, preserve CH, derive5EF8 using the
explicit x86 masked-shift profile, and use the unsigned note byte to read a
word at5F2E+2*note. Port42 receives low then high byte; port61 bits0/1 are set.
The supplied event data and resident divisor table remain external to C.

Negative bytes negate BL, clear BH and admit indexes1..11; other indexes
enter the end/queue path. CS6334 maps them as follows:

| Bytes | Effect |
| --- | --- |
| FF | End current source and test queued flag5EFD |
| FE | Copy operand byte to5EFA and advance source offset by two |
| FD/FC/FB | Set one of counters5F00/02/04 from the word operand, advance by three and save loop start5F06/08/0A |
| FA/F9/F8 | Decrement the corresponding counter; nonnegative result saves SI to5F0C/0E/10 and jumps to loop start; negative result advances by one |
| F7/F6/F5 | Zero counter jumps through saved5F0C/0E/10; otherwise advance by one |

The decrement branch tests JS, not JL. In particular8000h decrements to7FFFh
and takes the nonnegative path. The interpreter then rereads source fields;
native C preserves those reads and source/group aliases rather than caching
a decoded event list.

The end/queue path clears5EFC. With5EFD nonzero it copies5EF4 to5EF0 and5EF2
to5EEE, then retries; it neither clears5EFD nor sets5EFC. A queued zero segment
can therefore retry forever. With no queued source it clears5EF6 and silences
the speaker. Native diagnostic3 fences such nonreturning profiles, and
[four native-only diagnostics](evidence/td2ega-effect-tick-native-diagnostics-v1.json)
keep budget/adapter/argument outcomes separate from original parity.

IF/DF, DI/BP/DS/SS and the far-return frame survive. AX/BX/CX/SI/ES expose
their literal effects, including retained BH before note dispatch, retained
CH during shift and partial updates before failures. Effective offsets wrap
at16 bits; an ordinary word atFFFF reads its adjacent physical byte. The
synthetic20-bit bus profile and data/code/live-stack separation are explicit
preconditions. Early-8086 unmasked shifts and actual A20 profiles remain
separate platform obligations.

Timer handler61BF invokes callbacks after CLI, but enables interrupts before
counter processing and can regain IF1 from callbacks that execute STI. It has
no local nesting guard. This callback's serialized comparison does not prove
actual interrupt exclusion, source lifetime, timer cadence, complete callback
composition, audio output or game/fidelity acceptance. Full EGA portable
code-contract closure continues to gate CGA; resource-fed checks remain phase2/3.
