# Raw record, counter and pair arithmetic

| Entry | Instruction-derived contract |
| --- | --- |
| 06C9:5C30 | Shift CX right three, scan eight-byte records with low SUB/high SBB, signed correction and unsigned latest-tie selection. BP is clobbered, SI becomes DI. The do-once LOOP runs 65,536 iterations when the shifted count is zero. Near return. |
| 0143:019E | Increment two raw counters; signed upper clamp at200, CWD/IDIV20 and accumulated quotient, then CWD/IDIV by a raw field. On zero remainder increment/clamp another field. Far return. |
| 06C9:5A25 | Check high words and signed guards, then write destination high before rereading source low. Pair overlap retains this ordering. Explicit CF1 success/CF0 rejection; near return. |
| 06C9:5C5A | Unsigned SI square, triple its high word, divide DX:AX by DI, halve quotient and compare raw remaining distance. Rejection writes DS3344zero and AL1 while preserving AH; acceptance AX0. Near return. |

The C17 build-v2/comparison-v2 passed 23,360 cases and all 100 instruction
sites, with 10,051,308 original instruction events, including fault attempts.
Complete memory, GPR/BP/CF/IF/DF, actual SS frames and control coordinates
are compared. There are 20,144 return operations, 912 before-iteration
diagnostic prefixes, 2,304 division-fault prefixes and 2,376 overwritten
return coordinates. Sixteen zero-count scans complete 65,536 iterations.
Nine native interface rejections are separate.

The first compiler attempt rejected two unused locals under /WX; exact
source/log/recipe are retained. Removing those declarations produced the
selected clean build. The first comparison also found that Unicorn changed
FLAGS while reporting a division fault. The native diagnostic describes the
pre-instruction prefix, so comparison-v2 captures that state explicitly,
checks operand/register preservation and excludes exception-delivery FLAGS.
Undefined successful DIV/IDIV arithmetic flags are not admitted; subsequent
defined instructions determine the returned carry checked here.

Nine direct caller candidates are recorded. Raw field units/types, callers,
other FLAGS use, all writers, capacity, lifetime, exclusion and core integration
remain open. No actual DOS session, exception/IRQ delivery, device, renderer,
audio, complete state machine, gameplay or fidelity acceptance is established.
CGA remains behind EGA portable code-contract closure.
