# EGA handler and old-vector bridge with actual SS

18 October 2026. The additional [C17 interface](../../src/recovered/td2ega_timer_handler_bus.h),
[build](evidence/td2ega-timer-handler-bus-build-v3.json),
[4,474 original comparisons](evidence/td2ega-timer-handler-bus-validation-v3.json),
[static review](evidence/td2ega-timer-handler-bus-context-v1.json) and
[31 native diagnostics](evidence/td2ega-timer-handler-bus-native-diagnostics-v2.json)
cover all71 original61BF/6230 instruction sites and238,766 original instructions.
The older interfaces and their distinct virtual-stack qualification remain frozen.
Both original entries are counted once. No resource span is added.

61BF executesCLI, PUSHes DS/ES/AX/BX/CX/DX/SI/DI/BP, emits its byte PIC EOI,
loads relocated principalDS and executesSTI. It inheritsSS. The source saves
actual words and restores them before an actual six-byte IRET. The comparison
includes every byte of1MiB RAM, with no live-stack exclusion. Sixty-four cases
alter all nine saved words and all three IRET words; root coordinates and FLAGS
come from that storage and are reported without following the raw root return.

The6230 near bridge publishes the old vector through ES0, executes modeled
INT08, then writes61BF/currentCS through returned ES and nearRETs. The named
real-address ISA profile writes FLAGS-CS-IP before loading the IVT target;
24SS0/IVT-frame alias cases retain that order. This profile is documented in
the [Intel reference record](evidence/intel-int-real-mode-reference-v1.json),
without qualifying the historical CPU or delivering a real IRQ. AF after the
preceding XOR is represented by explicit0/1 stored-word choices. No CODE hook
writes EFLAGS. Modeled INT frame writes remain separately counted.

The far callback scan has no local five-row bound or reentry guard. Returned
DS/DI select subsequent rows after ADDDI4; the segment-zero sentinel and actual
far frames remain literal. Each child retired CS/IP/SP is checked before
continuation. External callback and oldIRQ bodies are explicit ABI effects plus
generic RETF/IRET. This packet does not execute403B or6269 as callback bodies.

There are3,934 retired root returns,256 raw child returns,232 budget prefixes,
and52 unsupported IRET FLAGS prefixes in the corpus. The prefixes qualify the
analysis interface and retain partial effects; they do not invent original
error returns.31 native checks separately cover invalid arguments, beforeCLI,
beforeEOI/allnine saves, beforeINT/post-IVT writes, and rejected service frames.

SourceSP68..FFE0 reserves18 saved bytes+4 far-frame bytes+the accepted403B
minimum46 for later composition. Standalone6230 usesSP6..FFFA. Valid actual
caller domains, actual403B/6269/oldIRQ bodies, nested delivery/scheduling,
callback/table writers, source resets, storage lifetime and exclusion remain
open. Counter words5E8C/E and5E90/92 have no assigned units. Physical086C remains
literal and unassigned. No complete-core or P1-GATE closure is claimed.

The first build failed on an incorrect header name; its exact source and log
were archived. Compiledv2 was preserved before correcting the INT vector alias
order. Buildv3 C/header/DLL stayed unchanged through comparison. The passing
4,390-case corpus was retained and84 targeted cases added. Native harness
ctypes callback-field restoration was repaired using retained callback objects;
the failed maker and log are preserved. These repairs changed no accepted code.

CGA remains behind EGA code-contract closure. Full resource decoding, Windows
gameplay and Amiga recovery have not started. No DOS game session, real BIOS/
device/IRQ delivery, renderer, audio output, complete state-machine validation,
gameplay or fidelity acceptance is established.

## Actual handler caller: early and paused paths

The separate [12,800-case caller comparison](evidence/td2ega-timer-state-tick-prefix-v2.json)
executes actual61BF, actual403B/412C, paused420A with modeledINT16 and actual69B7,
5A6F/control helpers, actual403B far RET and the caller's actualIRET. It compares
the full1MiB bus, GPR/BP/CF/IF/DF, defined caller-OR flags and all CPU/modeledINT
writes across two loads, distinct/equalSS, SP68/A3CE/E000/FFE0 and DF0/1. All256
3368 bytes and paused1/2/4 profiles produce227 exercised sites and1,570,592
original instructions. Actual403B receives the caller's IF0/real far frame and
returns its actual saved words. Unexposed child arithmetic bits are dead at
the immediately following621B ADDDI4; no full child-FLAGS claim is inferred.

The403B-only callback row is synthetic. This does not prove the actual6269-first
registration order, complete simulation/mode/record/nonlocal paths under61BF,
shared byte-source consumption/reset/lifetime/exclusion, nested IRQ delivery,
or whole-core feasibility. A3CE is a static startup stack candidate, not an
observed runtime stack. These12,800 supplementary cases are excluded from
helper totals and do not close P1 or any runtime/gameplay/fidelity gate.

## Actual registration order and both callback bodies

The separate [14,560-case ordered caller comparison](evidence/td2ega-timer-callback-order-v2.json)
executes the original3FD9/601C/614C registration slice to produce6269 followed
by403B and its zero-segment sentinel.32 producer executions cover78 sites and
6,752 instructions; these source-only producer counts are recorded separately
and do not establish native startup or real IRQ delivery. Their resulting
callback rows are preserved while explicit synthetic state fields vary.

Actual61BF then invokes actual6269 and actual403B early/paused bodies. The
native side invokes both recovered C bodies, checks each retired state/frame
and independently counted writes, then executes the C handler continuation.
The original side executes both original bodies and their actual far returns
and handlerIRET. No generic callback RET or C-valued mock replaces these bodies.
The comparison covers2,220,480 original instructions and367 sites, including
all140 effect sites, full1MiB RAM, GPR/BP/CF/IF/DF, defined caller OR flags,
ordered byte ports and CPU/modeledINT writes. Source/native stack data includes
the first callback's register changes and the second callback's actual DI4.

Two relocation bases, distinct/equalSS, SP68/A3CE/E000/FFE0 and DF0/1 are
covered. A3CE remains a static startup candidate rather than an observed
runtime stack.14,560 supplementary cases are excluded from helper totals.
Full403B simulation/mode/record/nonlocal and byte-source consumption under this
caller, oldIRQ delivery/nesting, every writer/reset/storage lifetime/exclusion
and whole-core/P1-GATE remain open. No DOS game session, real devices/audio,
complete state-machine validation, gameplay or fidelity acceptance is inferred.
