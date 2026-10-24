# EGA timer handler and old-vector bridge

2026-10-13. `06C9:61BF/6230`, `FN-EGA-000360/000361`, have two
[C17 exports](evidence/td2ega-timer-handler-build-v1.json) and
[3,586 comparisons](evidence/td2ega-timer-handler-validation-v1.json), exercising
all71 instruction locations across both fences. Old INT08 and far callback
bodies are ABI adapters. This is serialized code evidence, without actual
interrupt delivery, BIOS/PIC execution or clock semantics.

61BF executes CLI, saves DS/ES/AX/BX/CX/DX/SI/DI/BP, emits PIC EOI20h to port20h,
establishes principal DS and executes STI. It decrements5E9A and uses signed
JG. Old values2..7FFF take the positive branch;8000 decrements to7FFF with
overflow and still takes the rollover path. Rollover increments the32-bit
pair5E90/92, reloads5E9A from5E98 and optionally calls6230 when5E95 is nonzero.
No elapsed unit is assigned to either counter.

6230 conditionally decrements5E96 with the same signed JG rule, clearing
5E94/95 on expiration. It sets ES=0, installs5E88/8A into IVT20h/22h and
executes INT08. It then writes61BF and current CS through the *returned ES*.
It does not reestablish ES=0 after the foreign handler. The native bridge
preserves this behavior even when an adapter changes DS/ES. Such synthetic
profiles do not admit a real BIOS that changes those registers.

The comparison constructs the old interrupt's six-byte IP/CS/FLAGS frame,
enters its adapter with IF0 and restores the pre-INT flags on its IRET profile.
The near bridge returns with AX=CS; other modeled registers propagate from
the adapter. Callback adapters preserve SS/BP and frame/control integrity;
incidental arithmetic flags, TF-dependent behavior and BP-dependent adapter
bodies are outside this packet. Whole-handler IRET restores every saved
register and the supplied interrupt-frame flags, including IF/DF.

After the optional bridge, nonzero5EFE silences port61 bits0/1 and skips
callback work. Otherwise it loads BX from5E9C, increments the wrapped word
at5E9E+BX, increments32-bit5E8C/8E, and scans callback pairs from5F12. A zero
segment ends the scan. Each nonzero pair is called after CLI; returned DI
is incremented by four and returned DS selects subsequent fields. Callback
table writes, DS/ES/DI changes and indexed aliases remain literal in C.

There is no local five-row bound and no reentrancy guard. Six-row synthetic
fixtures verify that the handler continues beyond the installer's nominal
five callback slots. [Five native-only diagnostics](evidence/td2ega-timer-handler-native-diagnostics-v1.json)
separately check invalid arguments, rejected services and a callback DI cycle
that exhausts the native budget. They establish no original error-return
equivalence. Caller bounds and sentinel publication still require ownership
proof; these fixtures do not make arbitrary callback targets valid game code.

STI before the counters opens an interrupt window independently of callback
bodies. A callback such as403B can also call helpers that execute STI, leaving
another window before the next CLI. No host concurrency or nested interrupt
is delivered by these comparisons. The earlier byte-source nested model and
caller-IF witnesses remain separate; this packet does not integrate780E into
a game core or prove exclusion around its shared cursor.

The full synthetic bus is compared outside32 bytes of live/historical stack;
near/far/interrupt frames, guards, register restores and final flags are
checked separately. Actual platform/CPU/A20 profiles, old-handler body,
callback bodies and complete lifetime/scheduling rules remain open. Physical
086C retains its verified literal read address and unassigned source/timebase.
CGA remains behind EGA code-contract closure; no DOS game session, renderer,
audio output, complete state machine or gameplay/fidelity is accepted.
