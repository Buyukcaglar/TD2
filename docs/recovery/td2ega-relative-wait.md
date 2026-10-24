# Relative raw counter wait

`FN-EGA-000417` (`06C9:C6C5`) takes two SS words, a raw low/high offset.
It calls the actual `C692` reader, adds the offset with ADD/ADC, and stores
the target low word then high word in real SS locals. Every subsequent read
must satisfy both unsigned high-word and low-word comparisons. A greater
high word does not bypass the low-word test.

The reader executes CLI, reads current DS:5E90 and DS:5E92, executes STI,
and returns through its actual far frame. It leaves IF enabled. CF and DF
survive the reader; root normal return has CF clear. The root restores BP
from actual SS and uses plain RETF, consuming four frame bytes and leaving
the two arguments to the caller. Memory aliases can change those saved
words and return coordinates; raw targets are exposed after RET, never run.

The clean C17 build and original-x86 comparison passed 52,992 cases,
1,083,164 instructions and all 21 root/reader sites. Full bus, real SS
frames/locals/arguments, GPR/BP/CF/IF/DF and control were compared. Coverage
includes 2,796 high-greater/low-below discriminators, 1,152 minimum-SP32
cases, 5,760 NULL-observer stable-bus cases and 180,544 reads with IF clear.
Twelve native interface/observer diagnostics are separate.

An optional memory-only observer supplies synthetic counter/SS changes
before the actual reader's CLI. It supplies no CPU return state. Native
budget and observer-failure outcomes are distinct from normal return and
original errors. This does not exercise actual IRQ delivery or timing.

The two direct callers are `16FC:0301`, forwarding SS BP+8/BP+A, and
`1769:01BD`, preparing AX=4 and word CWD DX=0. Both execute ADD SP,4
immediately after return, redefining arithmetic FLAGS. Current DS is
inherited; these windows do not prove all preceding callees preserve it.

All counter writers, transitive DS/SS context, interrupt/reentry exclusion,
lifetime, parent bodies, other FLAGS needs and core integration remain
open. Physical address 086C is a separate, unassigned source anomaly.
No counter frequency or time unit is assigned. No DOS session, renderer,
audio output, complete state-machine, gameplay or fidelity gate is closed.
CGA remains behind EGA portable code-contract closure.
