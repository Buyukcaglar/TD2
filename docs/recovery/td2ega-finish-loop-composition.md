# Actual 1F71 caller chain

The original `1F71` body and its four near-call bodies now match the compiled
C composition in 1,024 private synthetic normal-return cases. The chain
executes `21C3` with actual `13A3:0038`, `2477` with actual self-modifying
`06C3`, `2542` with actual `268A`, and `088E`. No ABI-value leaf mocks remain
inside this particular chain. `1F71` retains its far return and saved
SI/DS/BP; the child calls retain their near returns, and `06C3` retains RET6.

The comparison covers full memory outside an explicitly excluded 64-byte
private SS frame region, returned GPR/BP/CF/IF/DF and four child-call boundary
requests. It executed 5,394,816 original instructions and 459 of the 579
locations in the eight-entry fence. The fence is not an all-path claim.
Nested calls counted 51,200 table lookups, 2,560 line calls, 3,072 limit
calls and 46,080 clamp words. Equal and independent DS/SS views are each
represented in 512 cases. Each of the four initial line-opcode forms has
256 cases, using a fresh CPU per fixture.

These fixtures deliberately use synthetic zero-weight inputs, width 16 and
an empty sentinel list. They admit normal bounded counts for this comparison
only. They do not establish those values or bounds in an actual session.
The raw `2C2A` owner writer, every producer/alias/lifetime, resource-fed table
bounds, live SS frame separation and IRQ/reentry exclusion still require
closure before integration. Divide faults and native budget prefixes remain
separate helper evidence; neither is treated as a successful root return.

[Receipt](evidence/td2ega-finish-loop-composition-v1.json). Counts are separate
from helper-suite totals. No actual BIOS/DOS/device service, IRQ delivery,
game session, renderer, audio output, full state machine, gameplay or fidelity
acceptance is established. CGA remains behind EGA portable contract closure.
