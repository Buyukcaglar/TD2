# Three live point updates

`06C9:3A91` reads current DS:[52CA], calls actual3AB8 with BX0/color0C,
then reads DS:[52D2] for BX2/color09, then DS:[52DA] for BX4/color0E.
Each read occurs after the preceding call. Device writes can therefore
change later inputs or cached words. Actual near3AB8 and farBA3C frames,
registers and memory effects are retained. The parent owns no register saves.

One pixel-CALL cap and one device-event cap span all three updates; an outer
cap limits the three near calls. Setup reads and MOVs happen before each
budgeted call. Normal return preserves the third child's actual arithmetic
flags. A changed third child sets CF for parent SP2..7 and ZF for SP2;
an equality third child returns its comparison flags. The known caller's
3945 CMP replaces them. Plain near RET consumes two bytes.

The C17 `/W4 /WX` build passed13,568 original-instruction comparisons:
1,442,204 executed instructions and all103 sites. Whole memory, registers/BP,
CF/IF/DF, root ZF, device requests, counters and control match. This includes
252 raw child returns, four changed root returns and360 nested pre-RET
qualifications. Thirty-seven native checks and the13-site static review
remain separate. The accepted child sources and evidence did not change.

RS281 gains a conditional indirect reader/writer, and RS279 a conditional
indirect mask consumer; no new initialized span is asserted. The three
source-word views have unresolved units, writers and storage ownership.
Actual caller DS/SS, coordinate domains, all writers, capacities, lifetime,
interrupt exclusion, device latches, renderer and core integration remain
open. Raw RAM device adapters and isolated comparisons establish no DOS
session, audio output, complete state-machine, gameplay or fidelity acceptance.
CPU/A20 behavior and physical086C semantics remain unqualified. CGA stays
behind EGA code-contract closure; full resource decoding has not started.
