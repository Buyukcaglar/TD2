# EGA gameport routines with actual SS and ordered port state

18 October 2026. Three additional [C17 interfaces](../../src/recovered/td2ega_gameport_bus.h)
cover6686,680A and6828 using current DS and independent SS. The earlier group
interfaces, sources, libraries and receipts remain frozen. These original
entries are counted once. The new result is48 bytes; each port request is40
bytes and records GPRs/BP, CF/ZF/IF/DF, CS/IP/SS/SP, operation, port and value.
The typed byte-port adapter preserves RAM, registers and flags; only IN returnsAL.

The [build](evidence/td2ega-gameport-bus-build-v1.json),
[20,232 comparisons](evidence/td2ega-gameport-bus-validation-v1.json) and
[static review](evidence/td2ega-gameport-bus-context-v1.json) cover all150 sites
and 31,334,942 original instructions at two loads. They compare
the whole1MiB bus, GPRs/BP, CF/IF/DF, normalZF, actualfarreturn coordinates,
CPU writes and every ordered full port request. The
[18 native diagnostics](evidence/td2ega-gameport-bus-native-diagnostics-v1.json)
are separate from original equivalence and helper vectors.

6686 preserves its literal disabled path, ordered initial read/state writes,
CLI/OUT/poll/STI sequence, partial axis counts, calibration and final read.
X minimum and thresholds are signed; Y minimum and thresholds are unsigned,
while both maximum/candidate checks are signed. SUB/JLE uses the original
signed operands even on overflow; DIV and logical shifts use the wrapped word
difference. Defined flags and scratch values follow the literal operations.
Final XORAH,AH returnsCF0/ZF1 even when AL is nonzero. No physical units are
assigned to counts, calibration fields or constants.

The static finite-state review covers12,000 counter/active-mask states. At most
4,000 non-completing polls incrementCX, and at most one axis completion can
continue without incrementing it. The maximum is4,001 poll INs, plus initial
and final reads: **4,003 total INs**, under the adapter profile and exclusion
assumptions. Native diagnostics include the sharp bound and a4,002-read budget
stopping before the final IN afterSTI. This is no elapsed-time or device-rate claim.

680A has only MOV effects, preserving incoming CF/ZF/IF/DF and scratch GPRs.
The API therefore receives explicit incomingZF. Its five DS writes can overwrite
actual SS far-return words. 6828 saves BP before reading its SS argument and
the live DS byte at629E+(argument&15); the saved BP can overwrite that lookup.
The native discriminator returns78h from a saved5678h BP over an earlier11h byte.
Its final XORAH,AH also returnsCF0/ZF1. All three roots use plainRETF and caller
cleanup. Actual changed return coordinates are reported without following them.

All word SP values are admitted through the existing qualified boundary:
native5 stops before RETF when SP exceedsFFFCh. Native2 rejects invalid
interfaces;3 stops before an IN budget;4 reports a failed adapter. Those are
native outcomes, not original errors, historical CPU faults or hardware behavior.

RS295 records the initialized50-byte raw view627C..62AD: counts/button fields,
calibration/count/scale words and16 translation bytes at629E..62AD. It has no
intersecting relocations. Literal DS writers6686/680A and conditional SS saved-BP
writer6828 are recorded. The view lies outside the known DAT copy. Byte identity,
index footprint and known writers do not establish all producers, runtime
capacity, ownership, lifetime, exclusion, units or a resource format. Payload
remains external/private.

Six caller sites are reviewed. In420A, PUSHAX4219 supplies the6828 argument;
POPBX421F consumes it before ANDBX30h. That is not a saved-BX restore. The other
translator caller uses ADDSP2. After65D9, TESTAX30h replaces sampler arithmetic
flags;6620 returns directly after6680, allowing them to pass to its outer caller.
Whole caller/stack/field/IRQ admission remains open.

Whole input polling/key dispatch/420A/403B, all writers, actual device/IRQ
behavior, storage/lifetime and P1-GATE remain open. No DOS game session, renderer,
audio output, complete state-machine validation, gameplay or fidelity is
established. Full resources, Windows gameplay and Amiga recovery have not started.
Physical086C remains unassigned. CGA stays behind EGA code-contract closure.
