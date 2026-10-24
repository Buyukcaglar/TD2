# EGA signed motion, far multiplication and ES scanner with actual SS

18 October 2026. Three additional [C17 interfaces](../../src/recovered/td2ega_motion_scan_bus.h)
cover `06B3:0008`, `13A8:2EE8` and `06C9:44A6`. The earlier group/scalar
interfaces, sources, libraries and receipts remain frozen. These three original
entries were already portable; this packet adds no new unique entry.

The [build](evidence/td2ega-motion-scan-bus-build-v1.json),
[50,512 comparisons](evidence/td2ega-motion-scan-bus-validation-v1.json) and
[static review](evidence/td2ega-motion-scan-bus-context-v1.json) cover all 166
sites and 2,199,880 original instructions at two loads.
They compare the whole 1 MiB RAM bus, GPRs/BP, CF/IF/DF, defined normal-return
ZF, CS/IP/SP, actual CALL counts and CPU write counts. The
[18 native diagnostics](evidence/td2ega-motion-scan-bus-native-diagnostics-v1.json)
are separate from original equivalence and helper vectors.

Motion creates its real SS frame: saved BP, error at BP-2 and correction at
BP-4. Those writes and later argument pushes may alias current-DS fields;
subsequent reads retain instruction order. The original signed shifts, CBW,
CWD, signed IMUL by 120, unsigned MUL, wrapped absolute 8000h and clamps are
preserved without assigning physical units. The scale factor is 193..256 from
100h minus word30E6 shifted right ten. Byte moves extract the product logically
by eight bits before the correction clamps and ordered field writes.

The actual far CALL at 0114 pushes the motion CS and 0119 return word. The
multiply saves BP and reads four SS operand words at BP+6/+8/+10/+12. With no
intervening memory writes, frozen scalar multiplication supplies the low
32-bit result; the actual saved-BP write, stack reads and return are materialized.
Fast multiplication preserves CX and defines CF; its undefined ZF is excluded.
The general path returns wrapped cross-term CX and final ADD-DX CF/ZF.
**Multiply uses RETF 8**, consuming its four argument words and far frame.
**Motion uses plain RETF**. Result size is 48 bytes.

Motion entry SP is admitted from 20 through FFE0h, placing the deepest saved
BP at entrySP-20. Standalone multiply admits all word SP values but reports
native status five before RETF when SP exceeds FFFCh. That boundary preserves
the existing qualified backend profile; it does not claim a historical CPU
fault or return convention. Scanner admits SP zero through FFFEh, with actual
near-RET wrap and return-word alias effects. Native zero reports the root return;
one reports a raw child return without following it; two rejects invalid
interfaces; three stops before the multiply CALL budget; four stops before an
unrecognized scanner JMP. Parent composition must check return coordinates.

Scanner AX=0 returns immediately and retains incoming DF, BX, CX and DI. Its
nonzero path sets CX=5, DI=33DAh and DF=1, compares AL backwards against **ES**,
then clears DF even on no match. Remaining CX is doubled to select one of five
near words from **DS:33DC..33E5**. The three initialized actions at 44BF, 44C5
and 44D2 and the known bare RET tail at 44BE are admitted. Other raw words stop
before JMP44BA. The ES bytes and DS table can use different segments. Their
principal bindings to existing RS271 are conditional; no new extent or actual
all-writer/valid-target/lifetime proof is inferred.

The static review identifies 19 direct caller sites, including motion4261 and
scanner427D in 420A. After motion, 6601 invokes INT16 before branching on
returned ZF; this boundary has no unconditional flag-kill claim. After the
scanner, 420A returns directly, so its defined arithmetic flags can survive
until outer403B40DCCMP33D4. For the motion component, caller420A SP must be at
least24 before the far CALL; this is not whole420A/403B stack admission.

Whole420A/403B, actual input/handler interfaces, mutable transitions, callers,
valid domains, all writers, storage capacities, ownership, lifetime, exclusion
and P1-GATE remain open. Full supplied-resource decoding, Windows gameplay and
Amiga recovery have not started. No DOS game session, real BIOS/DOS/device/IRQ
delivery, renderer, audio output, complete state-machine validation, gameplay
or fidelity acceptance follows. Physical086C remains unassigned. CGA stays
behind EGA portable code-contract closure.
