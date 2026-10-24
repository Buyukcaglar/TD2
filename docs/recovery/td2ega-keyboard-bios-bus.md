# EGA installed keyboard BIOS handler with actual SS

18 October 2026. An additional [C17 interface](../../src/recovered/td2ega_keyboard_bios_bus.h)
covers `06C9:69B7` using the actual SS interrupt frame, saved BX/DS words and
ordered principal-DS pending/modifier accesses. The old group/data-bus interface,
source, DLL and receipts remain frozen. This original entry is counted once.

The [build](evidence/td2ega-keyboard-bios-bus-build-v1.json),
[25,184 comparisons](evidence/td2ega-keyboard-bios-bus-validation-v1.json) and
[static review](evidence/td2ega-keyboard-bios-bus-context-v1.json) cover all 27
sites and 354,342 original instructions at two loads.
They compare the whole 1 MiB RAM bus, GPRs/BP, CF/IF/DF, normal-return ZF,
CS/IP/SP, return kind and CPU writes. All 256 AH values and the admitted saved
CF/ZF/IF/DF combinations are exercised. The
[16 native diagnostics](evidence/td2ega-keyboard-bios-bus-native-diagnostics-v1.json)
are separate from original equivalence and helper vectors.

The handler pushes BX then DS before loading relocated principal DS. These
writes can change the pending word read at62B6. AH0 reads and clears that word;
the clear can overwrite saved DS, saved BX, the return IP or the saved FLAGS
word. Actual pops and returns retain this ordering, so BX/DS preservation
depends on the saved storage. With SS equal to principal DS and entrySP62B2,
pending62B6 is the saved FLAGS word; clearing it changes the IRET flags.

AH1 reads pending, executes STI and OR AX,AX, restores DS/BX and uses **RETF 2**.
It skips the saved FLAGS word, forces IF=1, retains entry DF and returns CF=0
with ZF from the actual AX. Other AH paths use **IRET**, restoring CF/ZF/IF/DF
from the actual SS FLAGS word after body writes. AH2 combines two modifier
bytes into AL while retaining AH=2; unhandled AH values return AX=0. Both
return forms consume six bytes from handler entry. The result is 44 bytes.

The standalone API receives an existing IP/CS/FLAGS frame; it does not claim
to deliver INT16. Native zero reports the actual root return without following
raw coordinates. Native two rejects invalid interfaces before effects. Native
five stops before an unqualified boundary: RETF2 with SP above FFFCh or IRET
with SP above FFFAh. No historical CPU fault or return behavior beyond that
analysis boundary is inferred. Other FLAGS, traps and interrupt delivery are
outside the exposed contract.

The installer code publishes69B7 in IVT16 and clears90 key-flag bytes. Two raw
initialized candidate views are registered without accepting a resource format:

- RS293: the two-byte pending word at62B6, published by6907 and read/cleared
  by69B7. The installer does **not** reset this word.
- RS294: the90 key-flag bytes at62BA..6313, cleared by6860 and written/read
  by6907. Modifier reads62E4/62F0 and the6620 direction reads lie inside.

Their hashes and literal producer/consumer footprints do not establish actual
IRQ history, all writers, writable capacity, ownership, lifetime or exclusion.
Payload remains external/private. Eight INT16 sites are identified in the
initial instruction ledger; mutable, unclassified and external domains remain
separate. Prior typed BIOS profiles and compositions retain their own scopes.

Whole420A/403B still requires the actual-stack input/key-dispatch/gameport
interfaces and caller integration. No actual installed-handler ownership,
INT/IRQ delivery, DOS game session, real devices, renderer, audio output,
complete state-machine validation, gameplay or fidelity acceptance follows.
Full resource decoding, Windows gameplay and Amiga recovery have not started.
Physical086C remains unassigned. CGA stays behind EGA code-contract closure.
