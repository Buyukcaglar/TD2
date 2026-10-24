# EGA key dispatcher with actual SS and callback return control

18 October2026. An additional [C17 interface](../../src/recovered/td2ega_key_dispatch_bus.h)
covers6528 using the actual SS key argument, saved words, current DS and far
return. The prior group interface/source/DLL/receipts remain frozen. This
original entry is counted once. Request/response/result sizes are34/36/48bytes.

The [build](evidence/td2ega-key-dispatch-bus-build-v1.json),
[35,584 comparisons](evidence/td2ega-key-dispatch-bus-validation-v1.json) and
[static review](evidence/td2ega-key-dispatch-bus-context-v1.json) cover all42
original sites and630,232 original instructions at two loads. They compare
the whole1MiB RAM bus, GPRs/BP, CF/IF/DF, normalZF, actual control and CPU writes.
There are1,364 raw child returns,842 changed root coordinates,1,122 changed-DS
callback cases,48 callback targets read from saved BP and144 saved-BP guard
cases. The [19 native checks](evidence/td2ega-key-dispatch-bus-native-diagnostics-v1.json)
are separate from original equivalence and helper vectors.

Callback bodies in this unit are explicit ABI effects followed by a private
generic RETF instruction. The11,998 synthetic callback returns are excluded
from the original-instruction count and establish no callback body semantics.
The public response reports a retired far return or explicit prefix, actual
CS/IP/SP, full exposed register state and CPU-write count. It can wrap a later
recovered callback body without executing its return twice.

PUSHBP precedes the guard read, so an SS alias can force the busy path. The
nonbusy path publishes the guard, reads its SS key, rewrites it on the ASCII
path and reads the current-DS near word. BX captures the target before saved
DI/SI, explicit CS and the actual near CALL write their stack words. A callback
frame thus contains IP655B followed by relocated6C9, at root entrySP-10.
Callback return CS/IP/SP must match before the dispatcher pops SI/DI, forces
AX0, clears the guard via returned DS, restores BP and retires plainRETF.
Changed child coordinates are reported without following them.

Busy returns CF0/ZF0 andIF1. A missing callback returns the current argument
in AX but retains CF0/ZF1 from ORBX,BX, even for nonzero AX. A normal callback
path returns CF0/ZF1 from XORAX,AX while callback IF/DF survive. Saved SI/DI/BP
and root return words can be changed by callback memory effects. No blanket
saved-register or original-DS guard-clear assumption replaces these reads.

Native3 stops before CALL6559 after PUSH DI/SI/CS;4 diagnoses a failed or invalid
service;5 stops before an unqualified far return or forwards a child boundary.
Native1 reports raw child control. Root SP spans all word values through these
explicit prefixes; other FLAGS, CPU boundary behavior and actual caller stack
storage remain separate obligations. Native outcomes are not original errors.

RS296 records522 initialized zero bytes6048..6251:128 ASCII near words and133
extended near words. Exhaustive word selectors address261 positions. Known
conditional DS writers6585/16FC:0002 and the dispatcher's own SS argument/frame
writes are recorded. The potential signed-negative setter domain covers32,640
even DS word offsets; known direct installer calls use only six small keys.
This introduces no claim that the wider inputs are reachable. Initial zeros,
index bounds and six registrations do not close all writers or valid targets.
The6559 indirect review remains complete=false. Payload remains external/private.

Both direct callers push AX before the far call and use ADDSP2 after return.
Callee SP equals caller SP minus6; the callback frame is caller SP minus16.
Their ADD replaces arithmetic flags. Actual caller storage, callback bodies,
ownership/lifetime, writer domains, exclusion and IRQ behavior remain open.

Whole input polling/420A/403B and P1-GATE remain open. No DOS game session,
real devices, renderer, audio output, complete state-machine validation,
gameplay or fidelity is established. Full resources, Windows gameplay and
Amiga recovery have not started. Physical086C remains unassigned. CGA stays
behind EGA portable code-contract closure.
