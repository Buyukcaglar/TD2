# Main-called mutable control and segment context

The initial-image tail review is **not an unconditional later-session return contract**. Main calls `13A8:002E` at0907 and09FF. That routine changes its own instruction boundaries and writes state/simulation opcodes in `06C9`. [1,920 isolated loaded-copy cases](evidence/td2ega-main-mutator-validation-v2.json) verify the currently observed paths with synthetic INT11 responses, two load segments, selected-drive words and carry inputs. No real BIOS, disk, DOS process or game session was executed.

The routine first installs NOP at its own offsets00BB/0154/03DA. In particular, the initial disassembly's AND at0154 consumes bytes that later become a NOP and a JMP at0155. The prepared code reaches015E, loads the saved near return from CS002C, pushes it and RETs at0162. Entry007E previously popped that return and has no conventional BP frame. Its two current callers resume at006E/007B. This is an additional reconstructed control-flow mechanism beyond the44 explicit indirect sites.

It also writes the current saved-stack position to physical0010h and literal0201h to0012h, then uses0010h to restore SP before popping the outer saved DS/ES/DI/SI/BP and RETF. Those low-memory words are not restored by this routine. Its own temporary DS domains are zero, CS, relocated06C9 and relocated1793; the latter aliases principal178F plus40h. It reads the selected-drive word through1793:5617, which aliases principal5657, and writes a byte through1793:5616, aliasing principal5656. Treating every DS access as the principal group would be wrong.

Each query compares the selected word's low byte against `(INT11_AX & 00C0h) >> 6`. There can be two separate queries; their responses need not be conflated in the recovered interface. The observed sequential outcomes are:

| Query result | `1BF7` | `424A / 4275 / 42AD` | Principal5656 | AX return |
| --- | --- | --- | --- | --- |
| First rejects | CLC (`F8`) | JBE / JBE / JA | 99 | Selected-drive word |
| First admits, second rejects | CLC (`F8`) | JNE / JNE / JNE | 99 | Selected-drive word |
| Both admit | RETF (`CB`) | JNE / JNE / JNE | 0 | 0 |

The three JNE bytes come from the admitted image's CS03D2 byte75h. Their branch displacements do not change. Historical intent, protection/patch origin, supported firmware profile and gameplay implications remain unassigned. Do not replace the comparisons by a generic always-success result or reinterpret these bytes as immutable simulation conditions.

The [four separate static code-state shadows](evidence/td2ega-mutable-control-map-v2.json) retain the initial image and three observed prepared outcomes in private revision `analysis/flow/mutable-states-v2`. Each has439 registered candidates and no conflicting instruction boundaries **within that state**. Code-byte counts differ:92,274 initially;92,272 in prepared first-/second-reject states;92,262 after both queries admit. These conservative snapshots do not propagate later mutation, restore-state ordering or interrupt interleavings. They are not a complete mutable program graph or code-recovery percentage. The original image and saved canonical program bytes stay unchanged.

## Consequence for the state return

[2,048 epilogue cases](evidence/td2ega-state-tail-modes-v1.json) execute1BF0 through either tail mode, with every state byte, both carry inputs and two load segments. Saved SI/DS/BP and far frame restore correctly; DI remains untouched.

With RETF at1BF7, AX is the sign-extended byte loaded from DS5490. The tail preserves its incoming ES and CF and does not write physical0086h. With CLC at1BF7, the subsequent initial-image instructions return AX=2/ES=2/CF=0 and write word2 to physical0086h. The earlier twelve cases beginning at the eleven-byte CLC tail remain valid isolated evidence for that byte state; they do not prove which state a complete caller reaches.

The literal physical086Ch reader is a separate issue. None of the observed mutator writes targets its code or that external word. Its address is still verified, while content/timebase/cadence remains unassigned. This discovery explains conditional reachability of the physical0086h write; it does not convert the086Ch read into an accepted timer.

## Analysis and closure boundary

The initial-image graph's compiler-runtime classification for13A8 entries was only a heuristic.002E/007E/0163 are now explicitly mapped as a main-called mutable platform/control family. Saved near-return context, code-state-dependent branches and the tail mode must inform P1-05/07/08/11. A single initial-image disassembly cannot close their supported semantics.

The separate Ghidra context-v2 project retains the startup ranges and adds only instruction-established DS domains for this family. Entry/restored caller DS stays symbolic and SS is inherited. No prepared opcodes are written into the canonical Ghidra program; use the shadow ledgers for their boundaries. Full mutable transition/caller, platform interrupt/vector lifetime, resource-fed behavior, portable game/CGA, runtime and fidelity gates remain open.

[Retry composition](evidence/td2ega-retry-mutator-context-v1.json) adds224 cases (39,264 original instructions):main09D2 cleanup,09D5 comparison, unconditional09D8 jump, DEC AX/store5657, actual002E andstore007C. With synthetic helperAX1, selectedword0 admits all tested equipmentindex pairs and installsRETF/JNE/JNE/JNE. AX0101 also admits because queries compare the selected lowbyte. AX0 wraps toFFFF and rejects all tested indices. This stops before5D83 and does not establish actual0477 success, game history or timer semantics.

The current direct memory-operand ledger has only two046C operands, bothES reads5D88/5D95. TimerISR61BF insteadupdates principalDS5E8C..5E92 and indexed5E9E; oldINT8 relay6230 temporarily swaps vector08 atphysical20/22. These observations do not exclude computed/indirect external086C writers, firmware behavior or unsupported code states, and supply no timebase.

## Bounded native control-state recovery

[The composed C17 build](evidence/td2ega-mutable-control-build-v1.json) provides
two native exports for002E and0163;007E is represented by an internal helper
under its two borrowed-parent-frame call sites. [5,792 comparisons](evidence/td2ega-mutable-control-validation-v1.json)
cover5,760 actual002E invocations and32 direct0163 invocations. Three native
argument diagnostics are separate. These tests vary two loads, drive words,
two independent raw INT11 responses, IF/DF, initial DX/scratch bytes, caller DS,
stack position and ignored readonly comparison results.

Host C code is never patched. Explicit branch-form and return-mode fields
represent the observed original code states. The native result exposes the
physical0010/0012 writes, AX/BX/CX/DX, stub-call count and saved-near returns.
First rejection preserves incomingDX; any first admission leavesDX equal to
the full selected word. The finalCX is2706 on rejection and2701 after both
admit. The original outer XOR BX,BX leavesBX0 and defined arithmetic flags
CF0/PF1/ZF1/SF0/OF0; TF is cleared, IF/DF are preserved in the admitted profile.
0163 separately preserves flags and DS and returns relocated1793 inAX.

Scratch byte2B is cleared initially and later receives the selected word's low
byte. A zero value makes both admitted steps take the extra two no-op stub
calls; a nonzero value skips those two calls on the second step. Scratch2A is
unchanged if the first query rejects, otherwise ends10h. Scratch24 and saved
return2C reflect the last attempted query. These details remain explicit rather
than reducing the family to a single boolean equipment check.

The original CMPS results are bypassed by the supplied prepared code. Matching,
last-word-mismatching and baseline readonly CS/ROM comparison views produce the
same exposed effects. The native contract omits those effect-free reads; it
requires ordinary readonly storage and serialized execution. It also requires
the supplied03D3 JMP/RET stub, an AX-only INT11 response profile, TF0 and valid
nonwrapping stack storage. Actual firmware behavior, incoming single-step
traps, alternate patches, asynchronous mutation, complete caller/platform
profiles and gameplay remain open. The physical086C read is unchanged.
