# Complete first byte-ring consumer

`FN-EGA-000019` (`019E:0004`) is a far entry with no SS arguments. It
calls `FN-EGA-000003` (`06C9:780E`) exactly once, masks AX with seven,
executes word CWD, and stores raw words to SS locals. Its comparison
chain maps categories 0..7 to `4800,5000,000D,000D,4D00,4B00,001B,0000`.
These values come from instruction immediates. No BIOS service or source
C declaration is inferred. Normal DX is zero and CF is clear for category
seven, set otherwise. BP restores from actual SS; IF and DF are retained.

The native composition invokes the unchanged recovered byte-ring C
transformation. A source-proven adapter materializes the actual far-call
frame and leaf PUSH SI, snapshots flat RAM after those writes, commits
the cursor before its selected byte, then performs actual SS POP SI and
far return. This requires serialized RAM without read side effects.
It establishes no interrupt exclusion and adds no lock or separate state.

The clean C17 build passed 67,584 original-x86 comparisons, 1,422,336
instructions and all 60 caller/callee sites. Full bus, ring state, SS
locals/saves/far frames, GPR/BP/CF/IF/DF, control and write counts match.
All eight categories execute. There are 2,048 minimum-SP30 cases,
33,792 DS=SS cases, 3,072 raw child returns and 4,096 altered root returns.
Native before-CALL and raw-target outcomes remain distinct from ordinary
return; targets are exposed after RET and never followed.

A separate 2,048-case original/native discriminator places the saved SI
high byte at DS:67E7. Cursor zero decrements to FFFF, selecting that byte;
the update changes what POP SI later reads. All 256 incoming high bytes,
four IF/DF profiles and two loads are checked. All 2,048 return changed
SI. Those cases and twelve native interface diagnostics are excluded
from the main helper-suite/vector totals.

Two actual callers are reviewed. `019E:0B00` PUSH CS followed by the near
CALL at `0B01` supplies a far-return frame. `0267:14FD` uses a far CALL.
Both later compare AX with `001B`, then replace that value with zero on
the shown path. Their CMP redefines arithmetic FLAGS before branching.
The larger owners' guards, DS/SS context, state and scheduling remain open.

This closes one complete consumer body. The eight direct consumption sites
remain shared users of the same ring; reset/seed provenance, all writers,
reentry/exclusion, lifetime and consumption across complete state transitions
remain required before core integration. No RNG policy, actual IRQ/DOS
session, renderer/audio output, complete state-machine, gameplay or fidelity
gate is established. CGA remains behind EGA code-contract closure.
