# Runtime guard and record reset wrappers

`FN-EGA-000291` (`13A8:184A`) takes one SS word. FFFF returns zero;
other values select bit four at DS:[BX+6F57]. When set, PUSH CS and a
near CALL invoke the actual far-return `190E` body. Its result is reduced
to zero or one. No handle bound or host stream type is invented. Normal
CF is clear; the other modeled state comes from source instructions and
actual SS restoration.

`FN-EGA-000282` (`0DF0`) takes one near record offset in current DS.
It requires both the byte+6 mask83 test and bit08 before calling actual
`2696` with word+4. After return it clears bit08, sets AX zero, and stores
zero to record base, +4, then +2 in that order. A skipped guard preserves
the incoming AX. The child's zero-pointer guard applies specifically to
its free-bit write; it supplies no global near-zero/host-NULL rule.

Actual child GPR/BP/DS/CF/IF/DF and bus effects are retained. The free-bit
write or positive-counter decrement can alter real SS saves or return
words. Changed child coordinates are exposed after RET and never followed.
The 184A native budget stops before PUSH CS; the 0DF0 budget stops after
pushing its argument but before the far CALL. Their live stack prefixes
are different. Root minimum SP22/SP26 ensures each frozen child SP16.

The clean C17 build passed 65,280 original-x86 comparisons, 829,596
instructions and all 55 wrapper/child sites. Full bus, SS arguments/saves/
far frames, GPR/BP/CF/IF/DF, control and write counts match. There are
22,272 minimum-stack cases, 32,640 DS=SS cases, 16,800 actual child calls,
828 raw child returns and 240 altered root returns. Twelve native
interface diagnostics are separate.

Four direct callers have instruction windows recorded. `0978:09B7` uses
a far CALL to 0DF0. `16FC:1763`, `1797` and `17FA` use near CALLs to
184A preceded by PUSH CS. All immediately execute ADD SP,2, removing
their one argument and redefining arithmetic FLAGS. Both wrappers return
with plain RETF, consuming the four-byte far frame.

Whole caller bodies, record/arena bounds, actual field ownership and all
writers, alias lifetime, IRQ exclusion, other FLAGS requirements and core
integration remain open. No host stream type, actual DOS session, complete
state-machine, renderer/audio output, gameplay or fidelity gate is established.
CGA remains behind EGA portable code-contract closure.
