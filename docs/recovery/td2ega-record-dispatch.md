# Raw record dispatch and two-word near unwind

`FN-EGA-000397` (`06C9:56ED`) has no SS arguments or PUSH AX prologue.
Eight possible calls execute the actual frozen5299,52FD,5334 and535B C
bodies. Their full returned registers, CF/IF/DF and memory effects feed
the threshold, table, curve and ordered partial-word stores. Minimum SP34
preserves the frozen52FD minimum SP32.

The near JMP at57A7 reads the actual mutable word at wrapped
`DS:[3460+2*(byte33B8-1)]`. The native body follows57AB,57B7 or57CF when
that exact word names one of those blocks, including retargeted table cells.
Other words produce native status6 before the JMP, retaining the actual
operand and its address. This is an unresolved control boundary, with no
source-error or closed-domain claim. The initialized five-word table has
three unique offsets, but byte0 reads345E and byte255 reads365C. Its ten
initialized bytes do not establish a valid mode bound. The existing indirect
review remains `complete=false`.

One path is an unusual near unwind. After relative SUB/SBB and signed
adjustments, the below-100 branch sets9258 and clears52DA/33B6/33B7/33B8/
33BA. It then executes POP AX at585A and a near RET at585B. AX receives
the actual first SS word; RET consumes the second, preserving CS. This is
not a far return or restoration of a saved AX. The result's `return_kind=1`
distinguishes it from the normal single-word near RET at587F.

The direct callers53A6:54F4 and5581 push their near-return words. The
two-word path can therefore bypass53A6 through the next SS word. Its whole
caller integration remains open; neither word is cached or assumed private.

The C17 `/W4 /WX` build passed38,736 comparisons,2,442,462 original
instructions and all249 feasible sites in the250-site fence. The remaining
5303 site has the existing entry-specific branch disposition. Full bus/SS,
GPR/BP/CF/IF/DF, control, dispatch operands and counts match. Coverage
includes79,744 actual near calls,270 POP AX/RET paths,768 altered child
returns,176 altered root returns,3,376 unknown-transfer boundaries and
2,576 mutable known-target cases. Eight cases alter the actual discarded
SS word. Fifteen native diagnostics are separate.

`RS-DOS-000269` identifies the external5636..5655 word view, indexed by
even offsets0..30 and lying wholly inside RS253. `RS-DOS-000270` identifies
the ten initialized code-offset bytes at3460..3469, while retaining the
larger raw byte-index envelope and open writers. Values, units, complete
resource formats, actual DS binding and immutable-table policy are unassigned.

All mode/target writers, complete53A6, caller bounds, ownership, lifetime,
interrupt exclusion and core integration remain open. No DOS session,
renderer, audio output, complete state-machine, gameplay or fidelity is
established. CGA and later resource/Windows/Amiga gates retain their order.

The sample-table review corrects a frozen validator comment: the actual
5299 DS32EE lookup has129 words (258 bytes,32EE..33EF), overlaps mutable
globals and excludes initialized jump tables3446..3469. The synthetic
256-word fixture fill extended beyond that source bound. Its final jump-byte
restoration describes fixture setup. Executed C, validator, DLL and comparison
receipts remain frozen; the matching comparison results are unchanged.
See evidence/td2ega-sample-table-context-v1.json and RS-DOS-000271.
