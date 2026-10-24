# Segmented member byte reordering

`FN-EGA-000252` (`06C9:C838`) takes four SS words: header offset/segment
and scratch offset/segment. It reads the raw count through the header
segment, selects the relocated principal DS before actual `C701`, and
consumes that helper's normalized AX/DX as SI/DS. Offset zero with a
nonzero segment remains a valid far address.

The body reads the member's high nibbles at +F and +E, two shape words at
+0/+2, and their low-word product. Selected mask bits trigger a column
traversal into scratch followed by copying back to the member. Four plane
iterations advance the local member pointer even when a plane is skipped.
These instruction-backed consumer fields do not admit a complete supplied
file format or resource decode.

STOSB and REP MOVSB honor incoming DF; explicit ADD SI,BX stays forward.
Widths, heights, product, address arithmetic and local rereads retain word
wrap and alias effects. Zero-width LOOP and zero-height row progression
are not replaced with empty loops. The member loop executes at least once.
Its DEC/JG guard retains signed overflow: `8000` becomes `7FFF` and exits.
Testing only whether the decremented word is positive would be wrong.

The clean C17 build and selected comparison-v3 passed 17,388 cases,
2,654,760 instructions and all 125 parent/child sites. Full bus, SS locals,
saves, arguments and far frames, GPR/BP/CF/IF/DF, control and write counts
match. Coverage includes 27,060 actual C701 calls, 105,048 byte transfers,
864 minimum-SP54 cases, 8,694 incoming-DF1 cases, 5,900 SS scratch aliases,
320 signed-DEC discriminators and 76 altered root returns. Twelve native
interface diagnostics are separate. Budgets stop before a member, plane,
transpose byte or REP byte; executing-code writes are excluded and checked.

The direct caller `1748:013B` passes a pair saved from `6D50` and the pair
returned by `70A3`. Under the reviewed allocator's normal contract, the
scratch offset is zero and DX selects its segment. Its request `1F6` is
in paragraphs, giving a nominal 8,032 bytes. Comparison-v3 adds 1,536
zero-offset scratch cases. The caller executes ADD SP,8, then releases
the scratch pair through `7490`.

The packed-loader result still requires its pass-chain contract: `6B02`
returns a far resource pointer; a final `7C16` can return an intermediate
byte count. The actual producer/header alignment, file grammar, scratch
and resource capacity, all writers and lifetime are unclosed. The full
`1748` body, transitive caller context, IRQ exclusion, other FLAGS needs
and core integration remain open.

Comparison-v1 passed the earlier fixtures. Its exact validator is archived.
A shell edit failed before file changes; the redundant unmodified v2 run
was stopped by its verified process identity before producing a receipt.
The corrected v3 adds the actual zero-offset caller case; C and DLL bytes
are unchanged. No source-comparison or compilation failure occurred.

No supplied resource decoding, actual DOS session, renderer/audio output,
complete state-machine, gameplay or fidelity gate is established. CGA
remains behind EGA portable code-contract closure.
