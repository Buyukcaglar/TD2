# EGA ordinal search caller

2026-10-13. Complete `16B8:0000` (`FN-EGA-000351`) has one native export
linking the [search helpers](td2ega-find-files.md), a
[C17 build](evidence/td2ega-find-nth-build-v1.json), and
[131,986 comparisons](evidence/td2ega-find-nth-validation-v1.json) against
the original caller and actual5EF4/5F4E instructions. DOS responses are synthetic.

The routine always calls FindFirst, saves AX and initializes a local index
to one. Its comparison with the requested ordinal is signed16-bit. Values
zero, one and negative words return the first result. Positive values above
one call FindNext, including when the first result was AX0. The loop stops
at the requested index or a zero next result. Each next call receives the
ordinal in AX before its SetDTA instruction; final AX is restored from the
last search result. It is a near path5D88 or zero, not a count.

All65,536 ordinal words are compared at two load bases, together with staged
search failures, stale basename destinations and a full7FFFh success sequence.
The actual first-failure continuation occurs in264 synthetic cases.32 cases
combine it with next success and stale5DEC=66E6, causing the original/native
13-byte replacement copy to alter ring fields. These are conditional alias
witnesses, not an actual DOS execution, reachable reset proof or seed policy.

The [historical Microsoft API reference](https://github.com/microsoft/MS-DOS/blob/2d04cacc5322951f187bb17e017c12920ac8ebe2/v2.0/source/SYSCALL.txt)
requires a valid FindFirst search block for FindNext. Actual state after a
failed first request, prior search history, DOS version and exclusive DTA/
basename ownership therefore remain explicit obligations. A successful
exclusive FindFirst establishes the bounded5D88..5DDF replacement range;
the caller does not independently check that success before continuing.

Full group bytes, service/current-DTA sequence, registers/ES/IF/DF, original
local index/last result, both unchanged arguments and far frames match.
[Three supplemental native diagnostics](evidence/td2ega-find-nth-native-diagnostics-v1.json)
check a missing adapter and budgets zero/one while retaining prefix effects.
They execute no original instructions and are excluded from differential
vector totals. Native budgets add no claimed original error path.

The two discovered media callers0432:0D35/0F71 still need their complete
history and resource-lifetime contracts. No actual filesystem/search results,
full resource decoding, IRQ/core integration, DOS game session, renderer,
audio, gameplay or fidelity is accepted. EGA closure continues to gate CGA.
