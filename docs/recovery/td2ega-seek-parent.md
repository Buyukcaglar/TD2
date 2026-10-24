# Three-call seek composition

`FN-EGA-000336` (`13A8:2AD8`) takes one SS handle word, saves BP/SI
and reserves eight local bytes. It calls the actual frozen `225E` C body
with mode1/offset0. Returned AX/DX are stored in actual SS; both FFFF
trigger an early FFFF:FFFF return. A successful raw offset FFFFFFFF is
indistinguishable from that sentinel here.

The next call uses mode2/offset0. Its AX/DX are saved even on error. A
third call uses mode0 and the first saved pair, reread in source order.
The third result is ignored, and the second saved pair is returned. No
compensating transaction or successful restore is inferred. Each next
handle uses the SI actually returned by its predecessor, rather than a
cached original handle. BP/DS/CF/IF/DF and bus changes also propagate.

All argument pools, nested far and near frames, SS locals, saved SI/BP,
cleanup and returns are literal. Each child far return checks CS/IP/SP
before continuation. Changed coordinates are exposed after RET and never
followed. Root minimum SP48 leaves child SP24 after the root saves/locals,
eight argument bytes and four-byte far frame.

The C17 `/W4 /WX` build passed 29,904 comparisons, 1,101,706 original
instructions and all 99 feasible sites in the 122-site parent/child fence.
The 23 excluded child sites belong to negative-offset query/end/restore
preflight: the first two parent pools have literal zero offsets, and the
third has literal mode0. Their exclusion applies only to this composition;
the standalone `225E` suite exercises every one of them.

Full bus/SS/GPR/BP/CF/IF/DF, service requests, control and counts match.
Coverage includes 22,984 actual far calls, 7,880 synthetic DOS services,
15,668 actual mapper calls, 9,216 minimum-SP48 cases, 3,824 altered seek
child far returns and 96 altered root returns. No raw mapper near return
occurred in these selected parent fixtures; the standalone child receipt
records that separate coverage. Thirteen native interface diagnostics,
including the ignored third result, are separate.

The single caller `0432:06CB` word-sign-extends byte `[BX+7]`, pushes it,
calls this entry, then immediately cleans the argument with ADD SP,2.
That ADD replaces arithmetic status flags before later flag use. The whole
caller, record/handle producers, ownership, bounds, writers, lifetime,
IF/DF context and interrupt exclusion remain open before core integration.
No actual DOS session, renderer, audio output, complete state-machine,
gameplay or fidelity is established. CGA and later resource/Windows/Amiga
work retain their existing phase order and acceptance gates.
