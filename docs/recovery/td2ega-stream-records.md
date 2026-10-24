# Raw record setup, membership and scan

| Entry | Instruction-derived contract |
| --- | --- |
| 13A8:0F16 | One SS near record pointer. Increment DS6DF2, test special6DFC/6E04/6E14 records, sign-extend their byte index and multiply by six with word wrap. Ordered near8440/count200/record/side-flag stores; the second family also saves a signed flag word at83D4. AX1/0 and CF0; actual SI/DI/BP saves restored. |
| 13A8:2170 | One SS word, low byte only. Preserve CH, scan DS6F1E with explicit INCSI independent of DF. NUL test precedes byte comparison, so requested zero returns AX0. MatchAX1, missingAX0, raw missing-NUL/missing-byte cycles retained. |
| 13A8:219A | No stack argument. Scan eight-byte records from6DF4 through an old-SI equality test against currentDS6F0C. First free-mask83 record gets ordered count/flags/base/index resets and returns a near offset. Used endpoint returns AX0. Unaligned endpoints can cycle. |

All use plain far RETF4. The first two callers own their arguments; no
callee argument cleanup or host C pointer/type is inferred. Local stack
space in2170/219A is reserved without inventing initialization writes.

The clean build-v1/comparison-v3 passed 56,904 cases and all 112 sites,
with 3,751,616 original instructions. Full bus including SS, GPR/BP/CF/IF/DF,
counts and return coordinates are compared. There are 48,404 far returns,
8,500 prefixes, 288 overwritten far-return coordinates, 18,432 negative-index
fixtures and 576 selected return-frame alias fixtures. Four full 65,536-byte
membership cycles stop at diagnostic prefixes; four full 8,192-record scans
reach their inclusive endpoints. Fourteen native checks are separate.

Comparison-v1 passed its original fixtures. V2 added an index that survives
return-frame aliasing plus guard-clear far-segment fixtures, exercising the
actual overlapping write paths. V3 corrects the raw-return coverage count
to compare against each fixture's initial return segment. C and DLL stayed
unchanged; exact earlier validators and receipts remain preserved.

Static review records four direct caller sites. Each executes ADDSP2 or
MOVSIAX/ORSISI before the first branch, so that branch uses newly defined
arithmetic flags. New/indirect callers and later undefined-FLAGS requirements
remain open. Initialized data identifies a five-byte membership candidate
(four nonzero bytes plus NUL), twenty eight-byte record candidates followed
by twenty six-byte side candidates, and initial inclusive end6E8C. These
are bounded initial views, not a full resource format, writer proof or host
FILE layout. Payloads remain external.

Actual caller/index/handle/bounds/writer/lifetime/exclusion and core obligations
remain open. No DOS session, device, renderer, audio, complete state-machine,
gameplay or fidelity gate is established. Full resource decoding remains
pending; CGA remains behind EGA portable code-contract closure.
