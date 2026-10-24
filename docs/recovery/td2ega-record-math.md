# Raw record arithmetic kernels

Five near entries are recovered: `5299` (FN391), `5022` (FN389), `5446`
(FN396), `4F92` (FN388) and `5B5A` (FN128), all in segment `06C9`.
They use raw DS fields and records. Units, resource formats, sortedness,
valid bounds and producer lifetime are not inferred from their arithmetic.

`5299` reads four record bytes with a ten-byte stride. The first byte's
sign selects stores to DS:3340/3342. Each masked seven-bit index is word
CBW-expanded and shifted twice, then selects DS:347F+4*index. The following
JL uses the preceding SHL's flags: its SF and OF are both zero for every
possible input, so AL is always negated. The unsigned maximum byte is
subsequently byte-absolute-valued, selects a word at DS:32EE+2*DL, and its
AL is multiplied by the low byte of DI. AX is stored to DS:3344; DX is DI,
and CF reflects the MUL upper byte. PUSH AX/POP BX restores the saved AX
containing the first record byte, rather than the incoming BX.

`5022` walks records backward with a minus-eight stride, a supplied origin
and DS:5356 end word. BP becomes a wrapping update count. `5446` loads
origins into BP/DI and separately walks the DS:39A5 and DS:3815 record
views, stores selected cursors and initializes other raw fields. Both use
low-word SUB followed by high-word SBB; signed branches retain overflow
and the low-word borrow.

`4F92` and `5B5A` use explicit DS overrides for BP+SI record operands.
Treating BP addressing as SS would change the source behavior. Their
initial, subsequent, forward and backward signed guards differ. Record
updates, wrap corrections, ring-end tests and field rereads retain their
instruction order. An arbitrary or unaligned end word can cause cycling;
no valid count or guaranteed termination is invented.

All entries use near RET, consuming two bytes from actual SS. The `4F92`
updating path saves/restores SI through actual SS; `5299` saves AX as
described above. Other register clobbers are retained. A native budget
stops before a documented loop site, retaining the prefix's real SS
writes and register state. Modified return targets are exposed only after
RET and are never executed by the comparison harness.

The clean C17 build passed 26,520 original-x86 comparisons, 1,760,060
instructions and all 267 sites. Full bus, SS frames/saves, GPR/BP/CF/IF/DF,
write counts and control coordinates match. Fixtures include 15,000 seeded
random cases, 13,260 DS=SS cases, 8,070 minimum-SP16 cases, 7,470 budget
prefixes and 160 altered near-return targets. Twelve native interface
diagnostics and 256 algebraic SHL/JL checks are separate from these totals.

Fifteen direct call sites in five owner bodies have instruction windows
recorded. Full caller FLAGS/DS/SS context, all writers, valid record/table
capacity, alias lifetime/exclusion and core integration remain open.
Original table values remain external. No full resource decoding, actual
DOS session, renderer/audio output, complete state-machine, gameplay or
fidelity gate is established. CGA remains behind EGA code-contract closure.

The [defined return-flag view](td2ega-record-flags.md) now extends4F92
without changing this frozen body. Actual4D3F PUSHF/POPF/JNE consumers
require ZF; AX cannot substitute. RawFLAGSimage/CPUprofile/SSword effects
and completeparent/core remainopen.
