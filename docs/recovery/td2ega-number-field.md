# Raw formatter number field

`13A8:20F0` takes two SS words containing current-DS output and input offsets.
It retains a raw `*` argument cursor at DS8404, optional minus in an actual SS
local, signed byte digit guards and decimal arithmetic that wraps at 16 bits.
Its leading-zero branch conditionally writes the word0030 to DS8402.

The final word `IMUL` uses the actual sign local and wrapped DI. For example,
32768 has DI8000; multiplying it by minus1 produces DX0000/AX8000 with carry1.
The output pointer is reread from SS, and the word store precedes actual saved
register and far-return reads. Aliases can therefore change those reads.
AX returns the input cursor. Incoming DF remains unchanged.

The C17 `/W4 /WX` build passed8,144 comparisons,295,120 original instructions
and all54 sites. Full bus/SS, GPR/BP/CF/IF/DF, control and write counts match.
Coverage includes4,072 DS=SS cases,1,536 minimum-SP16 cases,638 changed far
returns and1,488 before-digit budget prefixes. Eighteen native diagnostics
are separate. A diagnostic setup initially selected the wrong SS for its
alias case; the corrected native packet is v2. No C change was required.

Both direct calls from192C use PUSH CS plus near CALL, forming far frames.
Their immediate ADD SP,4 discards returned arithmetic status flags. Whole
formatter state, input/output bounds, argument-cursor writers, lifetime,
interrupt exclusion and core integration remain open. Raw far targets are
exposed after RET and never followed. No resource schema, DOS session,
renderer, audio, gameplay or fidelity acceptance is established.
