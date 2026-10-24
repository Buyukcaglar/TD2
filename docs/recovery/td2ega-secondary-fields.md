# Secondary raw-field controller

`FN-EGA-000390` (`06C9:50A1`) is a near entry with no SS arguments.
It always writes3340=100. Disabled3379 clears52D2 and returns. A nonzero
3375 is decremented as a byte; only a new zero computes a raw relative
SUB/SBB pair, selects52D4=-200 or200 using signed4/-4 guards, and clears52D6.

The main path has ten possible near calls to the actual frozen5299,5C5A,
52FD,5334 and535B C bodies. Full returned registers, CF/IF/DF, SS frames,
record/table reads and writes feed subsequent instructions. Minimum root
SP34 preserves the frozen52FD minimum SP32. Outer-call and5299-loop budgets
stop at separate source sites.

The5C5A divisor is four times the high byte of3318 and can be zero. For
nonzero DI the source numerator is at most3*65534, so division by DI>=4
fits a word. Native status5 stops before zero DIV at5C79; no exception
delivery or actual caller validity is established.

The raw decrease/acceleration guards, tables and clipping retain source
order. Commit writes52D6, then only AL to52D0, leaving52D1 untouched, then
updates the52D2 word. A relative SUB/SBB is followed by XOR DL,DL and an
unconditional33B5 clear. The final signed step toward CX uses raw535E with
word wrap and the actual comparison carry. No units, record schema or
physical interpretation is assigned.

The C17 `/W4 /WX` build passed31,648 comparisons,1,495,858 original
instructions and all303 feasible sites in the304-site fence. The remaining
5303 site has the existing entry-specific complementary-branch disposition.
Full bus/SS/GPR/BP/CF/IF/DF, control and counts match. Coverage includes
38,864 actual near calls,6,912 minimum-SP34 cases,104 boundaries before
zero DIV,120 altered child returns and592 altered root returns. Raw targets
are exposed after actual RET and never followed. Sixteen native diagnostics
are separate.

`RS-DOS-000268` identifies the external initialized5616..5635 word view:
sixteen words indexed by even offsets0..30. It lies wholly inside the existing
RS253 span; the separate consumer base is retained without assuming a shared
array schema. `RS-DOS-000267` at324A..3289 also has this direct consumer,
with byte index0..63. The comparisons observed11 distinct word indices and
15 byte indices. Separate instruction-bound checks cover all65,536 input
words and establish the complete index domains. Table values, units, all
writers and actual DS binding remain open; no original payload is embedded.

The direct caller403B:4111 immediately calls53A6, whose entry XOR AX,AX
replaces returned arithmetic status flags before conditional use. Complete
caller/IF/DF context,3318 producers, bounds, writers, ownership, lifetime,
interrupt exclusion and core integration remain open. No DOS session,
renderer, audio output, complete state-machine, gameplay or fidelity is
established. CGA and later resource/Windows/Amiga gates retain their order.
