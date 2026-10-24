# Raw member far-address calculation

`FN-EGA-000251` (`06C9:C701`) takes three SS words: header offset, header
segment and index. It reads the header word through ES:SI+4, but computes
the table index as the word4*headerword+4*index+6 without adding SI. The
word base8*headerword+6 is truncated before the segment-base addition.

The table low and high words are separate ES:[BX] and ES:[BX+2] operands,
so their effective addresses wrap separately. Raw32-bit addition and four
SHRDX/RCRAX pairs produce AX=offset nibble and DX=normalized segment.
BX retains the nibble, CX the low word of ES<<4, ES the source segment,
and CF the original linear bit3. DS is preserved; SI/BP restore from actual
SS. Plain RETF4 leaves all three argument words for the caller.

The clean build-v1/comparison-v1 passed 84,096 cases and all44 sites,
with 3,700,224 original instructions. Full bus, actual SS saves/frame/arguments,
GPR/BP/CF/IF/DF and control coordinates are compared. There are12,096 wrapped
high-word reads,69,120 nonzero-header-offset fixtures,40,320 minimum-SP16
fixtures and14,016 ES=SS fixtures. In4,056 results AX=0 with nonzero DX;
that valid raw far address is retained. Twelve native interface/convention
checks and nine algebraic normalization checks are separate.

The single direct callerC838 atC864 pushes index/segment/offset, restores
DS to the principal group before the call, and executes ADDSP6 afterward.
It stores AX/DX, then uses them as SI/DS for resource reads. That proves
the machine far-address consumer and the immediate arithmetic-FLAGS
redefinition; it does not establish a source C pointer type or full format.
Earlier in that caller DS selects the header segment, and afterward it
selects returned DX. A global DS assumption would lose those transitions.

Producer/header alignment, table extent, index, enclosing allocation/output
bounds, all writers/lifetime and core obligations remain open. Original
tables stay external. Source-segment fixtures and flat-bus comparison do
not qualify A20 or device behavior. No full resource decoding, DOS session,
renderer, audio, complete state-machine, gameplay or fidelity gate is
established. CGA remains behind EGA portable code-contract closure.

The [C838 body and its actual C701 composition](td2ega-member-reorder.md)
are now bounded-differential-passed. The1748caller supplies allocator-normal
scratchoffset0 and1F6paragraphs. Headerproducer/finalpackedpass/alignment/
tableextent/capacity/writer/lifetime/core remainopen;6D50doesnotuniversally
returnapointer. This supersedes only the earlier unimplemented-C838body item.
