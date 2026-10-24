# EGA pool setup and reset

2026-10-13. Complete `06C9:6F1E/6F86/6FD6`
(`FN-EGA-000176/000177/000178`) have three native exports and a
[C17 build](evidence/td2ega-pool-setup-build-v1.json).
[137,072 comparisons](evidence/td2ega-pool-setup-validation-v1.json) execute
their actual instructions with synthetic DOS AX/BX/CF responses and group data.
No actual DOS allocation, process or payload is created.

6F1E always saves current CS/DS at68DE/68E0. If68DA is nonzero, it skips all
DOS requests without validating descriptors or endpoints. Otherwise it issues
AH48 with BX64h, saves returned AX as the left segment,68DC and ES, and issues
AH4A twice. There is no carry-dependent branch. The first resize receives
requested end minus left segment modulo65536. The second retains the first
response's BX and AX low byte. The final saved end is68DC plus the last
returned BX, not necessarily the original requested end. Synthetic carry
profiles preserve these literal effects without assuming real DOS results.

It then resets cached6C6A to the right sentinel and active6C68 to the left,
clearing only interior status words at stride18. Names, paragraph sizes,
segments, sentinel statuses and payload are retained. The loop rereads the
right-pointer word6C6C after each advance, preserving shared-view alias
behavior. Native service/budget diagnostics retain partial state and are
outside original failure equivalence.

6F86 supplies endA000h and starts AXA000h, balances the near argument and
far-returns. Initialized setup therefore leaves AXA000h on this path.
6FD6 returns the wrapped word:

`right_sentinel.segment - active_top.segment - active_top.paragraphs`

This is not the gap before the cached boundary or an admitted host allocation
size. AX is that word and BX is the active descriptor pointer. Original
near offset zero remains valid. A word starting atFFFFh consumes the adjacent
physical byte; native views explicitly supply it without a host null/A20
interpretation.

Fixtures include6,000 setup/reset profiles and all65,536 active pointers at
two load bases, initialized guards, raw AX/BX/CF combinations, short/default
descriptor spans and near/word wrapping. Full group plus adjacent byte,
request order and live register values, clear counts, far frames and preserved
registers/IF/DF match. Actual DOS result domains, intended50-row invariants,
caller flag uses, moving payload ownership and IRQ exclusion remain open.
No resource decode, DOS game session, renderer, audio, gameplay or fidelity
is accepted. EGA closure continues to gate CGA.

The [historical Microsoft SetBlock reference](https://github.com/microsoft/MS-DOS/blob/2d04cacc5322951f187bb17e017c12920ac8ebe2/v2.0/source/SYSCALL.txt)
documents that a failed growth request can return a maximum size in BX.
This corroborates keeping returned BX in the synthetic profile; actual DOS
version and allocation behavior remain untested.
