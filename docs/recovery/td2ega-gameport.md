# EGA gameport contracts

2026-10-13. Complete `06C9:6686`, `680A` and `6828`
(`FN-EGA-000156/000412/000413`) have three native exports and a
[C17 build](evidence/td2ega-gameport-build-v1.json).
[136,074 comparisons](evidence/td2ega-gameport-validation-v1.json) execute
their actual instructions with synthetic group bytes and port201 responses.
They cover4,970 sampler profiles,32 initializers and131,072 translations.
No physical input device or elapsed-time behavior is accepted.

6686 returns AX0 without a port operation when6CFC is zero or6CFE bit0 is
clear. That path preserves incoming BX/CX/DX and IF. The active path clears
6281, saves an initial port201 read at6280, initializes both axis counts to
50h, executes CLI and writes the initial byte to port201. It polls active
bits until both clear or the counter reaches4000. CX increments only on a
poll where no active axis completes. An uncompleted axis retains50h on
timeout. These are instruction counts; no physical duration is inferred.

The routine executes STI before calibration and its final port read, ending
IF1. X minimum and threshold comparisons are signed. Y minimum and threshold
comparisons are unsigned, while its maximum/candidate comparisons are signed.
The shared shape is therefore not interchangeable between axes. Calibration
SUB/JLE uses signed original operands including overflow; DIV and logical
half/quarter shifts consume the resulting wrapped16-bit difference. Word
threshold arithmetic, candidate countdown and conditional scale writes remain
literal. Final button bits combine the initial and final port bytes.

Tests compare full64KiB state, every ordered read/write with its IF state,
AX/BX/CX/DX, far frame and preserved registers/DF. They include1,120 timeout
profiles, partial axis completion, min/max/candidate counter boundaries,
signed-overflow calibration values,1,024 varied state profiles at two load
bases and disabled configuration paths. The port adapter preserves nonresponse
registers and does not mutate group memory. Native service/budget diagnostics
are separate from original behavior.

680A sets6CFC=1, X/Y minima to50h and maxima to zero, leaving other calibration
fields intact.6828 masks its near word argument to four bits and returns the
byte at629E+index; all65,536 argument words are compared at both load bases.
Both preserve IF/DF. Active6686 returns zero-extended6281. Its final XOR AH,AH
sets ZF even when AL is nonzero; incidental flag consumers still need caller
review before integration.

Actual device presence/timing, calibration history, asynchronous IRQ effects,
every caller and complete input behavior remain open. Physical086C is the
separate verified external-read anomaly; no frequency or timebase has been
assigned to it. This packet establishes no DOS session, renderer, audio,
gameplay or fidelity. EGA closure continues to gate CGA.
