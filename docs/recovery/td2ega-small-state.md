# Finite raw state, read and copy helpers

Fourteen finite entries have recovered C bodies with explicit raw segment,
stack and flag behavior. The bounded comparison covers111 instruction
locations, including the actual C692 body called from C69C. These contracts
retain instruction-level outputs without inventing source return types.

| Native selector | Original entry | Behavior and convention |
| --- | --- | --- |
|0|06C9:5D00|Plain far no-op return,4 bytes|
|1|06C9:4A18|Plain near no-op return,2 bytes|
|2|06C9:5D83|AX/ES0040 then AX from ES046C, far return|
|3|06C9:5D8D|Same literal read minus one SS word; save/restore BP, far return|
|4|06C9:C692|CLI; AX/DX from current DS5E90/5E92; STI, far return|
|5|06C9:C69C|Actual nested C692, ADD/ADC two SS words, publish DS68D6/68D8, far return|
|6|13A8:2FC4|Clear CH, repeat SHLAX/RCLDX CL times, far return|
|7|06C9:7A82|Publish second SS word to DS6822, then reread first to DS6820, far return|
|8|13A8:246B|AX=(NOT DS6D97)ANDCX; CX0/1 from ALbit7, near return|
|9|13A8:2696|One SS near offset in BX, if nonzero ORbyte DS[BX-2],1, far return|
|10|0267:0004|Select AX7738 for SS argument1, otherwise7739, far return|
|11|13A8:2682|Pop far IP/CS into CX/DX, compare DS6DD4 with post-pop SP, reconstruct frame and far return|
|12|06C9:7AA4|Eleven forward words from DS6820 to current-DS near destination; CLD, far return|
|13|06C9:7ABD|Eleven forward words from current-DS near source to DS6820; CLD, far return|

The physical read is exactly086C, from0040:046C, independent of the module
load segment. Fixtures give canonical0040:006C a different word. No source,
writer, timer frequency or elapsed-time unit is assigned to086C. The owned
DS5E90/5E92 pair is separate; its increment sites61D9/61DF and the raw
68D6/68D8 comparison sites are instruction observations. C692 ends with
IF1, irrespective of incoming IF. Synthetic instruction execution establishes
that flag result, not actual IRQ exclusion, atomicity or timer delivery.

The publisher's6820/6822 words are untyped paired state. Presentation code
later reads their individual low bytes. The initial draft's "far pointer"
label was unsupported and is corrected in the selected recipe and live
contracts. The22-byte copy span likewise remains opaque state. Forward word
copy preserves source/destination overlap, odd offsets and word-register wrap;
it is not replaced by a host memmove. Saved SS registers, near/far frames,
GPR/BP/CF/IF/DF and the complete1MiB bus are compared.

The CL helper clears the high count byte and handles every byte count without
undefined host shifts. Its incoming count0 returns without shifting; count256
in CX means CL0 after clearing CH. The stack-space helper's threshold applies
to SP after both return words have been popped. The two no-op entries retain
their distinct return widths. The selector's AX values remain near offsets,
with no payload embedded and no original source return type inferred.

The [selected comparison](evidence/td2ega-small-state-validation-v3.json)
and [native checks](evidence/td2ega-small-state-native-diagnostics-v2.json)
are separate receipts. Earlier recipe/label revisions are archived; C bytes
and the compiled DLL remain unchanged. These finite contracts do not close
all caller/writer/alias/lifetime/bounds/IRQ, complete state-machine or core
integration obligations. No actual BIOS/DOS session, device, renderer, audio,
resource decoding, gameplay or fidelity acceptance follows. CGA remains
behind EGA portable code-contract closure.
