# EGA near simulation arithmetic and state primitives

2026-10-13. Fourteen original near entries have twelve native C exports.
[The C17 build](evidence/td2ega-sim-primitives-build-v2.json) and
[38,198 comparisons](evidence/td2ega-sim-primitives-validation-v1.json) use
synthetic data and two code loads. Two invalid native toggle selectors are
separate diagnostics. No dispatch table, complete simulation callback or game
loop executes. The64KiB compatibility view contains data only; the C source
contains neither an instruction interpreter nor original table/media bytes.

| Original entry | Bounded recovered effect |
| --- | --- |
| `448A` | Sum eight signed bytes335D..3364 into30E4; copy52CE into30E6 |
| `4612` | If2F56 nonzero, set2F5B, multiply unsigned3328*52CE, use the high word clamped to at least0320 as332C; expose low product and prior target |
| `4D26` | Subtract/add radius from center modulo65536, compare those words as signed against3336/3334; overlap produces originalZF1, outsideZF0; AX remains lower word |
| `4929` | Set3371=1; when9410 nonzero copy331E/942E into3356/3358 and set33D5=1 |
| `4947` | Set3371=2 |
| `494D` | Only when52DA=0, store record-base+50 modulo65536 there |
| `495D` | Only when52DA=0 and unsigned52CE>3200: save52CE at3354, set52DA=base+3C, clear52DE, set33B7=8, then choose52DC=0320/0190 from bit80 of the current byte at that new pointer |
| `499A` | Index=(byte533E+45)&7F; half=input>>1; scaled=(half-16h)*5 modulo65536; store its low byte at368A+index and a source byte from37DD+half at370A+index |
| `49C9/49CF/49D5` | XOR low bit at37F7/37F6/37F8; three original entries share one native selector API |
| `49DB/49E1` | Add/subtract10h modulo256 at337A |
| `5427` | Clear52DA and bytes33B6/33B7/33B8/33BA |

Names and state-purpose labels remain provisional. For example the sum and
product constants are numeric contracts, not admitted physical units. Signed
comparisons explicitly convert16bit values to an int32 range, avoiding an
implementation-defined unsigned-to-signed cast. The interval preserves wrap
*before* the signed comparison; unbounded mathematical intervals would differ.

495D reads its selected flag after its earlier writes. If the selected pointer
aliases52DA or52DE, those new bytes determine the branch. With base529E,
initial52DA=0 and admitted sample>3200, storing pointer52DA makes the read byteDA
and selects0320. Preloading the old byte or replacing zero with host NULL would
change the result. The tests include these aliases and pointer wrap to zero.

499A's indexed destinations use BP and therefore default to **SS**, while its
indexed source and other fields use **DS**. An initial separate-SS fixture was
rejected by the memory fence. The accepted profile usesDS=SS, includes the
active near-return bytes in the compatibility view, and keeps output writes
disjoint from that frame. Other primitive tests use separate data and stack
segments. The interrupt callback403B establishes DS/ES but inherits SS; its
complete caller/platform exclusion context remains required. Do not force
this conditional SS assumption over unrelated Ghidra ranges.

All entries use near RET, consuming one original return word. No CLI/STI,
port or DOS service occurs here, and DF/IF remain unchanged. Original scratch
outputs are checked for interval, product, sum/curve contracts where relevant;
the native interfaces expose named results and state changes. Other incidental
register/flag uses and every caller's actual record/dispatch domain must still
be reviewed before integration. Local exact arithmetic does not close P1-06/08,
the entire state machine, platform behavior, gameplay or fidelity.
