# Kylofon P1-R03 representative differential design

Date: 22 October 2026. This is a fresh comparison of the actual upstream C candidate with admitted original instructions. It does not rerun, replace or inherit accepted recovery receipts. The read-only clone and the 250 original-media files remain inputs; all candidate source, builds and synthetic RAM live under `analysis/candidates/kylofon-r03-v1`.

## Comparison boundary

The wrapper exports the actual candidate `mem[]` pointer and a scalar call dispatcher. Each fixture initializes that memory and an independent Unicorn instance from the same admitted relocated EGA image and synthetic input fields. The actual C functions execute directly; the comparison does not substitute our recovered helpers or Python replicas for them. Host stubs trap unexpected presentation, filesystem, pumping and fatal paths.

Original instructions use load segment `1000`, DS `278F`, CS `16C9`. The image SHA-256 is `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4`; the normalized MZ SHA-256 is `71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2`. The admitted MZ's 1,652 relocation entries are applied before execution. The original instruction hook accepts only syntactically disassembled ranges covering the selected entries; each call executes its actual near/far return and must reach the synthetic caller sentinel with the expected SP adjustment. No INT, IRQ, BIOS, DOS or game loop is supplied.

Full first-1MiB state is compared outside a declared original SS frame/local-scratch aperture (`SP-0300` through the input call frame). C host frames do not perform original PUSH/CALL/RET stores, so those bytes and GPR/FLAGS are not a native data-API equivalence claim. Ordinary cases use disjoint SS `9000` or DS=SS `278F` with SP `E000`, safely outside the compared live fields. Four additional deliberately overlapping SS argument fixtures demonstrate why that qualification matters; they are reported separately and cannot inherit a passing native caller profile.

The `twenty_bit_bus.py` shared allocation maps high physical accesses to the same 20-bit RAM. This is a serialized analysis profile, not evidence of historical A20, bus cycles or physical device behavior. No memory-read hook or CODE-hook flag mutation is used.

## Selected entrypoints

| Family | Original entry | Actual C function | Observations and cases |
| --- | --- | --- | --- |
| Byte-ring generator | `06C9:780E` | `rand8` | All cursor low-byte positions, 16-bit edges, varied source bytes, repeated 17-call consumption; scalar AX and all nonframe memory |
| Literal reader | `06C9:5D83` | `bios_ticks` | Independent physical `086C` and `046C` values; original AX decides which location the candidate must read |
| Literal subtraction | `06C9:5D8D` | `bios_ticks_since` | Independent low-memory pairs and zero/sign/wrap argument edges, actual SS far argument read |
| Input callback vector | `06C9:6A17/6A28` | `kbd_set_getkey_fn`, `kbd_get_getkey_fn` | Varied far words, equal/independent SS, full vector state and returned DX:AX; separate first-store/second-argument aliases |
| Simulation slice | `06C9:448A` | `curve_sum` | Signed bytes across eight samples, state sum and speed snapshot; no claim about units or full tick history |
| Simulation slice | `06C9:45BF` | `drag_apply` | Speed/force zero, extrema and sign boundaries, drag-table reads, throttle branch and neutral brake tail |
| Simulation slice | `06C9:4612` | `update_rpm` | Enabled/disabled cases, multiplier and speed extrema, high-product and minimum clamp; memory observations, not host pointer return ABI |
| EGA target state | `06C9:5DFB` | `gfx_set_clip_current` | Signed/raw clip words forwarded through actual original SS arguments into CS live target fields |
| EGA planar primitive | `06C9:BA3C` | `gfx_plot` | RAM-plane branch, arbitrary raw coordinates/row offsets, present/absent planes, colour bits and high physical wrap. This is no EGA hardware/latch/pixel-display acceptance |
| Run/block codec stage | `06C9:6B02` | `rle_decode` | Synthetic run-only control with high bit set and 1/3/11 escapes; literals, zero/short/long runs, fixed repeats, DS=SS stack-header path and returned destination |

The run-only codec profile deliberately does not exercise supplied resources, the sequence-first branch, zero-escape full LOOP, more than eleven header escape bytes, overlapping source/output, malformed unbounded streams or allocation/lifetime rules. The whole codec and full-resource gate remain separate.

## Baseline and repaired candidate

The same dispatcher builds against both an unmodified 85-file upstream copy and the separately repaired candidate. Both consume identical fixture streams. The baseline's wrong literal-reader address and missing physical wrap should produce retained mismatch witnesses; a repaired candidate is required to pass the admitted ordinary cases. The excluded original-SS alias cases remain explicit witnesses of the narrower host argument API rather than repairs to historical instructions.

`tools/validate_kylofon_representative_v1.py` accepts `--library`, optional `--baseline`, optional `--build-record`, and a fresh `--output` under `docs/recovery/evidence`. A bounded `--probe` may be used with a separate output name. Every failed/probe/final outcome must retain its exact executed validator and relevant library/source build identity. The result records original image/MZ hashes, library and validator hashes, per-family counts, executed instruction sites, deterministic fixture-stream hash, baseline/candidate mismatch examples and domain limitations. Acceptance uses explicit exceptions, never Python `assert`.

## Executed results

The [final representative receipt](evidence/kylofon-representative-validation-v1.json) passes **2,233 admitted vectors**, executing **116,990 original instructions**, with **zero repaired-candidate mismatches**. The comparison took **81.974 seconds** on this host. This is measured test execution time; it is not an estimate of saved development effort.

| Family | Admitted cases | Unmodified baseline mismatches | Repaired candidate mismatches |
| --- | ---: | ---: | ---: |
| Byte-ring and repeated consumption | 278 | 0 | 0 |
| Literal physical086C read | 27 | 25 | 0 |
| Literal physical086C subtraction | 243 | 225 | 0 |
| Input vector setter/getter | 256 | 0 | 0 |
| Simulation curve/drag/RPM slices | 725 | 0 | 0 |
| Graphics live clipping state | 128 | 0 | 0 |
| RAM planar point primitive | 384 | 41 | 0 |
| Synthetic bounded run-only codec | 192 | 0 | 0 |
| **Total admitted** | **2,233** | **291** | **0** |

The baseline disagreement witnesses discriminate the two concrete repairs: the original literal address rather than the normalized BIOS-clock address, and physical 20-bit wrapping for high-segment RAM plane accesses. The same exact deterministic fixture stream was supplied to both baseline and repaired C. The receipt retains per-witness addresses/scalars and hashes; it does not export original resource bytes.

Four further **excluded SS-alias fixtures** all disagree with both baseline and repaired native argument APIs. In the original, the first vector-field store overwrites the second forwarded SS argument before it is read. The C function receives already-evaluated host arguments. This is a demonstrated domain difference, not an unresolved ordinary-case failure hidden in the 2,233 count. The raw original alias contract remains authoritative. A future integrated native caller must prove that this alias is excluded by ownership/lifetime, or use an explicit bridge; this sample does not establish that reachability proof.

The [earlier 16-case probe](evidence/kylofon-representative-probe-v1.json) passed 1,584 original instructions and checks only byte-ring setup. It is separate from the final vector total. Exact executed validators and logs are retained in `analysis/candidates/kylofon-r03-v1/attempts/differential-probe-v1` and `analysis/candidates/kylofon-r03-v1/attempts/differential-full-v1`; both archived validators have the hash recorded in the final receipt. The final receipt pins the [C17 candidate build](evidence/kylofon-candidate-build-v1.json), DLLs, admitted image/MZ, validator and bus dependency. No accepted source/receipt was rewritten or historical validator rerun.

## Remaining acceptance boundaries

The pass establishes selected actual candidate C state/scalar agreement for the named fixtures at load segment1000. It does not establish P1 whole-core closure, all historical caller domains, live storage/descriptor ownership, real input/IRQ history, EGA hardware effects, full corpus decoding, native game sessions, audible/visible fidelity or P1-R04 subsystem adoption. No new native helper export, function-contract or resource-closure count is earned by this candidate comparison alone.
