# TD2EGA image and relocation recovery

The supplied TD2EGA image is now unpacked and independently validated. The original remains unchanged; all binary outputs are private under `analysis`.

## Results

| Property | Verified value |
| --- | --- |
| Supplied packed file | 114,421 bytes; SHA256 `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182` |
| Original MZ image start | File offset `0x200` |
| Packed data | File `[0x200,0x1B0C0)`, 110,272 bytes |
| Loader padding | 14 terminal `FF` bytes before the stub |
| Backward commands | 268: 137 fills and 131 literals, including the final fill command |
| Command expansion | 71,002 bytes plus a 59,238-byte unchanged prefix |
| Recovered load image | 130,240 bytes (`0x1FCC0`) |
| Recovered image SHA256 | `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4` |
| Inner relocations | 1,652 ordered sites, all within the recovered image |
| Original entry | Module-relative `13A8:03F8`, linear `0x13E78` |
| Original stack | Module-relative `20D2:0FA0` |
| Total minimum allocation | `0x21CD` paragraphs (`138,448` bytes) |
| Normalized image extra allocation | Minimum and maximum `0x201` paragraphs |

The precise command-kind totals are in [the transform record](evidence/td2ega-unpack.json). File offsets in the packed input cannot be applied linearly to the expanded image. The record maps each command's packed and output ranges; the unchanged prefix has a direct mapping.

## Independent checks

1. `tools/exepack.py` validates the admitted 18-byte EXEPACK layout/stub digest, backward command bounds, exact output size, final prefix accounting, inner relocation groups, original entry/stack and allocation. Seven synthetic tests cover valid framing and malformed lengths/commands/relocations/MZ headers.
2. [Original-loader verification](independent-unpack.md) executes only the original packing stub, stopping before its final application transfer. It records actual relocation writes and repeats at two load segments. Both normalized images and every ordered relocation site match the primary result. No application instructions, interrupts or port I/O occur in these loader checks.
3. The pinned author's independent EXEPACK tool produces the same image and ordered relocation records. [Comparison evidence](evidence/td2ega-author-comparison.json) separates image equivalence from different synthesized MZ headers.
4. [Ghidra import verification](evidence/td2ega-ghidra-import.json) compares every imported image byte against an independent relocation calculation: 130,240 bytes and all 1,652 relocations agree with zero mismatches.

## Normalized envelope and allocation

The project's synthesized MZ has a 6,640-byte header containing the restored relocations, original CS:IP/SS:SP, zero checksum and an extra-allocation budget adjusted to preserve the packed file's original total allocation. The packed image occupies 7,120 paragraphs and requests `0x5FD` extra; replacing it with an `0x1FCC`-paragraph image leaves `0x201` extra. This budget includes the stack/BSS space beyond the loaded image.

The author's envelope instead uses a 6,656-byte header, a computed checksum and retains maximum extra allocation `0x5FD`; its minimum extra allocation is `0x201`. These are envelope-policy differences, not image or relocation disagreements. Neither derived executable is claimed to be the historical pre-packing publisher executable.

The common stub/layout is established. The exact historical EXEPACK release and command line remain unknown; no version guess is required for the validated transformation.

## Reproduction

Run the custody verifier first. All recovery tools refuse or require fresh output locations; use a new revision directory when rerunning.

```powershell
python tools/verify_reference.py
python -m unittest discover -s tests -p test_exepack.py -v
python tools/exepack.py analysis/inputs/dos/TD2EGA.EXE --output-dir analysis/derived/td2ega-new --record docs/recovery/evidence/td2ega-unpack-new.json
```

The independent verifier and toolchain reports give their separate commands. Preserve tool/source hashes with each run. A repeat unpack result alone does not advance code, resource, gameplay, visual/audio or fidelity gates.
