# Independent TD2EGA EXEPACK loader verification

Date: 2026-10-13. Scope: Phase 1 image-recovery validation after the Phase 0 custody baseline. This check transformed only the verified private DOS working copy. It executed the original packing stub in an isolated CPU engine, stopped before the application's final far transfer, and executed no application instructions, DOS service, BIOS service, hardware I/O, or game loop. It is not a gameplay test, emulator acceptance test, or fidelity result.

## Independent method

The verifier is [verify_exepack_loader.py](../../tools/validation/verify_exepack_loader.py). It does not import or reuse the primary decoder. Instead, Unicorn 2.1.4 executes the original executable's admitted, byte-pinned unpacking instructions using a minimal real-mode memory/register setup. No guest operating system or devices are provided.

The public tool contains hashes, validation logic and the known loader coordinates; it contains no original code-byte array or game resource. Inputs and extracted images remain in ignored `analysis` directories.

The observed packing stub carries out three stages:

1. Copy its tail above the destination image and transfer into that copied loader.
2. Expand the source backward into the destination image.
3. Add the chosen DOS program load segment to each packed relocation target, restore the metadata-described stack, and prepare the original application far pointer.

The execution fence allows instruction fetches only from the initial stub's segment-relative `[0x12, 0x38)` and the moved stub's `[0x38, 0x101)`. It stops **before** the instruction at moved-stub offset `0xFE`, the final indirect far jump. Interrupt, halt and port-I/O opcodes are rejected before execution, including prefixed forms; an interrupt hook provides an additional denial. A finite hook budget catches loops. Inputs must match the pinned EGA hash, and CLI paths are restricted to the verified DOS working-copy tree and private independent-output tree.

At moved-stub offset `0x9E`, immediately before relocation-table processing begins, the verifier captures the entire destination image. It observes the actual two-byte relocation writes issued by loader instructions at offsets `0xBD` and `0xD6`, checks that each adds the load segment, and records their destination offsets and before/after words. After stopping, subtracting those observed additions must reproduce the pre-relocation snapshot byte for byte. This validates output bytes and actual relocation effects without independently assuming the packed table decoder is correct.

These offsets were verified by a bounded Capstone listing of the admitted original stub. The CLI does not depend on Capstone; its image-recovery implementation uses only the original instructions and Unicorn.

## Pinned evidence

| Item | Value |
|---|---|
| Source working copy | `analysis/inputs/dos/TD2EGA.EXE` |
| Source SHA-256 | `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182` |
| Original stub code/message range SHA-256 | `3c2ecf0c7854abfe0390cfa2482fc3941cf255546ce1629132eb62bb08f3d435` |
| Verifier SHA-256 | `1237456a2b18013aa840fa9a04e360d9144ec94980b9108b93567fce1dfd9e2a` |
| Unicorn | `2.1.4`, from the isolated locked project dependency directory |
| Recovered image length | 130,240 bytes, `0x1FCC0` |
| Pre-relocation/normalized image SHA-256 | `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4` |
| Observed relocation writes | 1,652; all destination offsets distinct |
| Original application entry | load-relative `13A8:03F8`, module byte offset `0x13E78` |
| Original application stack | load-relative `20D2:0FA0` |
| Original application instructions executed | 0 |
| Interrupts or port-I/O operations executed | 0 |

The complete pre/post relocation words and target offsets are private in each run's `verification.json`. That ledger can be compared to the primary decoder's independently parsed relocation records using module-relative byte locations.

## Two load-segment checks

| Program load segment | Pre-relocation image SHA-256 | Relocated image SHA-256 | Loader hook events |
|---|---|---|---:|
| `0x1000` | `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4` | `e36b827719c4692f9f89c5ba5d647111a82e61e8843f4d8b32ee653b7280ba99` | 92,681 |
| `0x2345` | `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4` | `5fb06f6da917041a4760b5b8a79a4d796a83ff8f59a32b6172385382591901f2` | 92,681 |

Both runs produced identical unrelocated image bytes and identical ordered relocation-target lists. Their relocated image bytes differ with the chosen load segment as expected. Reversing each run's observed relocation additions reproduces its pre-relocation image exactly. Hook events include repeated-string iterations reported by Unicorn; the count is not an 8086 cycle count or a unique-instruction count.

The loader stopped at `2FCC:00FE` in the `0x1000` run and `4311:00FE` in the `0x2345` run. Restored SS:SP was respectively `30D2:0FA0` and `4417:0FA0`; DS and ES were respectively `0FF0` and `2335`, the configured PSP segments. The metadata-derived original entry pointer was checked without following it.

Private outputs:

- `analysis/independent/exepack-loader-1000/pre-relocation-image.bin`
- `analysis/independent/exepack-loader-1000/relocated-image.bin`
- `analysis/independent/exepack-loader-1000/verification.json`
- Corresponding files under `analysis/independent/exepack-loader-2345/`.

## Synthetic checks and reproduction

[test_verify_exepack_loader.py](../../tests/validation/test_verify_exepack_loader.py) uses synthetic instructions only. All nine tests passed after the final tool change: reference-input rejection, public-output rejection, unknown-input rejection, stopping before a forbidden target instruction, interrupt rejection, port-I/O rejection, prefixed port-I/O rejection, outside-stub fetch rejection, and instruction-budget rejection.

From the workspace root, with the locked isolated dependency directory present:

```powershell
$env:PYTHONPATH = Join-Path $PWD 'analysis/tools/python'
python tests/validation/test_verify_exepack_loader.py -v
python tools/validation/verify_exepack_loader.py analysis/inputs/dos/TD2EGA.EXE --output-dir analysis/independent/exepack-loader-1000
python tools/validation/verify_exepack_loader.py analysis/inputs/dos/TD2EGA.EXE --output-dir analysis/independent/exepack-loader-2345 --load-segment 0x2345 --compare-image analysis/independent/exepack-loader-1000/pre-relocation-image.bin
```

The tool refuses to overwrite differing existing evidence. Identical reruns are permitted. `--compare-image` additionally requires an exact byte match against an independently supplied raw, unrelocated load image; do not point it at an MZ envelope or relocated dump.

## Primary decoder comparison

An exact artifact comparison against the primary decoder passed all 12 checks. The private comparison record is `analysis/independent/primary-comparison.json`.

- Primary raw image `analysis/derived/td2ega-v1/TD2EGA.image.bin` equals the independent pre-relocation image byte for byte.
- All 1,652 primary relocation targets equal the observed loader write targets **in execution order**, not merely as a set or by count.
- Primary original entry/stack/destination-length metadata equals the independently exercised loader metadata.
- Both independent load-segment runs have identical raw images and ordered relocation sites.
- The synthesized normalized MZ contains the exact raw image and ordered relocation sites, and its CS:IP and SS:SP agree with the original loader's prepared entry/stack.
- Its declared MZ length equals its actual length. The 6,640-byte envelope and 130,240-byte body total 136,880 bytes.
- Its `min_extra = max_extra = 0x0201` preserves the packed executable's minimum total program allocation of `0x21CD` paragraphs. This is a checked normalization choice, not a claim that those values were the original publisher header.

Normalized MZ SHA-256: `71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2`. Primary decoder tool SHA-256 for this comparison: `ce27ea25b3b65f5deb1bf7e0ae6c1215a059c2286d88bb2b1c69a804a0191b66`. The primary structural evidence is [td2ega-unpack.json](evidence/td2ega-unpack.json).

To require a raw-image comparison during an independent rerun, use a fresh evidence output directory and add `--compare-image analysis/derived/td2ega-v1/TD2EGA.image.bin`. The complete ordered relocation comparison and normalized-envelope checks are recorded in the comparison record described above.

## Limits

This is independent of the primary decompression algorithm, but it relies on Unicorn's real-mode instruction implementation and the supplied original stub. It does not establish historical EXEPACK version, authentic original publication, DOS execution compatibility, application control flow, simulation behavior, resource decoding, or presentation fidelity. The chosen load segments avoid low-memory wraparound; this check does not assess the historical EXEPACK low-memory-loading defect.

The independent comparison admits the raw EGA load image and its relocation treatment for subsequent static analysis. It does not admit application behavior. Any later change to the primary decoder, verifier, input, or normalized-envelope rules requires comparison of the newly produced artifacts. The application remains unexecuted by this verification path.
