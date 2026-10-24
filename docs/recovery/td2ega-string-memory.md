# Raw near string and memory operations

Five `13A8` functions retain current-DS near operands and incoming DF.
All save BP in actual SS and use plain far returns with caller cleanup.
They are portable instruction-derived algorithms, with no host string API
substitution or inferred original source C types.

| Entry | Recovered behavior |
| --- | --- |
| 2916 | Scan destination and source with CX=FFFF; compute raw tail/source positions; reread SS destination; peel a byte by source parity, copy words then residual byte. |
| 2956 | Scan source with CX=FFFF; read SS destination; peel a byte by destination parity, then word/residual-byte copies. |
| 2988 | Scan second string and subtract count from DI regardless of DF; compare bytes including the counted terminator. Equal returns AX0/CF0; mismatch returns AX1 or FFFF/CF1. |
| 2B40 | Compare bytes, BX always incrementing while LODSB SI follows DF; fold ASCII41..5A on differences. CL holds the final first-byte case mask; unprefixed98 sign-extends AL into AX. |
| 2B82 | Fill count bytes with the low argument byte using byte/word stores. Zero count preserves incoming CF and exchanges incoming DS into BX; nonzero ends CF0 and BX=repeated-byte word. AX=near destination, DI restored through DX. |

The two copy algorithms retain forward or reverse sequential overlap, raw
word pointer wrap and actual stack aliases. A scan exhausted without a NUL
retains its raw count and subsequent operations. Caller capacity, terminator
and direction guarantees remain separate obligations.

The selected C17 build is v2. Its 11,600 comparisons execute 8,986,320
original instructions and cover all 134 sites, with complete bus comparison
including SS. There are 5,908 far-return operations, 5,692 before-element
diagnostic prefixes, 88 overwritten far-return coordinates, and 5,800
reverse-DF fixtures. Nine invalid native-interface checks are separate.

The first build failed an SS-alias case in the case-insensitive helper:
the CL mask subtraction was promoted rather than wrapped as a byte. The
failed source/build/validator were preserved, the byte cast corrected,
and a fresh build and complete comparison passed. No failed run is counted
as a successful vector suite.

The static context records 109 direct caller candidates. Actual caller
bounds/NUL/DF/other-FLAGS requirements, DS/SS correspondence, all writers,
lifetime and core integration remain open. These checks establish no actual
DOS session, platform/device delivery, renderer, audio output, complete state
machine, gameplay or fidelity acceptance. CGA remains behind EGA portable
code-contract closure; full resource decoding and later phases remain pending.
