# First recovered TD2EGA C function

`FN-EGA-000003` is a bounded 29-byte helper at module-relative `06C9:780E`, image `[0xE49E,0xE4BB)`. Its instruction contract has been independently reviewed, translated to C17, compiled and compared to isolated original instructions. Its caller-level purpose is unknown. It is not labeled a random-number generator, game-physics routine or resource decoder.

Source: [td2ega_byte_ring.c](../../src/recovered/td2ega_byte_ring.c) and [header](../../src/recovered/td2ega_byte_ring.h). The code contains a state representation and algorithm, with no embedded original data or media. It is not integrated into a playable core.

## Recovered contract

The original function decrements the 16-bit word at `DS:66E6` modulo 65,536. It selects the low eight bits of the new cursor as an index into 256 bytes at `DS:66E8`, reads the selected byte, compares it with `0x80`, then rotates left through the carry produced by that comparison. The new byte is `((old << 1) | (old < 128)) mod 256`.

It writes the new cursor and selected byte and returns the byte zero-extended in AX. SI is saved/restored; no calls, interrupts or ports are present. The far return removes the four-byte return address. Final flags come from `XOR AH,AH`; they are documented in the instruction contract but not exposed as C API state.

The first Ghidra pass inferred a `void` return. The recovered C interface exposes the observed AX value, while the original C return type and caller use remain unknown: a void function can still clobber AX. Automatic decompiler signatures remain hypotheses.

## Compilation and differential evidence

MSVC 19.44 compiled the actual recovered source as C17 with `/W4 /WX /O2`; the private DLL exists only for the validation harness. The [build record](evidence/td2ega-byte-ring-build.json) identifies compiler, options, source, script and outputs.

[Validation](evidence/td2ega-byte-ring-validation.json) passed 131,584 vectors:

- All 256 ring indices paired with all 256 possible selected byte values.
- All 65,536 cursor values, including zero wrap and every high byte.
- 512 seeded varied-state cases.

The harness loads only this admitted 29-byte function into a fenced real-mode CPU instance. It compares all 258 state bytes and the AX-equivalent result against compiled C and checks guards around the native C state. Guest preserved registers/segments, far-return stack behavior and adjacent memory guards are checked against the x86 contract. These tests executed 1,447,424 original helper instructions; they did not launch a DOS game or expose devices/OS services. Explicit checks remain active under optimized Python execution.

This proves the bounded state transformation for the tested vectors. It does not establish caller semantics, full CPU flag equivalence, cycle timing, cross-platform builds, game integration or original gameplay fidelity. Those gates remain open.
