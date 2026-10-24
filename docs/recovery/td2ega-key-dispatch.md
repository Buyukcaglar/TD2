# EGA key dispatch and callback frame

2026-10-13. Complete `06C9:6528` (`FN-EGA-000153`) has one native export,
a [C17 build](evidence/td2ega-key-dispatch-build-v2.json), and
[262,144 comparisons](evidence/td2ega-key-dispatch-validation-v1.json).
Every16-bit key word is tested with clear/busy guard states at two load bases.
Callback bodies are explicit ABI mocks; their original semantics remain open.

The dispatcher executes CLI before checking byte6252. A busy guard returns
after STI, preserving incoming AX/BX/CX/DX and the key argument. Otherwise
it raises the guard and executes STI before examining the key. A nonzero low
byte selects the ASCII path, masks the entire key to7bits, writes that word
back into its caller argument and reads6048+2*index. A zero low byte selects
the high byte, clamps it to84h and reads6148+2*index without changing the
argument. These word reads stay within6048..6251.

A zero callback offset returns the current argument in AX and clears the
guard. A nonzero offset saves DI/SI, loads AX with relocated6C9, pushes that
segment and executes near CALL BX. The callback sees a four-byte far frame:
saved IP655B followed by relocated6C9. It must return through that frame.
Replacing it with an ordinary near-return callback would corrupt the stack.

Comparison verifies the actual callback frame at root entrySP-10 and saved
SI/DI order. Its explicit mock preserves DS/SS/ES and the frame, changes
BX/CX/DX/IF/DF and group bytes, and returns through the saved far continuation.
The dispatcher restores SI/DI, forces AX0 and clears6252 after callback return.
Callback IF/DF changes survive; the dispatcher performs no final STI or CLD.
The busy and missing paths end IF1. A callback's guard mutation is overwritten
on return; the guard is not a complete asynchronous exclusion proof.

Full group bytes, key argument, scratch outputs, original ordered guard/IF
writes, outer far frame and preserved registers match. The tests include
98,750 callback ABI mocks; this count establishes no original callback body
or live input behavior. Native missing/failing-adapter diagnostics are outside
original error equivalence and can leave the guard raised.

Actual callback bodies, DS-changing domains, every callback-table writer,
reentry/IRQ feasibility and full input lifetimes remain open. No DOS game
session, renderer, audio, gameplay or fidelity is accepted. The broader
EGA code-contract gate remains open and continues to block CGA.
