# 34DC prepared edge calls

The complete near-return34DC body passed12,576 comparisons against compiled
C17, including12,336 normal returns and240 native call-budget prefixes.
All36 instruction locations were exercised;364,560 original instructions
and24,912 far8582 ABI calls were compared. The leaf8582 values are mocks.

The body reads currentDS fields indexed by rawSI with16bit offset wrap,
halves the unsigned width, negates the resulting word and adds the raw height.
A nonzero37F7 flag instead substitutes2C2A-5 with word wrap. It reads both
end words and prepares two five-word argument pools before the second flag
test. If37F7 is zero, it pushes a third pool before the first far call.
The calls see15/10/5 live words or10/5 live words, with10byte caller cleanup
after each. Later leaf writes to the source or flag cannot change the already
prepared argument words. ReturnedDS/GPR/BP/CF/IF/DF remain explicit; final
cleanup carry is zero in the admitted stack profile.

The test includes all256 flag bytes, unsigned high-bit widths, wrapped source
selectors, equal/independent DS/SS frames, changed returnedDS and leaf writes
after the first call. Full memory outside64 private SS scratch bytes,
registers, frames and retained arguments match. Two native-only invalid input
checks are separate. Actual8582/2958 caller integration, output/frame bounds,
producer/ownership and IRQ exclusion remain pending. No resource format,
renderer, DOS game session, audio, gameplay or fidelity acceptance follows.

[Build](evidence/td2ega-edge-sequence-build-v1.json),
[comparison](evidence/td2ega-edge-sequence-validation-v1.json), and
[native checks](evidence/td2ega-edge-sequence-native-diagnostics-v1.json).
CGA remains behind EGA portable code-contract closure.
