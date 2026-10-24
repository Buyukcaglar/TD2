# Additional EGA mutable line-helper family

2026-10-14. The [static review](evidence/td2ega-line-mutation-review-v1.json)
records06C9:06C3/FN-EGA-000069. Its subsequent [native contract](td2ega-line-step.md) has compiled and
passed bounded comparisons; actual caller and asynchronous gates remain open. This adds a family to the earlier platform-mutator
review; it does not replace those four ledgers or prove a whole-program
transition graph.

Positive deltas write opcode40 to CS071F and thenCS0735; negative deltas write
48 in the same order. These are one-byte INC AX and DEC AX forms. Both stable
pairs and the two intermediate pairs retain all59 instruction boundaries.
The mixed forms describe ordered write prefixes. Actual IRQ delivery,
reentrancy, exclusion and lifetime behavior remain unproved.

On normal direct-entry interpolation paths, both writes precede the patched
arithmetic. Uniform-fill and zero-delta exits can retain the previous bytes
without executing either patched instruction. Native recovery must retain
the bus writes, early-exit behavior and arithmetic direction without mutating
the canonical image or assuming its initial INC bytes apply universally.

06C3 receives three words through SS:BP+4/+6/+8: destination, second endpoint
and first endpoint. Its near `RET 6` pops the return IP and six argument bytes,
for a total eight-byte return extent.2477 pushes15 words and calls it five
times; the callee cleanup leaves the saved SI ready for POP. A plain near RET
or caller-clean replacement would unbalance that stack.

2477 also reads previous-record fields through BP/defaultSS while current
fields use SI/defaultDS. OutputES is assignedDS. The actual corresponding
views and bounds must be proved before integration. Source/header context
must remain range-specific; no universal DS=SS correction is justified.

06C3 arithmetic/LOOP/DF/stack effects now have a bounded native contract;
2477/2542/268A and actual caller/exclusion closure remain the next frontier. This review establishes no renderer, full state machine,
actual device/IRQ, DOS/Windows gameplay, resource decoding or fidelity.
CGA remains behind EGA portable code-contract closure.
