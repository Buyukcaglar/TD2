# EGA named raw-file loader

2026-10-13. Complete original `06C9:6D18` (`FN-EGA-000172`) is recovered as
`td2ega_named_raw_load`, linking the reviewed acquisition, move, compaction,
paragraph-size, allocation and raw-read C helpers. The [C17 build](evidence/td2ega-named-raw-build-v1.json)
and [1,960 comparisons](evidence/td2ega-named-raw-validation-v1.json) cover the
actual original wrapper and callees. Only DOS services and byte streams are
synthetic; fatal calls stop before entering cleanup.

The wrapper tries cache acquisition first and branches on `DX != 0`. A hit
returning a nonzero segment performs no DOS operation. A successful acquisition
at segment zero has already moved data and changed ownership, yet falls through
to file sizing, allocation and reading. The C composition preserves this test;
original address zero is not represented by a host null pointer.

The miss path invokes5E1C,70A3 and6AA2 in order. Filename matching retains exact
case, basename, extension and twelve-byte semantics. A first free cached row
aborts the search. Metadata seek/rewind and close errors are ignored as in the
component contracts. Allocation failures retain their metadata prefix; raw open
and read failures preserve open handles and any bytes already written. No
cleanup, rollback or added close is inferred.

Tests compare the full64KiB data group,900 descriptor bytes and boundary
pointers, complete synthetic payload, service order, failure message, normal
far return and preserved registers. They include two relocation bases, cache
hits/misses/holes, descriptor and segment exhaustion, partial read errors,
exact-block EOF, segment-zero acquisition and a file whose actual bytes grow
after the size query. The original raw reader does not limit writes to the
earlier paragraph allocation; the adapter must expose these writes within its
admitted pool rather than silently clamp them.

The root RETF consumes its four-byte return frame and leaves the near filename
argument for its caller. Its raw-loader call pushes three words and removes
six bytes, unlike the separate6D50 packed-loader ADDSP8 anomaly. Normal AX is
zero and DX is the returned segment. DS/BP/SI/DI and the caller argument survive
the admitted service profile. Basename execution clears DF; incidental scratch
outputs and flags still require actual caller review.

These are serialized, bounded code comparisons. They do not accept any supplied
resource, actual DOS service, fatal cleanup, asynchronous cache ownership,
complete state machine, rendering, audio, gameplay or fidelity. CGA remains
behind full EGA portable code-contract closure.
