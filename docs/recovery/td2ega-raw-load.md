# EGA raw loader service contract

2026-10-13. `FN-EGA-000168`, far entry `06C9:6AA2`, has a bounded portable
service-driven C contract. [The build](evidence/td2ega-raw-load-build-v1.json)
and [776 comparison cases](evidence/td2ega-raw-load-validation-v2.json) compare
actual original instructions against native control, service requests, full
synthetic destination bytes and failure prefixes. Four native argument/service/
work-budget diagnostics are separate. No supplied resource or real file is read.

The three original word arguments are near filename at SS:BP+6, destination
offset at +8 and destination segment at +A. DOS open uses the caller's DS and
filename offset, mode AL=0. A successful handle is retained in a stack local;
zero and FFFF are preserved as opaque handle words in the synthetic profile.
Native I/O receives explicit data coordinates, never a host pointer formed
from an original near/far address. The service owns file access and byte storage.

Each read requests exactly4000h bytes at the same destination offset, with the
current destination segment loaded into DS. Carry-set read transfers to the
fatal prefix. Every carry-clear read increments the local segment by0400h
modulo65536, including a short read or zero-byte EOF; only AX=4000h repeats.
Consequently an exact-multiple file has one extra zero-byte read. The final
physical block FC00:0000..FFFF is covered, followed by EOF at0000:0000 and
local next-segment0400. Actual data in those cases remains below1MiB; synthetic
guard bytes above it establish no A20 behavior. Other caller range/allocation
preconditions still require proof.

After a short successful read, the original closes the handle and ignores
close carry and AX. It returns the *original* destination offset in AX and
segment in DX, restores DS/BP and far-returns, leaving the three arguments for
caller cleanup. SI, DI, ES and SS are preserved. It does not return the final
advanced segment or a byte count. The adapter records read count and local
segment for review; those are explicit native metadata, not invented original
return registers.

Both open and read errors enter6AF1, establish relocated principal DS, push the
filename and message offset64E0, and call16A7:0002. **There is no close before
that transfer.** Read-error cases preserve prior full blocks and any bytes the
synthetic service wrote before reporting an error. The handle remains live
until the separate fatal cleanup contract acts. The tests stop before6AFD's
far call: AX=64E0, BP owns the still-active locals, SP has the saved BP/DS and
two fatal arguments. Native status1 denotes this prefix rather than a normal
original return or accepted fatal cleanup.

The admitted synthetic service profile changes AX/carry and requested memory
only, preserving other registers. Native callback failure, null arguments and
work-budget exhaustion produce status2 outside the original contract. The
service/context/result storage is disjoint, each byte write must be valid in
the caller's supplied arena, and actual real-DOS register/error behavior and
every caller's allocation/lifetime remain platform obligations. The adapter
does not expose incidental arithmetic flags; callers must be reviewed before
integrating that API.

This raw loader is separate from the packed wrapper's extra ADD SP8 cleanup,
run/block and prefix stages, decoded resource schemas, actual filesystem
persistence, complete state machine, gameplay and fidelity.

[64 default fatal-chain cases](evidence/td2ega-fatal-default-v1.json) execute16A7:0002,29F6, signal22 lookup/defaultdispatch andruntime exit toDOS4C03. Video/input/timer cleanup, formatter anddiagnostic emission areABImocks. The wrapper forwardsfivewordstoB00;08B7 iscallee-clean RETF2 andtakes diagnosticcodes, notcharacter bytes. Exitrequestsclose onlyforflaggedruntimehandles5..19 andrestoresvector00 plusanoptionalvector. Actualprocess termination andunregisteredrawhandle release remainplatformcontracts; noactualDOSprocess executes.
