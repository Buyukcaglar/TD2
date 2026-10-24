# Plane fill instruction and effect trace

`06C9:840A` now has a C contract for six byte OUTs surrounding8,000
device-byte writes. It saves BP/DI, selects ES A000, emits four setup port
writes, then reads the actual SS fill argument. DI starts at0 and CX at1F40.
There is no CLD: forward DF writes offsets0000..1F3F; reverse DF writes0000
thenFFFF down throughE0C1. The final two OUTs precede the actual saved-word
restores and plain far return. All three known callers push zero and later
consume the argument with ADD SP,2.

The port sequence is3CE:05,3CF:02,3C4:02,3C5:0F, followed by the byte
effects and3CE:05,3CF:00. The typed adapter preserves CPU registers and
flags; its response registers are ignored. The selected raw RAM adapter
owns each device write. Its trace and memory effects are verified separately
from EGA planar, register and latch behavior, which remains unqualified.

The first draft's all-SP far-return assumption was too broad. A full
comparison found a segment-word mismatch at SSFFFF/SPFFFF after the port,
memory, register and count checks matched. A24-case fresh-CPU microprobe
confirmed that Unicorn2.1.4 reads the far segment word from a linear adjacent
address across SPFFFE/FFFF, while two separate POPs use the wrapped SP.
The exact first source, validator, reviewer, recipe, DLL and native receipt
are preserved in the failed-attempt manifest.

The selected implementation retains all port, fill and saved-stack effects
for those inputs, then returns native status5 at843D before RET when the
actual four-byte frame crosses the stack-offset boundary (SP>FFFC). It
does not select either backend load or wrapped-word behavior as the game's
historical CPU rule. Intel's2016 real-address word far-return definition
checks the complete four-byte frame against stack limits before popping
it; historical CPU binding and exception delivery remain open.
[Intel RET reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf#page=556)

The C17 `/W4 /WX` build and1,472 comparisons cover all30 instruction
sites, whole bus/SS, registers/BP/CF/IF/DF, exact port/device requests and
counts. They retain16 pre-RET qualification cases after full work, reverse
DF, stack wrap, port-to-argument mutations, fill-to-saved-word aliases and
changed bounded return targets. All256 byte values appear in actual
one-element prefix comparisons. Twenty-eight native checks,16,000 static
direction-address checks and24 backend microobservations remain separate.

Actual caller stack/DF/IF domains, historical CPU and stack limits, primary
EGA device contracts, writers, storage, exclusion and core integration remain
open. No renderer, DOS session, audio, complete state-machine, gameplay or
fidelity acceptance is established. CGA remains behind EGA portable
code-contract closure.
