# In-place shift and optional strip

`06C9:AE62` takes eight SS words: x, y, width, height, stride, member
offset, member segment and index. After literal setup OUTs it reads x,
shifts it logically by three, computes a CS row address and performs a
forward A000-to-A000 REP copy. Width is reread for each row; stride delta
and the row counter remain in registers. Height0/8000 execute one row.
Six literal ports precede the optional member path.

The optional path uses two byte MULs. The first multiplies the low bytes
of member height and width, adds headerF's high nibble and subtracts the
full requested width. The second multiplies the low bytes of index and
requested width to locate the source. These operations retain their
truncation even when the supplied words have nonzero high bytes.

A zero plane nibble exits the whole function. Each nonzero nibble emits
two ports, then performs unconditional LODSB, a destination-byte read into
AH, a byte write from AL and LOOP. A starting width0 therefore executes
65,536 iterations; the preceding REP width0 copies no bytes. SS skip,
destination and byte-plane counter are read after earlier effects. Raw
RAM adapters preserve CPU state and own the byte effects.

The C17 `/W4 /WX` build passed10,708 original-instruction comparisons:
3,041,104 executed instructions and all102 sites. Four complete width-zero
cases match65,536 loads, reads and writes each, with wrapped SI/DI/CX.
Whole memory, registers/BP/CF/IF/DF, device requests, counters and control
match, including eight changed root returns and24 pre-RET qualifications.
Forty-eight native checks and static byte-MUL/counter proofs are separate.
The earlier10,680-case passing receipt is retained; the selected second
receipt adds full wraps and completed qualifications without changing C/DLL.

Actual DS/DI/SI saves are popped before MOV SP,BP, POP BP and plain RETF.
The sole known caller immediately ADD SP,10hex and replaces arithmetic
flags. No new initialized resource span is asserted. Actual caller DS/SS,
member format, capacities, all writers, ownership, lifetime, interrupt
exclusion, EGA write-mode/latches, renderer and core integration remain
open. Isolated raw RAM comparisons establish no DOS session, audio output,
complete state-machine, gameplay or fidelity acceptance. CPU/A20 behavior
and physical086C semantics remain unqualified. CGA stays behind EGA
code-contract closure; full resource decoding has not started.
