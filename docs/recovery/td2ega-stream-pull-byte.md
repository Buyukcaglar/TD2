# Stream fill and first-byte read

`13A8:0B42` now has a bounded C contract with actual `0BE8` allocator
instructions and the `247C`/`094A` reader. Its far entry takes one near stream
offset in SS; the stream itself uses current DS. The three initial flag guards
retain their distinct ZF results. Otherwise, the signed channel byte selects
the six-byte side record, whose bit04 is cleared before the allocation guard.

Stream flags0C or side flag01 reset the cursor from the existing base. The
other path calls `0BE8` through a real near frame. It then rereads the channel,
pushes the current side count, base and signed handle, and calls `247C` through
a real far frame. The global DOS service limit spans both children. Nested
allocator, mapper and read-step limits remain separate.

After the reader returns, the parent uses its actual returned DS/SI/BP. It
stores AX into the count field before testing signed positivity. A positive
count decrements that field, saves the cursor, increments the cursor, and only
then fetches the byte at the old cursor. An alias can therefore change that
byte during the increment. The result is an unsigned byte in AX with CF0/ZF1.
Zero and negative counts mark stream flags10 and20 respectively, clear the
count and return FFFF with CF0/ZF0. Actual SS saves and far-return words are
read after all mutations; the caller owns the argument word.

The C17 `/W4 /WX` build passed27,080 original-instruction comparisons:
2,761,674 executed instructions and all498 feasible sites in the527-site
family. The29 allocator exclusions retain the reviewed fixed-mode argument
proof. Whole memory, registers/BP/CF/IF/DF, normal-root ZF, service requests,
control and counters match, including444 raw child returns,68 changed root
returns and48 reader pre-RET qualifications. Raw targets are never followed.
Thirty-two native interface checks and the70-site static review are separate.

The first26,952-case attempt matched every per-case comparison but failed its
coverage gate on ten reader sites. Its exact validator and log are retained.
The selected second receipt adds focused LF, Ctrl-Z and lookahead cases; C,
DLL and child implementations did not change.

The four known callers immediately execute ADD SP,2, replacing arithmetic
flags. RS266 gains a direct side-record consumer, and RS262 a conditional
consumer through the reader's mapper; no new resource span is asserted.
Actual caller DS/SS domains, all writers, valid indices, buffer capacities,
ownership, lifetime, interrupt exclusion and core integration remain open.
Synthetic DOS services omit real INT frames. Historical CPU/A20 behavior,
full resource decoding, a DOS session, renderer, audio, complete state-machine,
gameplay and fidelity acceptance remain open. Physical086C remains unassigned.
CGA stays behind EGA portable code-contract closure.
