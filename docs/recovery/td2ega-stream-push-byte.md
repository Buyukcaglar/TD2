# Stream cursor byte write

`13A8:21D6` now has a C contract composed with actual0BE8 and its heap
family. The far entry accepts a word value and a near stream offset.
It requires stream flag01 and rejects the full wordFFFF. A missing base
offset calls0BE8 through its actual near frame, then discards that argument.

The body compares the current cursor with the base. Equality with a nonzero
count returns AXFFFF. Equality with count0 increments the cursor first;
the common path then increments the count, decrements the cursor and writes
the low byte of actual SI. Word wrap and pointer underflow are preserved.

That byte write occurs before flags are masked with EF and flag40 is tested.
An alias can therefore change the flag or channel that the later operations
read. When flag40 is clear, the actual signed channel byte is multiplied
by six and bit04 is set in current DS:[6E94+index]. The nominal20-row RS266
candidate does not establish a bound on this raw signed index.

Success returns SI's low byte in AX, with CF0/ZF1 from SUB AH,AH. Source
failure returns AXFFFF with the literal guard flags. Saved SI/DI/BP and
the far return are read from actual SS after the writes. Plain RETF consumes
four frame bytes; all eight known callers consume both arguments with
ADD SP,4, replacing arithmetic flags.

The C17 `/W4 /WX` build passed12,152 comparisons and all357 feasible
sites in the386-site family fence. Full bus/SS, registers/BP/CF/IF/DF,
required normal ZF, service requests, counters and control match. The29
exclusions retain the literal2830 parent-argument proof; standalone2852
covers its complete body. All256 signed channel values appear in actual
success comparisons. The selected run adds64 byte-to-flag/channel aliases
and eight metadata-to-return aliases; those return words change1111 to1115
before actual RETF. The previous12,080 cases passed; C and DLL stayed
unchanged. Twenty-three native checks remain separate.

Complete callers, all writers, valid indices, DS/SS bindings, capacities,
ownership, lifetime, interrupt exclusion and core integration remain open.
Synthetic DOS services omit real INT frames; historical CPU/A20 behavior
remains unqualified. No DOS session, renderer, audio, complete state-machine,
gameplay or fidelity acceptance is established. CGA remains behind EGA
portable code-contract closure.
