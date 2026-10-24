# Raw mode controller composition

`06C9:53A6` now has a portable C contract with actual56ED and4612 calls,
the5446 tail, literal SS frames and three mutable near-jump operands.
It follows the actual word target among the13 reviewed parent blocks at
5514/55A1 and the three child blocks at57A7. An unknown target stops before
the original jump and retains its raw operand. This does not close the valid
mode domains or table writers.

The56ED exception at585A/585B pops the actual child return word into AX,
then returns through the parent root word with unchanged CS. This exits53A6;
the composition performs no additional root RET. Ordinary child RETs use
their actual near frames. Mode7 similarly rereads saved AX from SS after
4612 and the2F5B byte write; aliases can change the value before POP AX.
The5446 tail keeps the existing root frame and returns through it.

The no-mode SUB/SBB path executes OR AX,AX before JL, testing wrapped AX
sign. The two mode paths execute JGE immediately after SBB and use its
signed SF/OF relation. Overflow fixtures distinguish all three predicates.
The source also compares SI with DX after SI+=8/DX+=10 in two blocks; no
ring-end substitution is made.

The C17 `/W4 /WX` build passed38,280 full-bus comparisons,2,263,930 original
instructions and all530 feasible sites in the531-site fence. The remaining
5303 instruction has an entry-specific adjacent-branch disposition. Coverage
includes15,068 root calls,46,304 nested calls,280 nonlocal returns,3,494
unknown-transfer boundaries,44 changed child returns and88 changed root
returns. There are19,320 DS=SS and8,480 minimum-SP36 cases. Nineteen native
diagnostics are separate. Earlier comparison runs matched but lacked focused
coverage; only fixture changes were required, and the C/DLL stayed unchanged.

RS272 and RS273 identify the initialized3446 and3456 code-offset candidates,
containing eight and five words respectively. Their initialized lengths do
not bound the raw byte indices. Actual403B:4114 caller status flags are killed
by the next4D3F entry's XOR SI,SI; its whole state remains open.

All mode/target writers, caller state, actual DS/SS binding, storage ownership,
lifetime, interrupt exclusion and core integration remain open. No DOS game
session, renderer, audio output, complete state-machine validation, gameplay
or fidelity acceptance is established. CGA remains behind EGA contract closure.
