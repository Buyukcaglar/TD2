# Alternative exit-video request paths

`06C9:5FBC` now has a bounded C contract for both paths selected by current
DS:5E6E after PUSH DI. The push itself can alias that byte and change the branch.
The zero path calls actual642E and840A with live SS frames, incoming DF,
globally shared budgets and full synthetic BIOS returns.

The nonzero path masks physical0410 through0040:0010 with AND FFCF/OR0030.
It issues two byte OUTs, then twelve index/value pairs reading current
DS:5E7C+BX after each index OUT. CLD precedes16,384 zero-word effects at
B800:0000..7FFE. A final byte OUT precedes BIOS INT10 AX0007. Both paths
restore DI from the live saved SS word after BIOS; BP is not saved here.

The C17 `/W4 /WX` build passed1,224 comparisons,8,141,600 original instructions
and all91 parent/child sites. Whole bus, SS frames, registers, CF/IF/DF,
requests and counters match. Coverage includes6,498,044 device word effects,
1,568,072 byte effects,14 changed child returns,36 changed root returns,
24 pre-RET qualifications and four BDA-word/root-frame aliases. All42 native
checks passed separately.

The first comparison attempt reached a fixture assertion conflict: its BDA
case deliberately rewrote the plane child's return frame but expected a normal
root return. The whole-state comparison matched before that assertion. The
failed validator is retained; the selected second comparison uses a profile
without that return mutation. C and DLL remained unchanged.

RS280 records the initialized twelve-byte port-value candidate at5E7C..5E87.
Its runtime DS, all writers, controller units, hardware interpretation,
storage lifetime and exclusion remain open. The actual main caller next
returns through its epilogue to startup finalization; full BIOS BP/DS/IF/DF
and caller stack profiles remain unclosed.

Typed device adapters preserve CPU state and own raw RAM byte/word effects.
Synthetic BIOS callbacks do not deliver real INT frames. Historical CPU stack
faults and A20, actual DOS sessions, renderer, audio, complete state-machine,
gameplay and fidelity remain unqualified. This is a path inside TD2EGA;
CGA edition recovery remains behind EGA portable code-contract closure.
Physical086C remains separate and unassigned.

Evidence: [comparison](evidence/td2ega-exit-video-validation-v2.json),
[context](evidence/td2ega-exit-video-context-v1.json),
[native diagnostics](evidence/td2ega-exit-video-native-diagnostics-v2.json).
