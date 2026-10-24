# EGA video initializer

`06C9:90E8` now has a bounded portable C contract. Eight literal byte OUTs
precede an actual far call to `840A` with a caller-owned zero argument. The
child receives the actual SS frame and incoming DF; neither body executes
CLD. Its return must match the saved continuation before ADD SP,2 proceeds.
Changed child targets are recorded after RET and never followed.

The initializer masks physical0410 through0040:0010, then requests BIOS
INT10 AX000D. It adopts the full synthetic returned register/BP/DS/ES/CF/IF/DF
state. The next request is AX1002, ES equal to that returned DS and DX6848.
The IBM BIOS interface defines a17-byte buffer:16 palette values and one
overscan value. The adapter snapshots those bytes before palette callback
effects. Final registers and far-return words reflect all subsequent effects.

The C17 `/W4 /WX` build passed422 comparisons,1,603,694 original instructions
and all74 parent/child sites. Whole bus, actual SS frames, registers, CF/IF/DF,
requests and counters match. Coverage includes44 changed child returns,
32 changed root returns,12 pre-RET qualification cases and four cases where
the17-byte palette buffer aliases the root far-return frame. All37 native
diagnostic checks passed separately. One shared event budget covers ports,
device bytes and BIOS requests; the far-call budget is separate.

RS278 records the initialized17-byte parameter candidate at6848..6858.
Its actual runtime binding follows the mode BIOS's returned DS. All writers,
palette value interpretation, device hardware and renderer remain open.
The actual caller is0000:07B3 at07F7; its subsequent6A17 setter preserves
arithmetic flags until0809 ADD SP,4 replaces them.

All16-bit SP inputs retain body effects. Child or root four-byte far frames
crossing the selected qualification boundary produce native5 before RET.
Historical CPU stack limits, fault delivery and A20 policy remain unqualified.
Synthetic BIOS callbacks do not deliver real INT frames. No DOS session,
renderer, audio, complete state-machine, gameplay or fidelity acceptance is
established. Physical086C remains a distinct, unassigned external-word read.
CGA recovery remains behind EGA portable code-contract closure.

Evidence: [comparison](evidence/td2ega-video-init-validation-v2.json),
[context](evidence/td2ega-video-init-context-v1.json),
[native diagnostics](evidence/td2ega-video-init-native-diagnostics-v1.json),
[IBM BIOS interface](evidence/ibm-ega-bios-palette-reference-v1.json).
