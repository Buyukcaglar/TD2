# Literal BIOS request sequence at642E

`06C9:642E` has a bounded C contract for its actual plane-fill child and
two BIOS requests. XOR AX,AX and PUSH AX precede the actual far call to840A.
The child uses the live SS frame and incoming DF. Its actual return is checked
before ADD SP,2 consumes the zero argument. Changed targets are recorded after
RET and never followed.

The parent masks physical0410 through0040:0010, then requests INT10 AX0003.
It adopts the full returned register/BP/DS/ES/CF/IF/DF state. The second request
changes only AH to0B and BX to zero, retaining AL and the other returned state.
The final full synthetic BIOS state and any far-frame mutations remain visible.
No fixed BIOS preserved-register profile or hardware effect is assumed.

The C17 `/W4 /WX` build passed422 comparisons,1,788,098 original instructions
and all47 parent/child sites. Whole bus, SS frames, registers, CF/IF/DF,
ordered effects and counters match. Coverage includes44 changed child returns,
32 changed root returns,12 pre-RET qualification cases and four BDA-word/root
far-frame aliases. All33 native diagnostic checks passed separately.

Main and fallback callers return through epilogues to startup finalization,
whose060D CMP replaces arithmetic flags. The fatal caller's next68C4 body
replaces them with OR AL,3; the16FC caller immediately executes SUB AX,AX.
Full caller stack/BP/DS/IF/DF domains and exclusion remain open.

All16-bit SP inputs retain their body effects; unqualified four-byte child or
root far frames produce native5 before RET. Historical CPU limits, exception
delivery and A20 remain unqualified. Device requests use a raw RAM adapter,
and synthetic BIOS callbacks do not deliver real INT frames. No DOS session,
renderer, audio, complete state-machine, gameplay or fidelity acceptance is
established. Physical086C remains separate and unassigned. CGA recovery remains
behind EGA portable code-contract closure.

Evidence: [comparison](evidence/td2ega-video-reset-validation-v1.json),
[context](evidence/td2ega-video-reset-context-v1.json),
[native diagnostics](evidence/td2ega-video-reset-native-diagnostics-v1.json).
