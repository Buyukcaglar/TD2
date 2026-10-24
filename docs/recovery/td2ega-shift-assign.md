# Near-pointer shift and callee-clean far return

[9,600 comparisons](evidence/td2ega-shift-assign-validation-v1.json) passed
all19 original locations in13A8:2FD0 plus its actual2FC4 child, executing
3,424,512 original instructions. All256 CL counts are covered, with512
nonzero high count-byte fixtures,440 stack/data alias profiles,688 returns
with CF1 and128 raw root-return aliases. [Eight native checks](evidence/td2ega-shift-assign-native-diagnostics-v1.json)
cover invalid interfaces separately.

The root takes two SS words: a near offset in current DS and a count word.
It loads the pointed-to word pair into DX:AX and calls2FC4, which clears CH
and repeats single-bit SHLAX/RCLDX CL times. Count0 preserves the data but
clears CF through XORCH; counts beyond31 are repeated shifts, not a host
shift with a masked count. The root rereads its SS pointer, stores AX then DX
through current DS and restores its actual saved BP.

The literal instruction is `RETF 4`: it consumes the four-byte far return
frame and four argument bytes, ending at entry SP+8. It preserves the child's
carry; this is not ADDSP4 arithmetic followed by an ordinary return. Nested
child frames, source/output word order, odd offsets and effective-address
wrap match in the complete bus, including SS saves and return words. Raw
stack/output aliases are stopped after the original far return and expose
its resulting CS:IP/SP without executing the target.

The [static review](evidence/td2ega-shift-assign-context-v1.json) verifies16
operand/cleanup sites and two call sites within13A8:155C. AX/DX are observed
machine outputs; no original C return type or signed32-bit source type is
inferred. Actual near-field bounds, caller DS/SS correspondence, other flag
consumers, lifetimes, IRQ exclusion and complete state/core integration remain
open. Resource-fed phase2/3, actual device/render/audio/DOS session, gameplay
and fidelity gates remain separate. CGA remains behind EGA code-contract closure.
