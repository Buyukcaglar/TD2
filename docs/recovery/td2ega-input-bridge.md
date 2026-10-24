# EGA input callback and BIOS bridge

2026-10-14.06C9:69FE/6A03/6A17/6A28/6A3B have one
[C17 export](evidence/td2ega-input-bridge-build-v1.json) and
[1,928 comparisons](evidence/td2ega-input-bridge-validation-v1.json), covering
all32 instruction sites at two load bases. BIOS16 and dynamic far callees
are explicit ABI services. These tests deliver no real interrupt or input.

69FE executes a far call through currentDS64DC/64DE then plain RETF. The
native code preserves the requested target and modeled returned registers,
segments and CF/IF/DF. Initial6A03 and main-installed65C5 are observed targets,
but the setter accepts arbitrary words, so the full target domain stays open.

6A17 saves BP, reads offset from SS:entrySP+4 and writesDS64DC, then reads
segment from SS:entrySP+6 and writesDS64DE. It restores BP and returnsAXsegment.
One alias fixture puts the second argument atDS64DC: the first publication
changes the segment subsequently read. This ordering must survive recovery.
6A28 returns the current pair in AX/DX. Neither masks interrupts; a serialized
comparison does not prove atomic publication or asynchronous caller safety.

6A03 queries BIOS16 AH1 and branches on returned ZF. Empty returnsAX0.
Available input invokes AH0, testsAL, and clearsAH only whenAL is nonzero.
AL0 retains the extended high byte. Normal CF is zero; returned IF/DF and
other service registers propagate. 6A3B repeats query/consume until empty,
then returnsAX0. Continuous input can prevent completion.

All five roots use plain far RETF, popping4 bytes without cleaning caller
arguments. The setter's two words remain caller-owned. The native interface
uses virtual four-byte far frames and six-byte BIOS interrupt frames, with
IF0 on BIOS entry and explicit returned ZF/CF/IF/DF. Services preserve SS/SP
and control frames; native live frames are not materialized in the bus.
Setter argument/data aliases are retained, while live control-frame aliases
are outside the admitted profile.

[Five native-only diagnostics](evidence/td2ega-input-bridge-native-diagnostics-v1.json)
cover invalid frames, budgets, continuous input, rejected BIOS and invalidZF.
They are excluded from original comparison totals and error equivalence.

Installed69B7 behavior has separate keyboard evidence; this packet alone uses
ABI mocks and does not establish actual installed-handler composition,
callback lifetimes, IRQ nesting, device input, full state or core integration.
No DOS game session, renderer/audio output, Windows gameplay or fidelity is
accepted. CGA remains behind EGA portable code-contract closure.
