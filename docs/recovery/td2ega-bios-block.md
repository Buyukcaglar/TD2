# EGA raw BIOS10 block wrapper

2026-10-14.06C9:ABFA/FN-EGA-000236 has one
[C17 export](evidence/td2ega-bios-block-build-v1.json) and
[1,024 comparisons](evidence/td2ega-bios-block-validation-v1.json), covering
all10 instruction locations. BIOS10 is an ABI mock with a synthetic six-byte
interrupt frame; no actual BIOS or video device executes.

The wrapper saves BP, setsES to incomingDS, setsAX1002, and reads a near DX
argument through SS:BP+6. It invokes INT10, restores the saved BP, and uses
plain RETF, popping four bytes. The argument remains caller-owned. Returned
BIOS registers, segments and modeled CF/IF/DF propagate except BP, which is
restored even when the service changes it.

The native request exposes interrupt-entryIF0 and saved CF/IF/DF; the response
starts with pre-interrupt register values. Services can return explicit flag
and register changes. Native frames are virtual, with code/data/control-frame
separation and a nonwrapping stack. Four
[native-only diagnostics](evidence/td2ega-bios-block-native-diagnostics-v1.json)
are excluded from original differential totals and error equivalence.

The [3532/resource review](evidence/td2ega-sequence-resource-context-v1.json)
corrects the earlier near-text label for2E08/2E10. These are raw blocks passed
to BIOS10 AX1002. Their actual BIOS read extent, platform behavior, decoded
content and rendering acceptance remain open. The surrounding396-byte
initialized span has seven conditional near pointer/count extents, not a
universal runtime bounds proof. No original point or block payload is exported.

Actual caller/handler ownership and remaining EGA code contracts stay open.
No DOS session, renderer/audio output, complete state machine, Windows gameplay
or fidelity is accepted. CGA remains behind EGA portable code-contract closure.
