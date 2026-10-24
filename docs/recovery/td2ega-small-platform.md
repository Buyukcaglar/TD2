# Small DOS and BIOS wrapper contracts

The [comparison](evidence/td2ega-small-platform-validation-v1.json) passed
9,600 synthetic vectors and all50 instruction sites, executing63,744 original
instructions. There are5,760 normal far returns,3,840 prefixes stopped before
an INT service boundary and7,040 completed synthetic service calls.
[Ten native checks](evidence/td2ega-small-platform-native-diagnostics-v1.json)
separately cover invalid interfaces, adapter failure and an invalid returned flag.

| Entry | Raw service and resulting behavior |
| --- | --- |
|06C9:5D4E|INT21 AH19, returned AL to DL, INT21 AH0E, then clear AH/CF|
|06C9:5D74|INT11, CL6, shift AL6, clear AH, return AX2 for shifted0/1, otherwise3/4|
|13A8:2E2E|INT21 AH19, increment AX then clear AH, reread SS argument through returned BP, store word at returned DS:BX, AX0/CF0|
|06C9:5D5B|SS near offset to DX, INT21 AX4301/CX2; returned CF selects AX1/error or AX0/success|
|06C9:5D2E|INT1A AH00; mask returned CX/DX with3F3F and OR8080, store currentDS52C2/52C4, return near offset52C2 in AX|

The [static/API review](evidence/td2ega-small-platform-context-v1.json)
uses the unchanged pinned Microsoft MS-DOS2.0 reference for AH19 get-default-drive,
AH0E set-default-drive and AH43/AL1 set-attributes identities. It corroborates
historical names and fields. It does not establish the deployed DOS version,
actual service behavior or any change to a real file. No Microsoft implementation
code is copied into the recovered C.

Adapters explicitly return GPR/BP/CF/IF/DF; fixtures vary DS and BP as well as
ordinary register values. The runtime drive wrapper rereads its argument using
returned BP and writes through returned DS. The two-call wrapper forwards the
first response's AL through DL while retaining other returned byte halves.
Error CF is preserved on5D5B's AX1 path. SS BP saves, plain far return frames,
service requests, complete bus and returned state match.

The synthetic service contract preserves SS/SP/CS control. Both the native
adapter and Unicorn INT hook omit real interrupt-entry/return frames and
actual BIOS/DOS implementation. Before-call native budgets and adapter errors
remain separate from original return/error values. The raw BIOS1A response
transformation does not assign units or frequency to physical086C; that literal
reader remains a separate anomaly. DS52C2/52C4 also lie in the known DAT-copy
destination, so their writer and lifetime ordering still require caller review.

Actual caller bounds, complete service semantics, all writers, lifetimes,
IRQ/reentry, full state-machine and core integration remain open. No actual
DOS session, device, renderer, audio, supplied-resource decode, gameplay or
fidelity acceptance follows. CGA remains behind EGA portable code-contract closure.
