# Runtime vector cleanup

`FN-EGA-000262` (`13A8:05E0`) loads the segment word DS7078. A nonzero
segment enables a far call through DS7076:7078 with BX2; offset zero is
valid. The callback returns through an actual SS far frame to05ED.

The helper then PUSHes current DS before LDS DX from6D89, requests
INT21/AX2500, and POPs DS from actual SS. It tests byte6DC6 in that restored
view. Zero skips the second request and leaves CF0 from the comparison.
Nonzero saves DS, reads raw AL6DC7, LDSes DX from6DC8, sets AH25 and invokes
INT21 again. After POPDS, the second service's CF is retained. The root
uses near RET2. No fixed secondary interrupt number is inferred.

The clean build-v1/comparison-v1 passed 15,360 cases and all 18 sites,
with 132,488 original instruction events. Full memory, actual SS saves
and callback/root frames, GPR/BP/CF/IF/DF, requests and control coordinates
are compared. There are 5,512 root near returns, 7,736 budget prefixes,
2,112 raw child returns, 8,656 synthetic DOS services and 9,600 callbacks.
Synthetic callback RETF instructions are counted separately. Fixtures cover
4,608 stack/global aliases, 3,072 minimum-SP16 cases, saved-DS service
mutations and 1,392 altered root offsets. Seventeen native rejection,
minimum-stack, adapter and budget checks are separate.

PUSHDS can overwrite a source word before LDS or alter the guard/vector byte;
those post-write reads are retained. A saved-DS mutation changes the view
used after POPDS. Callback operands overlapping the future SS call frame
are captured before the CALL overwrites them. Service-returned DS is not
silently treated as preserved.

Static review records one physical caller05D6 under two shared exit owners,
fifteen explicit address-reference candidates, and startup04CA/04CE writes
to6D89/8B from BX/ES. The optional callback pair and secondary-vector fields
are initially zero; this does not establish all writers or lifecycle bounds.
The05E9 indirect target, saved-vector ownership, aliases, IRQ exclusion and
actual caller lifetime remain open. Indirect/aliased writers and unclassified
code are outside the explicit-reference inventory.

The pinned DOS reference identifies AH25 as SET_INTERRUPT_VECTOR. Tests use
synthetic services and omit actual interrupt frames, vector installation,
restoration and IRQ delivery. No DOS session, device, renderer, audio,
complete state machine, gameplay or fidelity gate is established. CGA remains
behind EGA portable code-contract closure.
