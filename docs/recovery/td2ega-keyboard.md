# EGA keyboard vectors and handlers

2026-10-13. `06C9:6860/68C4/6907/69B7`, `FN-EGA-000157..000160`, have four
[C17 exports](evidence/td2ega-keyboard-build-v1.json) and
[38,400 comparisons](evidence/td2ega-keyboard-validation-v1.json), exercising
all155 instruction locations. Ports, IVT, interrupt frames and key tables use
synthetic data; no real keyboard, BIOS/PIC, IRQ or input session executes.

6860 reads port21, masks IRQ0/1 with OR3 and examines vector09's offset at24h.
If that offset equals6907 it skips *both* vector installations, irrespective
of the vector segment. Otherwise it saves vectors09/16 at62AE..62B4 and installs
CS:6907 andCS:69B7. It restores the original port21 byte, establishes ES=DS,
clears exactly90 bytes at62BA..6313 with CLD/STOSB, restores DI and RETFs.
Pending keyword62B6 and last-scan62B8 are retained. AX/CX end zero; DF ends zero.

68C4 similarly masks/restores port21. A zero saved09 offset62AE skips vector
and BIOS-state restoration. Otherwise it restores all four IVT words and
ANDs physical0417 withF0. It leaves ES=0, AX with the original port21 byte in
both halves, and BX with the last restored segment. Neither function executes
CLI/STI; the native profile does not infer atomicity from PIC masking.

6907 executes STI before saving AX/BX/CX/DX/DS. It establishes principal DS,
reads scan byte60h, reads61h and writes its bit7-set value then its original
value back to61h. Break bytes clear their masked key slot. Make bytes store
the masked index at62B8 and publish1 to62BA+index *before* modifier selection.
Indexes5A..7F clamp to zero. There is no separate E0-prefix state in this code.

Modifier tests use bit0, in priority62F2,62D7,62E4-or62F0,62F4, then default.
They choose byte tables6480,6425,636F,63CA,6314. A translated byte below80 is
zero-extended into pending62B6. Bytes80..84 become a high-byte keyword with
AL0; bytes85..FF first clear bit7, then become the high byte. Breaks leave the
pending keyword and last-scan word unchanged. Finally it sends EOI20h to
port20h, restores saved registers and IRETs with the original frame flags.

69B7 preserves BX/DS while establishing principal DS:

| AH | Effect | Return |
| --- | --- | --- |
| 0 | CLI, load62B6 into AX and clear the word; even an empty word returns immediately | IRET, saved flags restored |
| 1 | Load62B6 without clearing, STI, OR AX,AX | RETF2, IF1 and result availability flags |
| 2 | AL=62E4 OR62F0, retaining AH2 | IRET, saved flags restored |
| Other | AX=0 | IRET, saved flags restored |

AH1's RETF2 consumes IP/CS and discards the flags word rather than restoring
it. ZF reports AX0; CF/OF clear, SF follows bit15 and PF follows low-byte
parity. AF is undefined and excluded from comparison. IF becomes1 and DF
remains the entry value. Tests check actual RETF2/IRET cleanup, registers,
defined flags, saved words and guards. [Four native-only diagnostics](evidence/td2ega-keyboard-native-diagnostics-v1.json)
keep API/port failures separate from original error equivalence.

The older input-poll receipt admits an IF/DF-preserving BIOS adapter. That
profile cannot describe this installed AH1 handler when incoming IF0.
Returned BIOS flags are now carried explicitly, with separate actual69B7
wrapper comparisons recorded below. The historical restricted receipt remains valid within its
stated profile; it is not installed-handler or whole-input acceptance.

Actual vector ownership, keyboard/IRQ nesting and timing, all table writers,
callback dispatch/UI bodies, CPU/A20 profiles, complete state-machine and
resource ownership remain open. No game, renderer, audio output or
gameplay/fidelity is accepted. CGA remains behind EGA portable code closure.

The inputservice nowreturns explicitIF/DF: inputpollv2 andinputupdatev3
comparisons retainpreserving/AH1IF1/DF-toggle profiles. The separate
[2,876 actualinstalled-handler compositions](evidence/td2ega-installed-keyboard-poll-v1.json)
close thepreviousIF-assumption gapfor65C5/6601. Wholeinput/IRQ/callback/core
acceptance remainsopen.

[9,984 separate420A/installed-handler cases](evidence/td2ega-installed-keyboard-update-v1.json)
nowcoveractualroot+13callees+69B7 andnativeinput/keyboard composition inboth
stablebranchforms. This doesnotestablish fullmutatortransitions, actualIRQ,
callbackbodies, source/resourceownership orwholegame acceptance.
