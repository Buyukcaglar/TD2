# Defined return flags for the record helper

`FN-EGA-000388` (`06C9:4F92`) now has a compiled return-flag view around
the unchanged recovered record-math C body. A read-only preview classifies
the initial reject/skip/update decision in serialized flat RAM. The actual
body performs all state changes, SS saves and near return. The view exposes
defined flag bits, a mask and the source return site.

| Return site | Last flag setter | Defined mask |
| --- | --- | --- |
| 4FA9, early reject | CMP BX,FFFC | 0ED7 |
| 5016, updated records | XOR AX,AX | 0EC7, excluding AF |
| 5021, skipped record | INC DX | 0ED7, retaining prior CF |
| Native loop prefix | Existing CF/IF/DF and analysis bit1 | 0603 |

The masks expose modeled status flags plus IF/DF and analysis bit1. Other
bits in the returned value are placeholders. The [Intel INC/CMP reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf#page=551)
corroborates carry preservation and status effects. AF after XOR is
architecturally undefined, so it is excluded rather than assigned the
emulator's chosen value. [Intel XOR reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2c-manual.pdf#page=597)

The clean C17 build passed 278,432 original-x86 comparisons, 4,773,396
instructions and all 54 sites. There are 262,144 exhaustive INC-DX cases:
all word values, two preceding-CF setups and two load/IF/DF profiles.
These cases have zero source/native write events; the whole buses are
compared at each profile end. Another 16,288 cases compare full bus,
SS saves, registers, control and every claimed flag bit. Thirteen native
interface/mask diagnostics are separate.

The comparison includes 262,140 cases with AX zero and ZF zero, and 770
with AX nonzero and ZF one. AX therefore cannot supply the caller's ZF.
The existing CF/IF/DF-only record-math evidence remains valid within its
scope; this view adds the flags needed by the actual consumer.

`4D3F` saves the first 4F92 result's FLAGS at `4E27`, restores the SS word
at `4E58`, then executes JNE at `4E59`. Three further direct JNE sites
follow 4F92 calls and flag-preserving MOVs. Opcode75 tests ZF. [Intel Jcc reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf#page=585)

Full parent composition still requires raw PUSHF image construction for
CPU-specific and undefined bits, the actual SS flag-word writes/reads and
POPF effects, ownership/alias lifetime and caller context. The defined-mask
view alone cannot materialize that raw word. Preserve its uncertainty or
provide an explicit CPU-profile input; no private-stack assumption or AF
policy has been assigned here.

The full `4D3F` body, core integration, actual CPU/IRQ/DOS session,
renderer/audio output, complete state-machine, gameplay and fidelity gates
remain open. CGA remains behind EGA portable code-contract closure.
