# Reviewed EGA startup interfaces and segment context

2026-10-13. `P1-03` follow-up to [startup analysis](td2ega-startup.md), using the same hash-admitted image. Coordinates below are unrelocated module segment:offset. Static contracts and a saved tool-context reconciliation establish this task; they do not establish a DOS startup session.

The current private project is `analysis/ghidra-projects/TD2EGA-context-v2.gpr`.
[Startup readback](evidence/td2ega-context-startup-v2.json) records17 fixed
startup DS/SS ranges; [mutator readback](evidence/td2ega-context-mutator-readback-v2.json)
records six additional DS ranges. An [independent reopening](evidence/td2ega-context-import-readback-v2.json)
verifies all130,240 saved image bytes and1,652 relocations at synthetic load1000h,
with no byte mismatch. Unknown PSP, environment, arbitrary LDS and restored
caller DS remain symbolic. The original analysis project and historical v1
evidence remain available. This context project has no automatic analysis
pass; the corrections do not admit decompiler signatures.

## Segment ownership

Register values apply before the instruction at the named boundary. DS initially selects the PSP; its numeric value depends on the DOS loader and is not globally fixed in the tool. `MOV SS,DI` at `13A8:0415` establishes the relocated `178Fh` group beginning at `0417`. The normal startup path keeps PSP DS through `046F`, while explicit SS prefixes access group bookkeeping. `POP DS` at `0470` establishes group DS beginning at `0471`.

| Range or transition | DS ownership | SS ownership |
| --- | --- | --- |
| Entry through `0415` | PSP | Initial metadata stack until SS assignment |
| Normal `0432` through `0470` | PSP | Principal `178F` group |
| Error path beginning `0420` | Principal group, from separate `PUSH SS; POP DS` | Principal group |
| Runtime init `04BE` through `04D3` | Principal group | Principal group |
| `04D4` through `04DD` | CS, for DOS vector installation | Principal group |
| `04DE` through `04F0`; `04FE` through `0505`; `0512` through `053F` | Principal group | Principal group |
| `04F1` through `04FD`; `0506` through `0511` | Far pointer selected by LDS; restore occurs at final POP DS | Principal group |
| `0540` through `0552` | Environment segment during copy, restored at `0552` | Principal group |
| argv `0694` through `06D7`; `0756` through `0779`; `081E` through `0825` | Principal group | Principal group |
| argv `06D8` through `0755`; `0788` through `081D` | PSP command tail | Principal group |
| argv `077A` through `0787` | LDS-selected executable-name source, then PSP restored | Principal group |
| env `0826` through `082D`; `0854` through `0869`; `0887` through return | Principal group | Principal group |
| env `082E` through `0853` | PSP | Principal group |
| env `086A` through `0886` | Environment source | Principal group |

Only numerically established ranges are written to Ghidra. PSP, environment and arbitrary LDS values remain symbolic. Main's DS is fixed only before its first call; later caller/callee preservation is a contract to review, not a global DS override. Its normal stack remains in the principal group. The direct-flow inventory finds only the startup SS assignment; unresolved indirect paths are still outside that observation.

The separate mutable platform family has these additional before-instruction
DS contexts in v2. Its SS is inherited; no fixed SS override is applied there.

| Mutable range in13A8 | DS ownership |
| --- | --- |
| 003B..0045 | Physical segment0 |
| 0046..0163 | CS13A8;0163 then restores caller DS |
| 0169..0180 | Relocated06C9 code segment |
| 0182..0187 | Relocated1793, four paragraphs above principal178F |
| 0189..01A2 | CS13A8 |
| 01A3..01A7 | Physical segment0; following restoration returns symbolic caller DS |

These ranges describe the [reviewed mutable family](td2ega-mutable-platform.md),
whose code states and alias writes remain distinct from startup. Conditional
DS=SS requirements in header/codec, curve and input-consumption paths are
caller preconditions; they are not saved as global segment equality.

BP-based memory operands default to SS even while DS selects the environment. In particular env writes at `086F`–`0882` construct a near-pointer array in the principal group; these are not writes into the environment source. SI-based source reads select DS and STOSB selects ES. Flattening every access under one assumed DS would corrupt this interface.

## Startup helper interfaces

The table specifies observed machine interfaces. It does not assert original source prototypes or a precise compiler version. Far-frame arguments follow saved BP at offsets `+6`, `+8`, etc. A near CALL immediately preceded by PUSH CS also supplies the four-byte far-return frame.

| Entry | Reviewed interface and return convention |
| --- | --- |
| `13A8:04BE` | Far call; runtime init saves DOS version, installs divide handler `13A8:049B`, visits optional far service at group `7076:7078`, inspects environment/file-handle flags, invokes initializer spans. RETF at `0581`. DS temporarily changes as above and returns to group. |
| `13A8:060D` | Near internal helper. SI/DI delimit a near array of far function pointers. Walks backward in four-byte steps; skips null pairs, far-calls `[DI]`, returns with RET at `061F`. Empty/reversed spans do nothing. Callback effects require their own contracts. |
| `13A8:0826` | Far call, no stack arguments. Reads PSP environment, reserves group storage, copies strings, builds a null-terminated array of 16-bit near offsets, stores its group offset at `6DBC`. BP-default SS is essential. RETF at `088B`; DS restored. This is not a far-pointer argv/envp array. |
| `13A8:08E2` | Near allocation helper used by env. AX is requested byte count; DI selects failure-message ID. Reads/updates group `6D2A` and allocation limit `6D24`, optionally resizes DOS allocation. On success BP receives old allocation cursor and AX receives old BP, followed by RET at `091E`. Caller saves/restores its original frame BP separately. Failure branches into startup termination. Do not translate as a conventional AX-returning allocator. |
| `13A8:0694` | Far call; immediately pops caller IP/CS into group `6DD6/6DD8`, then retains command-line allocations on SS stack. Stores argc at `6DB8` and near argv offset at `6DBA`; each argv item is a near group offset. Restores DS, writes null argv terminator, resumes saved caller with indirect far JMP at `0822`. This edge is a saved return, not game dispatch. |
| `0000:07B3` | Far application entry. Caller pushes envp, argv, argc as three words. BP+6 is argc; BP+8 is near argv (used at `07D9`); BP+Ah is the passed near envp. Main returns AX with RETF at `0C03`. Startup then passes AX to exit helper. Source-level names remain descriptive. |
| `13A8:0582` | Far entry with exit code at BP+6. Runs finalizer spans, checks runtime checksum, closes flagged handles, restores saved vectors through near helper `05E0`, and performs DOS AH=4Ch at `05DE`. No normal return is expected; direct-flow fallthrough is only conservative discovery. |
| `13A8:088C` / `08B7` | Runtime message lookup/output helpers consume one word and use RETF 2 (callee cleanup). `08B7` writes via DOS AH=40h, BX=2. Do not add caller cleanup or apply main's caller-cleaned convention here. |
| `13A8:2988` | Far near-string comparison: arguments BP+6 and BP+8 are offsets in DS, ES becomes DS. Restores SI/DI/BP, returns -1/0/+1 in AX, RETF at `29B2`; caller removes four argument bytes. |
| `06C9:6A17` | Far callback setter: BP+6 offset, BP+8 segment; writes group `64DC/64DE`, RETF. Main supplies `06C9:65C5`. Indirect far call at `69FE` consumes that pair; initial image pair is separately `06C9:6A03`. |

Main has eight near-call encodings preceded by PUSH CS. Preserve their far-return frames; classifying every E8 as a near-return function is incorrect. Runtime also contains ordinary near RET helpers, RETF helpers, RETF 2 helpers, nonreturning DOS exit, and a saved far-return JMP. These are distinct conventions.

Near offset zero and host NULL must not be conflated. Main accesses argv's second word at `07DC` without a preceding argc check, then passes it to the near-string comparison. A zero word addresses DS:0000 at machine level; its supported interpretation needs the data-group/caller contract. Conversely a returned resource offset AX=0 with nonzero DX is a valid far allocation. Any native pointer conversion must preserve these distinctions rather than introducing host C null dereferences or rejecting valid offset-zero blocks.

## External word anomaly

`06C9:5D83` sets ES=0040h, reads ES:046Ch into AX and RETFs. `06C9:5D8D` does the same, subtracts the caller word at SS:BP+6 modulo 65536, restores BP and RETFs with caller argument cleanup. Neither routine reads physical 046Ch.

[Sixty isolated cases](evidence/td2ega-external-word-validation-v2.json), at two relocated code segments with different sentinels at physical 046Ch and 086Ch, verify the physical **086Ch** read, AX, ES, preserved DS/SS/BP, allowed writes and far-return frame. Both segment immediates and read displacements are verified absent from the admitted relocation table. A Unicorn read-hook issue affected the initial fixture when callbacks covered RETF stack reads; the accepted fixture observes only low external memory and checks the final return registers directly. A [separate synthetic probe](evidence/unicorn-retf-read-hook-probe-v1.json) reproduces the tool limitation without original bytes.

The main caller samples at `07CD`/`0A07` and requests differences at `0945`/`0AAE`. That is evidence of elapsed-word use, not an admitted timer implementation. Firmware contents, timebase, cadence, and whether this is an original defect remain unresolved. No offset patch or timer-frequency assumption is authorized by these results. P1-07 retains that semantic question.

Later P1-05 work found a separate [main-called mutable platform family](td2ega-mutable-platform.md) below startup in segment13A8. It changes DS among zero/CS/relocatedcode/data aliases, reconstructs a near return through PUSH/RET, and conditionally replaces the state tail's CLC by RETF. These are additional caller/code-state contracts, not a reason to globally force DS=the principal group or label all13A8 functions compiler runtime. The observed mutator does not change the086Ch reader's code/address.

`P1-03` closes loader/address/register and startup ABI review. Remaining full callback/dispatch reachability belongs to P1-04, data/resource/state ownership to P1-05, and platform scheduling to P1-07. Game startup, runtime acceptance, rendering, audio output and fidelity remain unestablished.

The fatal-chain review independently exercises08B7's RETF2 convention withdiagnosticcodes10/FC/FF/1 underABImocking; thesevalues are notadmittedcharacteroutput. [Default fatal-chain evidence](evidence/td2ega-fatal-default-v1.json) preservesfivewordformatterforwarding andtheoriginalcleanuporder.

## Additional arithmetic-helper convention

The [bounded2EE8 review](td2ega-signed-motion.md) verifies a distinct callee-clean
far convention: two32-bit operands, DX:AX low32 product and RETF8. The composed
06B3:0008 caller performs no additional argument cleanup. This does not alter
the earlier near/far pointer, argv continuation, allocator-BP or RETF2 contracts.


The [reviewed callback walker](td2ega-finalizer-list.md) now has a C17/body
comparison packet. Six unique caller sites have fixed SI/DI operands: only
0582's call0594 uses7082..7086; direct0599's05A2/05AB use empty7086 spans.
Initialized0A3A callback body, all writers/aliases/lifetime and core remain open.
