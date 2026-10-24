# Byte-ring caller context

2026-10-13. The expanded graph finds eight unique direct call sites of `FN-EGA-000003` at `06C9:780E`, including simulation calls reached through vector 08's callback registrations. [Verification](evidence/td2ega-control-map-verification-v5.json) checks every far-call encoding and preserves their original coordinates. Shared tails can give one call site several candidate owners; these do not count as additional consumption sites. The bounded helper C and its earlier 131,584 vectors remain unchanged.

| Caller owner | Call site | Observed use of AX |
| --- | --- | --- |
| `FN-EGA-000019`, `019E:0004` | `019E:000A` | Masks AX with 7, uses 16-bit CWD, and selects one of eight key-code-shaped values; returns selected word at `0094..009A`. Both `019E:06C5` and `0267:139B` call this owner. This is instruction evidence for synthetic input selection; live game-state purpose remains provisional. |
| `FN-EGA-000026`, `0267:0039` | `0267:0A59` | Stores AX and divides the byte range into three categories using signed comparisons with 85 and 171. AX is zero-extended by the helper, so signed/unsigned thresholds agree for this caller. |
| `FN-EGA-000030`, `0267:15E4` | `0267:19D8` | Copies AX to CX, multiplies by a selected signed parameter minus one, applies 16-bit sign/absolute/shift operations, and stores at DS:`865A`. Exact overflow/rounding must be retained in P1-06. |
| `FN-EGA-000083`, `06C9:1E59` | `06C9:1E79` | Compares returned AL with DS:`1A70` to choose a conditional record-copy path. Owner first sets ES=DS, BP=3813h, and uses BP+SI default SS accesses; DS=SS aliasing is required on this path. |
| `06C9:4674` simulation path | `06C9:46F4` | Compares AL unsigned against DS:`337A`; only successful threshold results consume the next byte at `4713`. |
| Same path | `06C9:4713` | Masks AL to four bits; rejects 15 and 7, then uses the signed result after subtracting 7 to choose alternate record paths. Consumption is conditional on the previous sample. |
| Same path | `06C9:475B` | Masks AL with 7, repeats the call while the result is 6 or 7, then scales an accepted result by 5 and stores a record selector. This is a variable-consumption rejection loop. |
| Shared simulation tail from `49E7/4A19/4A2E` | `06C9:4A41` | Uses signed AL positivity; nonpositive bytes return early. Positive bytes can update counters and choose main states 5/6/7/8 using thresholds and parameter comparisons. Preserve the signed branch rather than interpreting all nonzero bytes as positive. |

These callers refute a model in which AX is unused on every supported call. They support a shared deterministic byte source used in selection, threshold and scaling paths. They do not recover the original C declaration or establish a complete RNG/seed policy.

The cursor remains at principal-group `66E6` and the byte array at `66E8..67E7`. The current syntactic scan finds only the helper's direct absolute cursor/array operations. That does not exclude indexed copies, resource overlap, aliases or later discovered writers. Initial media-backed array provenance, owner lifetime, reset/seed behavior and exact consumption order across complete state transitions remain required before core integration. The helper continues to expose explicit state and remains outside the complete portable game core.

Simulation consumption is reachable through `61BF` → indirect far callback `403B` → simulation helpers, while the other sites run in application orchestration/presentation paths. The handler executes CLI before callback dispatch, but the complete callees' interrupt-enable effects still need review. The isolated C API models a noninterleaved invocation. It does not prove that every original main/interrupt invocation is atomic, or that presentation and simulation can be given independent byte-source state. P1-06/07 must preserve the shared state and admitted scheduling/consumption order.

[45,056 nested-call model cases](evidence/td2ega-byte-ring-nested-v1.json) pause the actual outer helper before each of its11 instruction boundaries, execute one actual nested helper with preserved outer registers, then resume. The loaded bytes and original native leaf remain unchanged. After the outer DEC and before its MOV SI at7813, both invocations select the inner cursor: cursor decreases twice, that byte transforms twice, and the outer index is skipped. All4,096 fixtures at that boundary differ from two serial native steps; other tested boundaries have serial-equivalent finalstate under this model. This is a concrete non-atomicity witness, not actualIRQ delivery or proof that the full callback guards admit that schedule. Core integration must either prove exclusion on supported paths or preserve the admitted interleaving; adding a lock or separate RNG state would require evidence.

[Callback metadata recovery](td2ega-timer-callbacks.md) proves unmasked addition and CLI/write/STI removal; the ISR itself executes STI before bookkeeping and CLI before each callback, while called audio helpers can executeSTI again. Caller-level masking and actual reentry remain open.

[160 actual caller-slice cases](evidence/td2ega-byte-ring-caller-if-v1.json) start4A34 andexecute7977 then780E. The sampler cursor/index/data operations execute withIF1 forbothincomingIFvalues, preservingDF. Thus callback-entryCLI doesnotprove samplerexclusion onthisslice. Earlierpathguards andfullIRQ/PIC delivery remainopen.

The [complete019E0004 caller](td2ega-ring-selection.md) now passed67584
comparisons/all60caller-leafsites. Its twoactualcallers includePUSHCS+nearCALL
at019E0B00/0B01 andfarCALL026714FD. Separate2048actualsource/nativeSS-save
alias cases proveSIcanchange throughits realPOP. Eightdirectsourceconsumption
sites stillshareone ring; writer/reset/seed/IRQreentry/lifetime/fullstate/core
obligations above remainopen.

The [complete4A2Ecaller](td2ega-sample-adjust.md) now passed28,984
comparisons/all117root-control-setter-ring sites. Actual7977STI yieldsIF1
at4A41; noIRQexclusion is inferred. ActualringPUSHSI canoverwritecursor
orselectedbyte andPOPSI canreturnchangedSI. LeafSIpreservation isdisjoint-stack
fixture scope. Conditionalindexedwriters alsooverlapthreeinitializednear
controltables; realvalidselector/sharedwriters/reset/lifetime/core remainopen.
