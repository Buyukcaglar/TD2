# EGA controller 4674 and its actual callees

18 October 2026. The [C17 build](evidence/td2ega-sim-controller-build-v1.json)
and [59,202 comparisons](evidence/td2ega-sim-controller-validation-v3.json)
cover 19,987,218 original instructions and all 687 sites at two loads.
Earlier runs matched 45,550 cases at 627 sites and 58,978 cases at 686 sites;
their coverage failures, exact validators and logs remain archived. The final
112 cases per load add byte-threshold and wrap boundaries: the earlier fixed
threshold 255 could never be met by the preceding even-valued byte shift.
The C source and DLL remained unchanged across all three runs.

The [interface](../../src/recovered/td2ega_sim_controller.h) implements the
whole 241-site near body at `06C9:4674` and composes 25 actual original bodies
through eleven compiled C source files. It retains current DS, independent
inherited SS, actual near/far CALL frames and raw return coordinates. The
[static review](evidence/td2ega-sim-controller-context-v2.json) pins the
687-site family, direct caller and arithmetic guard. Twelve
[native diagnostics](evidence/td2ega-sim-controller-native-diagnostics-v2.json)
check interface rejection and an iteration-budget prefix separately from the
original comparisons.

The full comparison includes 188 changed root returns, 60 raw callback
returns, 366 unknown-target prefixes, 32 interpolation divide-fault prefixes
and all 256 raw callback selectors. Four cases execute exactly 1,793 calls
in the rejection loop after two initializer calls. A separate
[row-cycle review](evidence/td2ega-sim-controller-row-cycle-review-v1.json)
rechecks two long fixtures and counts one actual `4742` SI wrap at each load,
with 8,193 row heads and SI eight at the budget prefix. The full comparison's
legacy field named `actual_8192_source_row_cycles` also counts fresh scans in
later controller iterations; its value 366 must **not** be read as 366 full
cycles. That frozen diagnostic field is qualified by this separate review;
the full RAM/register/control comparisons remain valid.

| Original CALL site | Actual target |
| --- | --- |
| `46B0`, `48A2` | `4AFA` window/state writer |
| `46F4`, `4713`, `475B` | Far `780E` byte-ring body |
| `488F` | Far `13A3:0012` signed table scalar |
| `48A5` | `4B5D` conditional guard and near sample call |
| `48A8` | `4B9A` threshold/interpolation controller |
| `48AB` | `4C85` indexed width/sample controller |
| `491D` | Current-DS near word target; thirteen recognized bodies |

Before the loop, the function conditionally moves wrapped word `52CC` toward
160 in steps of 20, then calls `4AFA`. It forms wrapped AX from `52C8` plus
three times byte `52CF`. Each loop head checks unsigned state byte `5490`
against two, stores AX into `52C8`, and returns when AH is zero. After a normal
callback, it reloads `52C8`, decrements **AH only**, and returns to that head.
Neither the whole loop nor the actual callers have a proven finite bound:
callback writes and SS aliases can change the counter or return frames.

The source path consumes the shared byte ring through literal far frames,
including the leaf's saved SI. It preserves the unsigned first-byte threshold,
the second byte's mask/subtraction/sign branches, raw flag masks and an
eight-byte row scan. A present generated coefficient lies in -7..-1 or 1..7.
The rejection loop accepts a masked byte below six and produces a token from
`0,5,10,15,20,25`; it then reads a presence word at `1DB4+4*token`. The absent
path stores FF in both destination byte arrays. These are numeric code
contracts; purpose, units and resource interpretation remain open.

The output index `(incremented byte533E+46h)&7Fh` bounds this producer's two
destinations to 128 bytes each. It does not bound other producers. The shared
ring, row scan and callback table retain explicit native budgets. Exhausting a
budget reports the current instruction prefix with prior writes retained.
It is not an original error path or a proof that the original loop terminates.

The word DIV at `47BF` has a sufficient preceding guard. The code doubles DX
modulo 65536, compares that result unsigned with CX, and only divides when the
doubled word is smaller. SHR then restores `DX&7FFFh`, which is also smaller
than CX. CX is consequently nonzero and the quotient fits a word for every AX.
The static review enumerates all 65,536 initial high words and checks the
maximum low-word numerator at the smallest admissible denominator. This
establishes the guarded arithmetic property, without qualifying exception
delivery or historical CPU timing.

Later arithmetic retains wrapped additions, signed comparisons, two separate
SAR memory writes, the actual signed scalar table call, signed word IMUL by
36, and literal word CBW. The window, sample and interpolation children use
their actual SS interfaces. A changed child return is executed and reported
before any continuation at the parent's expected return address.

The first stream byte is read through DS. The next selector at `4904` is read
through **SS:[BP+1]**. Both record indices are masked to seven bits, selecting
four-byte views at DS:347E. Byte three of the latter record supplies a separate
unmasked callback selector. Its near-word lookup therefore reaches
DS:33E6..35E4. The implementation captures that operand before writing the
near CALL frame and recognizes the thirteen reviewed bodies. An unknown
target stops before CALL, retaining the raw target for further review. The
initialized table's 48 words do not establish valid selector bounds or writers.

Two external byte-view identities are registered:

- RS289: DS:347E, 512 bytes, SHA-256
  `5f1168b5e5a106bf77a893be0e06df1cfdab49fe9a9553d03d46f90be1a8ce8f`.
  This footprint lies within the reviewed 7,774-byte DAT copy; its conditional
  known writer is FN-EGA-000030. The four-byte stride and selected byte uses
  do not decode the complete record format.
- RS290: DS:33E6, 96 bytes, SHA-256
  `6c1a8ca3265a38472f19c278612c4aff42fda9b78e914af27420b2792cd77bf4`.
  It contains 48 initialized near words and thirteen distinct targets, lies
  outside that DAT copy, and overlaps RS271 in its first ten bytes. The raw
  selector envelope extends beyond it into adjacent control/data views.

Neither view intersects a relocation. Their payload remains external/private;
the C implementation contains code-entry mappings rather than resource bytes.
Identity, initialized size and a code index are separate from runtime writable
capacity, valid selector sets, ownership and lifetime.

For the actual `491D -> 499A` edge, incoming BX is twice the raw callback
selector, from zero through 510. The leaf's logical halving therefore gives
zero through 255, bounding its live DS source to `37DD..38DC`. That entire
caller-derived source view lies within RS288 (`30E8..38E7`). This does not
narrow the standalone leaf's broader word-BX interface or remove its SS/DS
write-then-read aliases.

The sole discovered direct caller is `06C9:403B` at `4107`. That parent saves DS, ES,
DI and BP, sets DS/ES to the relocated principal group and inherits SS. Its
`410A` CMP kills returned arithmetic flags before use. The parent's earlier
CLD does not justify forcing DF zero across `420A`, whose explicit service
profiles can return a changed DF. Conditional nested `7977` executes STI;
neither the callback nor byte-ring consumption is proven atomic from this
packet. Whole `403B`, callback installation, writers, reset/interleaving,
storage and lifetime remain required before core integration.

SP is admitted from 24 through FFE0h so the composed interfaces receive their
required frames. Native statuses distinguish root RET (zero), raw child return
(one), invalid interface (two), a budget prefix (three), an interpolation
divide-fault prefix (four), and an unknown indirect target before CALL (six).
Root status zero can report changed root return coordinates. Only a completed
root exposes ZF as valid; CF/IF/DF and partial effects follow the admitted path.

Physical `086C` remains unassigned. CGA remains behind EGA portable contract
closure. No DOS game session, real device/IRQ behavior, renderer, audio output,
complete state-machine validation, gameplay or fidelity acceptance follows
from this packet.
