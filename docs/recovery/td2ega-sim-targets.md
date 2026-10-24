# EGA target and sample arithmetic

2026-10-13. Complete near entries `06C9:412C`, `4441` and `4588`
(`FN-EGA-000366/000370/000375`) have three native exports and a
[C17 build](evidence/td2ega-sim-targets-build-v1.json).
[419,868 comparisons](evidence/td2ega-sim-targets-validation-v1.json) cover
their original state effects, AX/BX/CX/DX, near frames, preserved registers
and IF/DF using synthetic shared data groups. Tables remain external bytes.

412C increments byte336A and masks its table selector to five bits. Its first
word read stays within32AE..32ED and is stored at5FDE. It moves332A toward
332C by a wrapped60h step using signed comparisons, stores332A, then indexes
another word using `(332A >> 5) & FFFEh`. That read stays within30E8..38E7.
It can alias state just written: index242h reads the updated word332A.
The native implementation retains the shared view and publication order.
It does not split these candidate tables into immutable arrays.

The remaining branches select literal5FDA values or update named countdown
and oscillator fields. The33B2 countdown can be overridden by336F;33BC takes
an earlier override. A3374/942E-controlled path moves3350 by two modulo65536
and changes direction335C at signed thresholds05DC/0708. Other3374 paths
select05DC or07D0 using3346 bit2. Numeric constants have no inferred physical
units. Incidental AX low-byte changes retain its original high byte.

4441 first chooses a branch by signed CX/DX comparison, then applies unsigned
thresholds to wrapped magnitudes. One branch can set33B2=3 and subtract five
from52CF. The other clamps an8-bit difference to zero on borrow, multiplies
it by3329 and, if the unsigned product reaches1B58h, stores the high byte of
the earlier magnitude in33B2. That stored byte is not the product high byte.
Conditional BX/DX changes and unchanged paths match the original.

4588 subtractsC8h from332C and applies a signed0320h minimum, or adds0258h
according to2F56 and the signed336C byte. It retains wrapped subtraction
before the signed comparison and sets2F5B only on the original paths.
All65,536 target values are compared across three branch profiles at two
load bases. No nominal speed range or units are assumed.

Other fixtures cover signed smoothing boundaries, all256 counter bytes,
all second-index inputs, countdown and oscillator wrapping, byte borrow and
product thresholds, and varied groups. Full64KiB output comparisons preserve
every indexed alias. Actual table contents/ownership, caller flag consumers,
asynchronous publication and the complete simulation/state machine remain
open. No renderer, audio output, DOS game session, gameplay or fidelity is
accepted. EGA code-contract closure still gates CGA.
