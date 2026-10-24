# EGA indexed projection and signed-byte lookup

2026-10-14.06C9:21C3 and13A3:0038 have two
[C17 exports](evidence/td2ega-projection-build-v1.json) and
[8,392 comparisons](evidence/td2ega-projection-validation-v1.json), covering
all261 instruction locations. There are1,024 normal projection returns,
eight actual signed-divide faults,192 bounded work prefixes and7,168 standalone
lookup comparisons. Four
[native-only domain checks](evidence/td2ega-projection-native-diagnostics-v1.json)
are separate. Fresh CPU instances follow divide faults.

The far lookup sign-extends AL, uses its absolute magnitude0..128 to select
a word from currentDS5560, and negates the wrapped word for negative AL.
BX/DX and other modeled registers survive; AX/CF are returned. The table's
contents and mathematical meaning stay external and unassigned.

The near21C3 body processes25 raw bytes backwards through2C26. A seven-bit
index selects two-word descriptor records347E..367D. Raw flags, accumulators,
three25-word input arrays and two signed-byte lookups per record feed its
indexed output and limit fields. The C preserves signed ADD/JGE overflow
behavior, unsigned multiplication, high-word negation, raw accumulator
clamping, conditional taper, TEST/JG and signed comparison order. No physical
units, geometry or decoded resource meaning is inferred from these operations.

A37A6 sentinel/list scan can select signed interpolation through IMUL and
IDIV. Zero divisors and out-of-range quotients retain the original23FA fault
prefix. Division truncates toward zero. Arithmetic condition flags after IDIV
are undefined, so fault CF is compared with the captured **pre-IDIV** value;
no post-IDIV arithmetic-flag behavior or exception handler is accepted.
This policy is corroborated by the
[official Intel IDIV reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf#page=544).
The [reference receipt](evidence/intel-idiv-reference-v1.json) records successful
web reading and a failed direct download; it claims no local PDF identity.

Normal completion leavesSI50/CF0, writes2B58=17, and uses plain near RET.
The lookup uses plain far RETF. Modeled GPR/BP/IF/DF and bus effects outside
eight bytes of live SS scratch agree. Work budgets stop before the next raw
record or list node and do not invent original returns or error behavior.

The [resource context](evidence/td2ega-projection-resource-context-v1.json)
registers a258-byte lookup span and150-byte input-array span without exporting
values. Conditional DAT links retain pending actual source mapping, schema,
list terminators and lifetime checks.21C3 is a reviewed writer of2C2A; the
remaining2477/2542 and actual1F71/088E caller bounds still need closure.
The DS/SS relation and whole state/resource ownership remain open.

No full resource decoding, renderer/audio output, real divide-handler/DOS
session, IRQ/device, complete state machine, Windows gameplay or fidelity is
accepted. CGA stays behind EGA portable code-contract closure.
