# EGA file and header paragraph helpers

2026-10-13. `FN-EGA-000141` (`06C9:5E1C`) and `FN-EGA-000142`
(`06C9:5E8A`) have native service-driven contracts. [The build](evidence/td2ega-file-paragraphs-build-v1.json)
and [1,488 comparisons](evidence/td2ega-file-paragraphs-validation-v1.json)
cover two loads, opaque zero/FFFF handles, open/read/seek/close responses,
partial stack-header initialization, count boundaries and truncation. Seven
native-only service/argument diagnostics are separate. No real file executes.

Both take one near filename word at SS:BP+6, use caller DS for opening it and
return a paragraph word in AX on normal far return. BP, SI, DI, DS, ES and SS
are preserved on that return; arithmetic flags and other registers are
incidental outputs which the native APIs do not expose. Caller flag/register
uses still require review. The native service owns file access, and all native
context/result/seed storage is valid and disjoint.

The file helper opens, seeks to end with CX:DX=0, saves returned DX:AX, seeks
to start with CX:DX=0, then rounds the saved word pair to paragraphs and closes.
**Neither seek carry flag is checked.** The rewind's result and close carry/AX
are ignored. The accepted response profile therefore treats even an error
DX:AX as the saved quantity. Rounding is `(value >> 4) + (value & 15 != 0)`,
truncated to16bits; it must not be rewritten using a32bit overflowing
`value + 15`. The quantity can be32bits while its paragraph result wraps.

The header helper opens, requests four bytes into SS:BP-6, and compares the
returned AX with CX=4. **It does not check carry after reading.** AX4 with CF1
follows the successful-count branch and consumes whatever four stack bytes
exist, including old bytes untouched by that service. The native API requires
an explicit four-byte stack seed and retains partial writes. The cases with
CF1/AX4 are adversarial service profiles, not claims that a particular actual
DOS read produces those responses.

The header's first byte is ignored by this size helper. Bytes1..3 form a24bit
little-endian quantity; the same round/truncate expression supplies AX.
For example valuesFFFFF1h..FFFFFFh round to paragraph word0. This is a size
interface observation, not a full resource format or decoder admission.
Original DS=SS is required for the DOS read into those stack locals; the native
API uses an explicit four-byte destination instead of inferring host segments.

AX other than4 closes the opened handle before transferring through5E30 to
fatal reporting. Open error reaches the same fatal prefix without a close.
This differs from raw loader6AA2, whose read-error path does not close before
fatal reporting. Both metadata helpers use message offset5D7A and relocated
principal DS on that transfer. The tests fence before16A7:0002; complete fatal
cleanup remains separate.

Adapters preserve nonresponse registers, change AX/CF and seek DX as specified,
and initialize only explicitly written header bytes. Actual DOS responses,
resource-fed sizes, complete caller allocations/lifetimes, fatal behavior and
game/fidelity acceptance remain open. Fixing missing carry checks or replacing
unwritten bytes with zeros would alter the recovered contract.
