# Runtime diagnostic and raw XOR guard

`FN-EGA-000264` (`13A8:0620`) executes the actual runtime-message helper
for FC, tests the current DS6DCE segment word, optionally far-calls
DS6DCC:6DCE, then executes the actual FF message. Offset zero remains
valid when the segment is nonzero. The root uses MOVSP from returned BP,
POPBP and plain RETF4. Its message children use RETF2 callee cleanup;
the caller's separately prepared argument is retained.

`FN-EGA-000266` (`13A8:066E`) saves SI, clears DF, XORs 66 current-DS
bytes into AH, and XORs AH with55. On the AH-zero branch, **AX retains the
final byte in AL**; it is not normalized to Boolean zero. On the other
branch it executes actual0620 and message1, then sets AX1. SI is restored
from actual SS before plain RETF. The shared caller at05B3 executes
ORAXAX and tests full AX, so a nonzero retained low byte matters.

The clean build-v1/comparison-v1 passed 27,136 cases and all 78 root/message
instruction sites, with 3,589,412 original instruction events. Full memory,
nested SS frames, GPR/BP/CF/IF/DF, service requests and control coordinates
are compared. There are 7,864 root far returns, 16,968 budget prefixes,
2,304 raw child returns, 6,800 synthetic DOS writes and 2,880 callbacks.
Synthetic callback RETF instructions are counted separately. All 256 final
bytes are tested on the AH-zero branch in 4,096 fixtures. Another 11,520
fixtures use the minimum admitted root SP48. Eighteen native rejection,
minimum-stack, budget and adapter checks are separate.

Four unique caller sites account for eleven graph-owner records. The
current-DS checksum-source ownership, its writers and intended guard role
remain open; no game-integrity or timer semantics are inferred. Callback
body/targets/writers and the0633 indirect domain remain open. The catalog
end marker, key/NUL/capacity/DF/other-FLAGS requirements and caller lifetime
still need closure. The05B3 OR overwrites the checksum's arithmetic FLAGS
before that caller's branch, but does not remove the raw AX dependency.

Synthetic DOS/callback services omit real interrupt frames and delivery.
No actual DOS session, device, renderer, audio, complete state-machine,
gameplay or fidelity gate is established. CGA remains behind EGA portable
code-contract closure; full resource decoding remains pending.
