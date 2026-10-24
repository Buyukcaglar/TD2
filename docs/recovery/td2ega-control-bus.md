# Control helpers with literal SS frames

The additional `td2ega_control_bus` interface covers near entries `4588`,
`44D8`, `45BF`, `4612` and `45FC`. Earlier group APIs and their frozen
receipts retain their original scope: four arithmetic registers and data
separated from stack/result writes. The new bus bodies reexpress the
source instructions with actual SS, GPR/BP/CF/IF/DF and return coordinates.

`4588` retains the signed byte336C condition, subtract200/clamp800 path,
AX-versus-DX comparison, or add600 path. `44D8` sets DX1600 and jumps to
`45FC`. That body saturates subtraction at zero, stores52CE when changed,
then makes the actual near call to `4612`, pushing4611 in SS. `45BF` keeps
incoming DX on its FF shortcut; its initial AX1600 is overwritten. Its other
path uses the high AX byte divided by four to index the DS:324A byte table,
then retains the word arithmetic, sign and borrow branches.

`4612` tests byte2F56, conditionally loads332C, writes2F5B, loads3328 and
52CE, multiplies unsigned, clamps the high product at800, stores332C and
returns through actual SS. Its own near frame can change the guard or field
reads, and the store can overwrite its return word. No SS scratch region
is excluded. Minimum SP18 supports the nested near frame; the native budget
stops before460E after the preceding52CE write.

The C17 `/W4 /WX` build passed 34,720 comparisons, 489,376 original
instructions and all 68 sites. Full memory/SS/GPR/BP/CF/IF/DF, control and
counts match. Coverage includes 7,504 actual4612 calls, 5,120 minimum-SP18
cases, 420 altered child returns and 1,316 altered root returns. Raw targets
are exposed after actual RET and never followed. Seventeen native interface
diagnostics are separate. This adds an interface and evidence, with no new
original entry or function-completion count.

`RS-DOS-000267` identifies the external initialized DS:324A..3289 span.
XOR BH, MOV BL,AH and two SHR operations give index0..63 for every AH byte.
MOV CH,BH makes the table byte a word0..255; optional doubling yields0..510.
Eight pinned operand sites support this bound. No original table payload is
embedded in C, and no values, physical units, immutable-writer policy or full
resource format is inferred.

Selected caller windows establish local arithmetic-status liveness: `5A6F`
compares33D4 after its two calls; `44EA` compares336C after4588. The `44EA`
entry comparison replaces the status flags returned by5880, and403B later
uses SUB before its conditional branch. IF/DF, complete callers, all writers,
DS/SS binding, table bounds in other views, ownership, lifetime and interrupt
exclusion remain open before core integration. No DOS session, renderer,
audio output, complete state-machine, gameplay or fidelity is established.
CGA and later resource/Windows/Amiga gates retain their existing order.
