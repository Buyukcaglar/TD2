# EGA DOS search and near-path state

2026-10-13. Complete `06C9:5EF4/5F4E` (`FN-EGA-000143/000144`) have
two native exports and a [C17 build](evidence/td2ega-find-files-build-v1.json).
[262,882 comparisons](evidence/td2ega-find-files-validation-v1.json) execute
their original instructions with synthetic DOS services and full group views.
They are FindFirst/FindNext path helpers, rather than open/close existence
routines. Success returns near offset5D88; failure returns0.

Both select DS5DEE through AH1A, then issue AH4E or AH4F. They do not save or
restore the previous DTA address.5EF4 sets CL6 while preserving incoming CH.
On success it initializes basename pointer5DEC=5D88, copies up to87 bytes
from the near filename with16-bit source wrapping, and updates5DEC after each
colon or backslash. It then copies exactly13 bytes from5E0C into that location.
The100-byte buffer5D88..5DEB accommodates the maximum established basename
offset5DDF plus13 bytes. It does not add a terminator after the87-byte limit.

5F4E reuses the existing5DEC pointer without rebuilding the prefix. Its
13-byte forward copy reads the live group for each byte. Overlap with the
DTA filename can repeat overwritten bytes; a destination can wrap through
FFFF or overwrite the pointer itself. All65,536 replacement offsets are
compared. Native code preserves these effects without treating address0 as
host NULL or returning an unchecked host C string.

Success changes ES to DS, clears DF and returns CX0. Failure preserves ES/DF,
returns AX0 and retains any adapter-written DTA prefix. BP/SI/DI/DS/SS and
BX survive the admitted service profile. The first helper's failure retains
CH|6 in CX; the next helper retains its incoming CX. SetDTA carry is ignored;
the search call's carry controls the result. No case conversion or clearing
of bytes after the found-name NUL is introduced.

Fixtures include every near filename and replacement offset at two load bases,
source/destination aliases, partial failure writes, missing terminators,
separator and87-byte boundaries. Full group bytes, current-DTA/request order,
registers/ES/IF/DF, copy counts and far frames match. Initial5DEC is zero;
the discovered direct stores are5F0F and5F2B. Under an exclusive successful
FindFirst lifetime, replacement remains5D88..5DDF and cannot touch the byte
ring. Arbitrary/stale5DEC can target other fields.16B8:0000 can request
FindNext after FindFirst failure, so initialization and actual DOS search
state cannot simply be assumed. No reachable ring reset is established.

The pinned [Microsoft historical syscall reference](https://github.com/microsoft/MS-DOS/blob/2d04cacc5322951f187bb17e017c12920ac8ebe2/v2.0/source/SYSCALL.txt)
corroborates the API identities and13-byte found-name field. Its
[intake record](evidence/msdos-api-reference-v1.json) pins the private document;
no Microsoft implementation code was copied into recovered C. It identifies
an historical API, not the DOS version actually used by the game.

Actual filesystem/search results, DTA/basename ownership and interleaving,
caller attributes, resource schemas, IRQ and core integration remain open.
No full resource decode, DOS game session, renderer, audio, gameplay or
fidelity is accepted. EGA closure continues to gate CGA.
