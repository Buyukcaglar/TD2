# EGA packed-loader composition

2026-10-13. Complete `06C9:6D50` (`FN-EGA-000173`) now has a native C
composition and [C17 build](evidence/td2ega-packed-load-build-v1.json).
[2,424 comparisons](evidence/td2ega-packed-load-validation-v1.json) execute
the original wrapper and actual cache, allocation, paragraph, raw-read,
run/block, prefix and copy callees against the native composition. Only DOS
service responses and file bytes are synthetic. The earlier48 composition
cases with mocked metadata helpers remain separate evidence.

Cache acquisition returns early only for a nonzero segment. Otherwise the
wrapper reads the four-byte header for a rounded paragraph count, adds one
paragraph modulo65536, allocates a descriptor, measures the file and reads it
into the tail of that allocation. The native view exposes partial metadata,
payload and failure stage. It adds no cleanup or rollback.

After6AA2, the original removes eight bytes despite pushing three words.
The final `MOV SP,BP` restores the outer return frame, but its preceding pops
are shifted: DI receives incoming SI, and SI receives the original BP-0A word.
That word is either its supplied uninitialized seed or the last intermediate
copy segment. The native result exposes these observations explicitly. The
cache-hit path preserves incoming SI/DI. This behavior is not repaired.

An outer high-bit header supplies a seven-bit pass counter and advances the
source offset by four. Count zero still executes one dispatch before the
signed decrement test exits. The dispatcher admits selector1 for6B02 and2
for7C16; other selectors reach fatal message6503. The tests cover both direct
invalid selectors and an invalid selector produced by a successful first pass.

7C16 returns an intermediate24-bit byte count. If another pass remains, the
wrapper rounds DX:AX to a16-bit paragraph count, copies that many paragraphs
backward from the allocation start to its tail and dispatches again.6B02
returns a far pointer. The final return preserves the last codec's DX:AX;
it is not universally a pointer when an outer counter stops after7C16.
The previously reviewed7C16 low-word-zero extra65,536-byte write remains a
caller allocation obligation; these wrapper fixtures do not accept it as safe.

The tests include two load bases, synthetic literal/run streams, one/two pass
chains, two stack fills, cache hits/misses/holes, descriptor exhaustion,
metadata/raw failures, partial writes, ignored metadata carry, invalid codecs
and outer counts0/1. Full pool bytes, descriptor metadata, boundary words,
service order, fatal message, normal return frame and shifted SI/DI match.

The admitted profile requires DS=SS for stack-header and codec scratch, valid
component tables and exclusive bounded nonwrapping pools. Incidental scratch
memory/register/flag consumers, all actual caller lifetimes, asynchronous IRQ
exclusion and supplied-file bounds remain open. No actual resource decoding,
DOS game session, renderer, audio, gameplay or fidelity is accepted. Full EGA
portable code-contract closure still precedes CGA.
