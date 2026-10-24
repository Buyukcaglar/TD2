# Runtime message lookup and output

`FN-EGA-000269` (`13A8:088C`) takes one SS word, captures current DS in
ES and walks from near82C4 with LODSW and REPNE SCASB. It retains incoming
DF. A matching ID returns the raw post-LODS offset; otherwise INCFFFF
detects the end case and returns zero. Match testing precedes that end
test, including when the requested word is FFFF. Actual SI/DI/BP saves
are restored; literal RETF2 consumes the far frame and one argument word.

`FN-EGA-000270` (`13A8:08B7`) copies its argument and executes that actual
lookup through a materialized far frame. A nonzero result is scanned through
ES without CLD. NOTCX/DECCX computes a raw length, then INT21/AH40 writes
through BX2. Returned service DS/BP/IF/DF remain explicit; saved DI is popped
before MOVSP from returned BP and the root RETF2. There is no extra caller
cleanup and no host string API substitution.

The clean C17 build-v1/comparison-v1 passed 24,032 cases and all 47 sites,
with 3,101,888 original instruction events and full memory including nested
SS frames, GPR/BP/CF/IF/DF, requests and control coordinates. There are
6,136 RETF2 root returns, 17,896 diagnostic prefixes, 832 synthetic DOS
services, 272 altered root coordinates and 12,016 reverse-DF fixtures.
Sixteen full no-NUL scans produce raw length FFFE with CF1 in a write
request. Fifteen native interface/minimum-SP/adapter/budget checks are separate.

The initialized image proves an eight-row prefix at DS82C4..83B2 (239 bytes).
Only ID words, row offsets, lengths and a span hash are recorded; original
message text remains private/external. **A terminating catalog marker has
not been established.** Following bytes include adjacent runtime fields;
unknown-key scans cannot be assumed safe or bounded by that prefix.

Thirteen graph-owner records represent seven unique call sites: six to
output and one nested lookup. Prepared keys0/FC/FF/1/A and one handler path3
occur in the initialized prefix. Other fatal-path prepared AX values and
argument survival across callbacks/callees need caller/writer review.
Actual key domains, NUL/capacity/DF/other-FLAGS requirements, table writers,
lifetime and core integration remain open.

Synthetic DOS boundaries omit real interrupt frames and device/file effects.
No DOS session, renderer, audio, complete state-machine, gameplay or fidelity
gate is established. Full resource decoding remains pending; CGA remains
behind EGA portable code-contract closure.
