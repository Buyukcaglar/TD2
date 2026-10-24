# EGA function, data and indirect-control-flow map

2026-10-13, P1-04 with P1-05 discovery expansions. [Machine-readable map](evidence/td2ega-control-map-v115.json), [reviewed indirect mechanisms](evidence/td2ega-indirect-review-v8.json), and [static verification](evidence/td2ega-control-map-verification-v6.json) accompany the [stable function registry](functions.json).

The admitted image currently yields **440 registered candidates**, including the existing three IDs. Recursive discovery starts at startup, four instruction-proven installed handler entries and the explicitly reviewed XOR prologue06C9:BB08, follows direct branches/calls and explicitly reviewed indirect targets, and retains ordinary call fallthrough conservatively. All discovered entries have IDs, source-image locators, candidate ranges, call relationships and separate gates. Discovery does not admit their complete ABI or portable behavior. The original three records retain their reviewed ranges and prior C/differential evidence.

The initial-image traversal has 35,547 segmented instruction locations spanning 92,306 distinct image bytes, with no conflicting instruction boundaries or out-of-image targets in this traversal. Counts include conservative paths and shared tails. They are not runtime coverage or a percentage of recovered semantics. The remaining image has 4,190 unclassified prefix bytes and 33,744 principal initialized-data candidate bytes. Code/data/padding and embedded-resource ambiguity remains explicit.

Automatic Ghidra-only hypotheses are listed separately by disposition: an interior/shared-body instruction, an unreached automatic candidate, or a principal-data-group hypothesis. None is silently called unreachable or recovered. Comparisons use physical module offsets to locate bytes, while preserving observed segment:offset pairs for near-control semantics. A normalized Ghidra alias is not sufficient evidence for the correct original CS.

[Four state-specific ledgers](evidence/td2ega-mutable-control-map-v3.json) separately map initial, prepared high-drive, prepared low-drive and mixed-query states. Their instruction counts are35,547/35,547/35,543/35,547; unique codebyte counts92,306/92,304/92,294/92,304, with no conflicting boundaries perstate. These snapshots do not establish transition-aware whole-program coverage. [The mutator review](td2ega-mutable-platform.md) adds a saved-near return through CS002C/PUSH/RET0162 to the44 explicit sites, for45 reviewed mechanisms. Ownopcode edits change boundaries at00BC/0155/015E; do not merge incompatible decodes.

## Reviewed mechanisms

All **44 currently discovered indirect sites** have a reviewed mechanism or an explicit writer/bounds obligation. Sixteen have closed target sets under their stated preconditions; **28 retain open bounds, mutation or caller-context questions**. The latter keep full P1 closure open.

| Mechanism | Sites and evidence | Remaining obligation |
| --- | --- | --- |
| Saved far return | `13A8:0822`, IP/CS popped at `0694/0698`, resumes startup `0482` | Preserve argv stack allocation and far continuation; no game dispatch |
| Pushed-segment near call | `13A8:04BA`, explicit PUSH CS and word `6D28`; `06C9:6559`, PUSH relocated `06C9` segment before CALL BX | Setter/writer audit for latter callback array; retain far-return frame |
| Runtime initializer/finalizer array | `13A8:061B`; observed nonempty finalizer span `7082..7086` contains `13A8:0A3A` | Alias/writer audit; initial startup spans are empty |
| Registered far input callback | `06C9:69FE`; initial `06C9:6A03`, main registers `06C9:65C5` via `6A17` | Complete setter caller and lifetime audit |
| Timer far callback array | `06C9:6217`; admitted registrations include `0143:019E`, `06C9:6269`, `403B`, `75EA` | Bound terminator/slot ownership and callback lifetimes; preserve interrupt masking/nesting in P1-07 |
| Audio command tables | `06C9:7667` and `632F`, local signed/unsigned guards with CS tables | Command/state/source bounds in P1-10; raw format interpretation remains separate |
| Simulation dispatch | `44BA`, `491D`, `5514`, `55A1`, `57A7` | One bounded five-byte scan; remaining record/mode domains and aliases stay open for P1-05/08 |
| Resource dispatch | `06C9:6DE9`, two far entries in CS:`6E2E`; raw selectors 1/2 pass the local guards | Surrounding resource semantics and allocation ownership in P1-05/06; full codec interpretation in phase 2 |
| Bounded application tables | `0432:206A`, seven targets; `06C9:1432` and `2F90`, four distinct targets each from indices 1..20 | Semantic interpretation and data-field ownership in P1-05/08/09 |
| Main-state continuation | `06C9:1BA8`, positive byte at DS:`5490`, first ten table words at DS:`2302` | No local upper bound: all writers and accepted state domain must be established in P1-05; ten observed code offsets are a candidate set |
| Mutable near continuation | `06C9:0CFD`, discards near return, jumps through DS:`0702`; writers at `00EA` and `1F9C` | Ordering/alias review before treating two observed destinations as complete |
| Drawing near calls | `93EF/9E3E` select `8336` or `839C`; `9536/9F79` select `AD8B` or `ADF4` | Preserve near RET and register/local contracts in P1-09 |
| Drawing alignment tables | `9416/955C/9E5B/9F98` use CS table bases from shared prologues | Prove valid index, table immutability, shared-tail locals and caller resource bounds in P1-09 |
| Drawing local dispatch | `8E27/9061`, local pointers built from plane-mask decomposition and CS tables | Complete local-slot bounds in P1-09 |
| Runtime format tables | `13A8:1319/1AB3`, unsigned normalized format index 0..21 | Source semantics remain pending; target sets checked against 22-word tables |
| Signal dispatch and hooks | `13A8:2C5F`, six signal indexes; indirect pair calls at `2C83/2C93` | Registered handler lifetimes and DOS service behavior in P1-07 |
| Optional runtime hooks | `04F5/050B/05E9`, `0633`, `066A`, `1834/1E57/1E7C/1E95/1EB3` | Initial null/sentinel/error targets recorded; writer/alias audit required before nontranslated disposition in P1-11 |

The keyboard installer `06C9:6860` writes vector 09 to `06C9:6907` and vector 16 to `06C9:69B7`; `68C4` restores the saved pairs. The timer installer writes vector 08 to `06C9:61BF`; cleanup `610A` checks ownership before restoration. Startup installs vector 00 at `13A8:049B`, now registered as its own handler entry even though conservative startup traversal already found its bytes. Vector 16's AH=1 branch uses RETF 2 to return the computed key-availability flags; other handler branches use IRET. These conventions must remain explicit.

## Verification and completion boundary

Eight synthetic discovery tests cover conditional flow, backward cycles, segment-preserving far calls, unresolved indirect termination, resolved shared near bodies, far indirect call fallthrough, saved returns and out-of-image reporting. Static checks verify all candidate IDs/locators, all indirect mechanism records, ten guarded table target sets, four far-pointer relocation sites, the known main body (360 locations, 56 calls), and all eight PUSH CS + near CALL far frames. They also verify eight unique byte-source calls and that both address anomalies' constants are not relocated.

P1-04's **discovery/disposition map** accounts for the currently discovered entries and retains uncertainty as required. It does not close the target/writer obligations above, code semantics, portable C, or complete supported-path reachability. Those named obligations remain in P1-05/07/09/11 and prevent P1-GATE. A newly discovered entry or edge must expand this ledger and be registered before subsequent closure.

No CGA recovery, full DOS resource decode, native Windows host, DOS game session, renderer/audio output, gameplay or fidelity acceptance is established by this map.

FN-EGA-000440 registers BB08 without renumbering existing IDs. Its32-byte prologue establishes SS locals, mode18h/flags4 and a shared91F3 tail. Its two source-pointer words and shared far return are static observations; actual caller/reachability, XOR body and portable contract remain pending. It is not classified dead.

The [56ED review](td2ega-record-dispatch.md) adds a separate literal return
convention at585A/585B: POP AX followed by near RET consumes two SS words,
preservesCS and can bypass53A6. The map now records this under
`nonlocal_return_conventions`. It does not increase the44explicit indirect
site count or close57A7mode/targetwriter bounds; fullcaller integration is pending.
