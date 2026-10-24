# EGA input roots with actual SS and explicit FLAGS frames

18 October2026. Three additional [C17 interfaces](../../src/recovered/td2ega_input_poll_bus.h)
cover65C5,6601 and6620 with current DS, inherited SS, raw FLAGS and validity.
They compose the frozen actual69B7 handler,6528 dispatcher and6686 sampler.
The earlier group interfaces, sources, DLLs and receipts remain frozen; these
three original entries are counted once. Result/Limits/Services sizes are64/16/40bytes.

The [build](evidence/td2ega-input-poll-bus-build-v1.json),
[41,612 comparisons](evidence/td2ega-input-poll-bus-validation-v3.json) and
[static review](evidence/td2ega-input-poll-bus-context-v1.json) cover all273
admitted sites and 3,005,590 original instructions at two loads.
The roots own74 sites;199 belong to actual callees. Six AH2/unhandled handler
sites are unreachable because these roots force AH0 orAH1; the separate full
handler unit covers them. Comparisons check the whole1MiB RAM bus, GPRs/BP,
CF/IF/DF, defined full FLAGS, control, ordered port requests and writes.
The [21 native checks](evidence/td2ega-input-poll-bus-native-diagnostics-v3.json)
are separate from original equivalence and helper vectors.

Each modeled INT16 writes FLAGS,CS,nextIP in that order, clears entry IF/TF
under the selected profile, executes actual69B7 and checks retired control/SP
before continuing. Those three frame writes are counted separately from source
CPU-memory-write hooks. This is a serialized interrupt profile, with no real
IVT ownership, BIOS delivery, IRQ or PIC acceptance. Handler AH1 uses RETF2
and ORAX/IF1; AH0 uses IRET and the actual saved FLAGS word after pending clear.

The incoming word is explicit: bit1 set, bits outside0ED7h zero, validityFFFFh
orFFEFh, with CF/IF/DF matching the register state. Logic/shift AF is undefined
and represented by an explicit0/1 analysis choice with its validity bit clear.
The choice is materialized when writing modeled FLAGS storage; the private
backend's CODE-hook flags are left untouched. Complete stored words can affect
aliased pending data and subsequent keys: the native shared-stack witness
returns AX2 versusAX12h for the two AF choices. Other defined bits still match.
This does not assign historical CPU semantics to undefined AF.

AH0 clear overlapping the low FLAGS byte makes AF known zero; overlapping only
the high byte retains its prior validity. After dispatch, ADDSP2 defines all
arithmetic flags from actual SP, including overflow boundaries. Incoming FLAGS
at65C7/6603 survive MOVAH1;65CD saves the prior AH1 OR flags;6614 saves the
SS/DS equality comparison. This closes the input-component FLAGS-storage gap
in the stated profile. Whole420A still needs signed-motion full FLAGS before
6601, plus actual caller/stack/writer ownership and exclusion.

Current key callbacks remain explicit ABI effects plus private generic RETF,
with their synthetic returns excluded from original-instruction counts. Their
actual bodies and UI callees remain open. Port responses are synthetic byte201
profiles. Source near/far frames, raw child returns, key argument cleanup,
input publication and repeat ordering remain literal. Native before-INT/CALL,
adapter and unqualified-return prefixes are separate from original errors.

The first probe exposed a harness defect: rewriting EFLAGS from a CODE hook
made JE take the wrong branch despite ZF1 readback. Exact failure bytes, maker
and diagnostic traces are retained; the untouched-backend probe passed. Full
attemptv2 matched40,284 cases but covered267 sites. V3 adds countdown-zero
calibration paths and full-FLAGS ADD/CMP boundaries, reaching all273. A native
intent assertion initially omitted the dispatcher's STI and expected IF0;
the exact failure is retained and the corrected IF1 assertion passes. Recovered
C/header/DLL bytes did not change through these harness/fixture refinements.

RS297 records36 initialized bytes6252..6275: guard6252, uninterpreted6253,
sixteen lookup words6254..6273 and repeat word6274. Its identity and literal
field footprint establish no capacity, all writers, units, lifetime or format.
Known guard/repeat/potential indexed and conditional SS frame writers are
recorded. The view lies outside the known DAT copy; payload stays external/private.

Three direct CALL sites are reviewed. The6601 return is followed by ORAX in
420A, but its incoming FLAGS follows signed motion without a prior flag kill.
Non-CALL/computed/tail domains remain separate. No unreachable claim follows
from the absence of a direct65C5 CALL in this ledger.

Whole420A/403B and P1-GATE remain open. No DOS game session, real devices,
renderer, audio output, complete state-machine validation, gameplay or fidelity
is established. Full resources, Windows gameplay and Amiga recovery have not
started. Physical086C remains unassigned. CGA stays behind EGA code-contract closure.
