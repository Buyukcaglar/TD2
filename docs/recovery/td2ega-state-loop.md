# EGA session-state orchestration

2026-10-13. `06C9:1B2C`, `FN-EGA-000080`, has a
[C17 build](evidence/td2ega-state-loop-build-v1.json) and
[3,012 comparisons](evidence/td2ega-state-loop-validation-v1.json). This is
the root's instruction/control contract under explicit far-callee interfaces,
not complete state-machine validation. Most callees remain ABI mocks;120 cases
execute actual1E59/780E and their recovered C, consuming two synthetic samples.

The prelude calls1E59,1C8F,5D00, then1E31/5ADA and queues1352:DS through7946.
The loop calls its eleven update/presentation helpers and reads signed5490.
Zero repeats the loop. Nonzero clears336B; negative values enter exit work.
Positive values call7971, reload5490, sign-extend AL, double it and jump through
DS2302+BX. The state is not checked again after7971. Synthetic late-state
changes verify table0 and negative wrapped-index effects without admitting
those histories as actual game reachability.

The native interface follows the actual table word and admits the ten reviewed
target labels. It does not assume that an index uniquely determines a semantic
state, nor invent a fallback for an unknown target. [Four native diagnostics](evidence/td2ega-state-loop-native-diagnostics-v1.json)
keep invalid input, unknown target and budget exhaustion separate from original
return/error equivalence. All state/table writers and valid domains remain
P1-05/11 obligations.

Targets invoke3532/3643/36E0/371F/372B/3737/3743/3713 then decrement8424,
except target374F which enters exit work directly. The36E0 path first increments
8658 modulo65536. A zero decremented8424 enters reset; otherwise375F runs,
states4/9 exit, and other values restart at1E31. The fixtures cover zero/wrap,
continuation, wait and every reviewed target, retaining literal call order.
State labels such as collision, refueling or finish are not inferred here.

Reset calls5C98, pushes2288/2286 and calls80CA. Those two words remain on
the stack while2284/2282 are pushed forAA12. AA12 therefore sees its own two
arguments followed by the earlier pair. A single ADDSP8 cleans both calls.
The call-service interface exposes current and still-live argument words in
that order. All reviewed normal callee exits use plain RETF. Services preserve
SP/SS and argument words in this profile; actual graphical/resource bodies
and their data/frame exclusions require separate recovery.

Exit work subtracts3B51 from52CA and52D2 modulo65536, subtracts11 from380F,
performs the original unsigned clamps into5374/5376, then copies331E to942E.
It calls7971/1F60/0083/38D4/601C, sign-extends current5490 and restores saved
SI/DS/BP. The active code-state input then selects the verified tail:

- RETF at1BF7 returns the sign-extended current state, preserving returned ES/CF.
- Initial CLC tail clears CF, returns AX2/ES2 and writes word2 to physical0086.

The tail form comes from the reviewed mutable platform state; neither return
interpretation is unconditional. CF/IF/DF and modeled registers propagate
through explicit services. Incidental arithmetic flags at service entry are
outside this packet. Nonwrapping live frames make the caller cleanup carry
effects explicit. Changed DS/ES/BP/SI/DI and table targets are synthetic
interface probes, not admitted real callee behavior.

The combined root/preparation fence exercises155 of168 instruction locations;
the independent1E59 packet covers its complete deletion/fault paths. The real
caller composition here is a small terminated DS=SS profile. No supplied
resource, live IRQ, actual UI/drawing/audio body or DOS game session executes.
Physical086C keeps its distinct literal read address and unassigned meaning.
Complete state/resource/indirect-domain/callee/IRQ closure remains open, CGA
stays behind EGA portable code contracts, and no gameplay/fidelity is accepted.
