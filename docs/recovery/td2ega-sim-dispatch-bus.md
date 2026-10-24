# EGA indirect target interfaces with separate DS and SS

2026-10-16. The [C17 interface](../../src/recovered/td2ega_sim_dispatch_bus.h)
adds an explicit memory-bus view of eleven bodies already recovered through
the simulation-primitives and small-state interfaces. It admits independent
DS and SS, reads the actual near-return word, and exposes defined CF and ZF.
The earlier source files, compiled libraries and their narrower contracts are
unchanged. These are additional interfaces to existing original entries.

The [build](evidence/td2ega-sim-dispatch-bus-build-v1.json),
[36,356 original-instruction comparisons](evidence/td2ega-sim-dispatch-bus-validation-v1.json)
and [static context review](evidence/td2ega-sim-dispatch-bus-context-v1.json)
cover all 64 instruction sites. Ten
[native invalid-input checks](evidence/td2ega-sim-dispatch-bus-native-diagnostics-v1.json)
are recorded separately. The comparisons check the entire 1 MiB memory bus,
GPRs, BP, CF/ZF/IF/DF, write counts and actual return coordinates at two code
loads. They include 44 changed return words and 704 near SP wraps.

| Native selector | Original entry | Effect |
| --- | --- | --- |
| 0 | `06C9:4929` | Stage byte and conditional ordered snapshots |
| 1 | `06C9:4947` | Stage byte; preserves incoming CF/ZF |
| 2 | `06C9:494D` | Conditional wrapped BP+50h pointer publication |
| 3 | `06C9:495D` | Conditional BP+3Ch publication; reads target after state writes |
| 4 | `06C9:499A` | Indexed SS byte writes with an intervening live DS source read |
| 5–7 | `06C9:49C9/49CF/49D5` | XOR one at three separate byte fields |
| 8–9 | `06C9:49DB/49E1` | Wrapped byte threshold addition/subtraction |
| 10 | `06C9:4A18` | Plain near RET; preserves incoming CF/ZF |

At `499A`, incoming BX is halved logically. The resulting half selects
`DS:37DD+half`; the wrapped expression `(half-16h)*5` supplies the first output
byte. The output index is `(DS:533E+45h)&7Fh`. Both indexed destinations use BP
and therefore default to **SS**, at `368A+index` and `370A+index`. The first SS
write precedes the DS source read. Different segment values can still make
those physical byte addresses coincide. The comparison includes 3,072 such
alignment fixtures, including 1,024 observable write-then-read discriminators.
CF and ZF belong to the final word ADD before the MOVs; replacing AL with the
source byte does not recompute those flags.

Every body performs a plain near RET and consumes the current SS word. Its
state writes can change that word. Native status zero reports the original
return operation and actual coordinates; the parent must check its expected
return address before continuing. The API accepts SP from zero through FFFEh;
FFFFh is outside this interface. Input ZF is explicit because `4947` and `4A18`
leave arithmetic flags unchanged. Other incidental flags are unadmitted.

The caller at `491D` remains an open indirect domain. Its record selector comes
from **SS:[BP+1]**, then is masked to 7 bits and selects a four-byte DS record.
Byte three of that record is a separate, unmasked callback selector. Its word
table access can therefore range from DS:33E6 through DS:35E4. The initialized
48-word table and thirteen recognized target bodies do not prove the valid
selector set or all writers. A future caller bridge must capture the target
operand before creating its actual near CALL frame. After a normal return,
`4921` loads AX, `4924` decrements AH and execution reaches `46CA`, whose CMP
kills returned CF/ZF before the branch. Other returned registers and memory
remain significant to the whole controller.

The context review separately checks a conditional termination lemma for
`475B..4764`. The byte-ring transformation is
`T(b)=((b<<1)|(b<128))&255`. Exhaustive enumeration of 256 initial bytes shows
at most seven consecutive outputs with `(T(b)&7)>=6`; eight transformations
complement the input and sixteen restore it. With 256 slots visited in order,
the first accepted output occurs by `7*256+1 = 1793` calls. An initial ring
filled with byte three attains that bound. This is a mathematical finite-state
check, separate from execution of the complete original caller.

That bound requires stable current DS, no intervening ring/cursor writer,
reset or reentry, and call frames and saved SI disjoint from the ring and
cursor. It does not establish those conditions in the actual interrupt
context, identify a random-number purpose, or close the whole controller.

No new embedded resource identity is introduced. The curve output views are
conditional writers of RS284/RS285 only when SS identifies their principal
group storage; direct DS stage/snapshot/threshold writes intersect RS271.
Capacity, producer, ownership, lifetime, callback target writers and interrupt
exclusion remain open. Whole `4674`, whole `403B` and P1-GATE remain pending.
Physical `086C` remains unassigned. CGA stays behind EGA contract closure.
There is no DOS game-session, device, renderer, audio, complete state-machine,
gameplay or fidelity acceptance from this packet.
