# EGA session-initialization contracts

2026-10-13. Four complete original entries have four native C exports, with
[2,080 comparisons](evidence/td2ega-session-init-validation-v1.json) against
their actual instructions and [one composed C17 build](evidence/td2ega-session-init-build-v1.json).
The build links the reviewed simulation, timer-control and callback helpers.
Four native argument/profile diagnostics are separate. These are serialized
synthetic-data/port/vector tests, not a game session or full state-machine test.

| Entry / ID | Bounded effect |
| --- | --- |
| `06C9:3FF9` / `FN-EGA-000125` | Clear named simulation fields, set33CA=FAh, then invoke the reviewed transition clear5427 |
| `06C9:38F2` / `FN-EGA-000111` | Reset2F46..2F5C fields and copy external words23C6/23C8 into2F4C/2F4E |
| `06C9:1E31` / `FN-EGA-000082` | Invoke3FF9, set52CC=A0h, clear5490, set5FD8/5FDA/5FDC=FFFF and invoke38F2 |
| `06C9:3F40` / `FN-EGA-000124` | Reset sample/state fields, fold71 selected record bytes, relocate3811, invoke601C and register6269/403B |

3F40 clears eight signed-sample bytes335D..3364 and the exact fields listed in
the source. It conditionally clears33AF only when90A8 is nonzero, copies843E
to3379 and initializes337A=20h. It does not introduce inferred physical units
or semantic defaults beyond those stores.

The71-byte source at3B51..3B97 selects first bytes from four-byte records at
347E. The original shift/clear/shift sequence masks each selector to7bits;
native code expresses the equivalent `(selector & 7Fh)*4`. Thus this particular
record read stays inside the512-byte table347E..367D for every byte selector.
The fold is stored at33BD. These ranges lie within the already reviewed7774-byte
DAT copy346A..52C7; this is a downstream data-consumer contract, not decoding
or acceptance of any supplied DAT file.3811 is incremented by3B33h modulo65536
on every invocation. Replacing that addition with an idempotent assignment
would change repeated initialization.

The composed C implementation imports group timer/callback metadata into the
typed device view, calls the recovered fixed installation entry601C, adds6269
and403B, and exports the resulting metadata. Whole64KiB group bytes, physical
vector words and ordered port/IF effects match in the tests. The source view,
device and result are disjoint; currentCS is nonzero. This is a serialized
snapshot contract. It does not assert that a bulk native field publication
preserves every asynchronous original interleaving.

All four use far RET and leave the caller's group/stack/base intact.3F40 executes
CLD and ends withIF1 through its helper calls. The other three preserve incoming
DF/IF. Their incidental scratch registers still require caller review before
integration; the C APIs expose state and explicit device effects.

The258-byte cursor/table range66E6..67E7 stays unchanged in every test, including
zero/FF and varied synthetic groups. These four initialization paths therefore
provide no per-session byte-ring reset. This does not exclude other indexed or
aliased writers, establish original seed policy or accept the complete shared
source schedule. Source/code contracts, complete caller lifetimes, actual
platform/IRQ behavior, resource schemas, gameplay and fidelity remain separate.
