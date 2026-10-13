# Test Drive II recovery progress

Checkpoint: 13 October 2026. **Phase 0 is complete. Phase 1 is in progress, with TD2EGA first.** This is development progress, superseding the earlier planning-only status for those two phases.

## Completed at this checkpoint

- Original custody verified for all 250 files; metadata baseline and 249 verified DOS working copies persisted.
- Local source control initialized with originals, binary payloads, analysis databases, tools/downloads and captures excluded.
- Toolchain, address/evidence conventions, five validated schemas and a pinned future execution-oracle specification established.
- TD2EGA recovered as a 130,240-byte load image; 1,652 relocations and original entry/stack validated by independent methods, including the original loader at two load segments.
- Ghidra real-mode project saved; all imported image bytes and relocations independently checked. Automatic function/decompiler outputs remain hypotheses.
- Startup/main candidates and the principal data/stack group mapped statically.
- One 29-byte helper recovered into C17, compiled and passed 131,584 isolated instruction-to-C vectors. Its higher-level purpose and integration remain unknown.

## Read and reproduce

| Document | Purpose |
| --- | --- |
| [Custody and baseline](custody-and-baseline.md) | Original identity, working-copy policy and Phase 0 gate |
| [Toolchain](toolchain.md) | Pinned versions/hashes and isolated commands |
| [Evidence conventions](evidence-conventions.md) | IDs, coordinates, confidence and separate gates |
| [Future execution oracle](oracle-spec.md) | Pinned DOSBox-X profile/fixtures; not installed or exercised |
| [EGA unpacking](td2ega-unpacking.md) | Transform, allocation, image and relocation proof |
| [Independent loader check](independent-unpack.md) | Original-stub execution stopping before application entry |
| [Startup analysis](td2ega-startup.md) | Entry, DS/SS, runtime scaffolding, main candidate and open anomalies |
| [First C helper](td2ega-byte-ring.md) | Exact contract, build, comparisons and limits |
| [Function registry](functions.json) | Three reviewed/discovered records; not a complete routine inventory |
| [Progress data](progress.json) | Task status, evidence, next work and remaining gates |

The [development roadmap](../planning/roadmap.md) and [backlog](../planning/backlog.json) retain the required phase order. Original media remains external. DOS audio is PC Speaker music/effects; Amiga audio and Northern Germany Challenge remain later requirements.

## Next work

Continue `P1-03`: reconcile range-specific DS/SS analysis context, review startup helper interfaces and preserve known near/far pointer and far-return conventions. Then build a reviewed function/indirect-control-flow and resource-consumer map under `P1-04` and `P1-05`. Investigate the exact external-memory read address anomaly before assigning timer semantics. Establish caller context for `FN-EGA-000003` before core integration.

CGA recovery remains behind EGA portable code-contract closure. Full resource decoding, Windows-host gameplay and Amiga recovery have not started. No DOS game session, renderer, audio output, complete state-machine validation or gameplay/fidelity acceptance is established by this checkpoint. Isolated loader and function emulation are recorded separately from those gates.
