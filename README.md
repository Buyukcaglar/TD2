# Test Drive II reconstruction

This project will recover a portable C game core from the supplied DOS executables, decode the original resources, build a native Windows game that reads user supplied originals, and then add Amiga graphics, animation, music, sound effects and Northern Germany Challenge scenery when its required files are supplied. The main reference is `reference/dos/TD2EGA.EXE`; `TD2CGA.EXE` supplies the CGA implementation evidence.

**Phase 0 is complete and Phase 1 has started with TD2EGA.** The EGA load image and relocations are independently validated, startup analysis is underway, and one small C17 helper has passed isolated differential tests. The game core is not complete or playable. Start with the [current recovery checkpoint](docs/recovery/README.md).

Audio scope is DOS PC Speaker music/effects and Amiga music/sound effects, with live provider selection in the final phase.

The [development roadmap](docs/planning/roadmap.md) preserves the required order. Supporting planning documents are:

- [Resource findings and decoding plan](docs/planning/resources.md)
- [DOS executable evidence](docs/planning/dos-executables.md)
- [Amiga evidence and recovery plan](docs/planning/amiga-evidence-and-plan.md)
- [Proposed native architecture](docs/planning/architecture.md)
- [Acceptance and validation plan](docs/planning/validation.md)
- [Risks, decisions and effort](docs/planning/risks-and-estimates.md)
- [Tooling and primary sources](docs/planning/tooling-and-sources.md)
- [Ordered task backlog](docs/planning/backlog.json)
- [Continuation instructions](docs/planning/continuation.md)

Machine readable evidence includes the [reference manifest](docs/planning/evidence/reference-manifest.json), [DOS resource observations](docs/planning/evidence/resource-observations.json), [Amiga member inventory](docs/planning/evidence/amiga-member-inventory.json) and [external patch source examination](docs/planning/evidence/whdload-source-examination.json). The [inspection log](docs/planning/evidence/inspection-log.md) records methods and limits, and the [planning audit](docs/planning/evidence/planning-audit.json) records consistency and original-file checks. These contain metadata and observations, not retained game payloads.

The original material under `reference` must stay unchanged. Future executable runs, unpacking and writable game files belong in separate working directories. A distributable must contain the reconstructed program and permitted dependencies; game artwork, fonts, audio, maps and other original media must be loaded from the user's files.
