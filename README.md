# Test Drive II reconstruction

This project will recover a portable C game core from the supplied DOS executables, decode the original resources, build a native Windows game that reads user supplied originals, and then add Amiga graphics, animation, music, sound effects and Northern Germany Challenge scenery when its required files are supplied. The main reference is `reference/dos/TD2EGA.EXE`; `TD2CGA.EXE` supplies the CGA implementation evidence.

**Phase 0 is complete and Phase 1 is in progress with TD2EGA.** The EGA image, relocations and bounded startup ABI are reviewed. The current inventory has 440 function candidates, and 215 native C17 exports covering 292 original entries have passed isolated comparisons. State/resource ownership and complete portable code recovery remain open; the game core is not playable. Start with the [current recovery checkpoint](docs/recovery/README.md).

**22 October 2026 Kylofon selection:** [P1-R04 is complete as a source-selection decision](docs/recovery/kylofon-r04-reuse-decision.md). The [normative allowlist](docs/recovery/evidence/kylofon-reuse-decisions-v2.json) selects 10 groups: six value groups covering 11 already-recovered entries and four support groups, with [origins and license obligations](docs/recovery/evidence/kylofon-reuse-origin-manifest-v2.json) retained. The existing [P1-R02/R03 evidence](docs/recovery/kylofon-r02-r03-results.md) remains 2,233 admitted original-body vectors and 380 separate support checks; four SS aliases remain excluded. No source extraction/integration, new recovered entry or runtime/phase gate is earned. Originals and the reference clone remain unchanged. The [current effort estimate](docs/planning/kylofon-effort-review.md) is 203–461 engineer-days, about 41–93 engineer-weeks before reserve, with no substantial saving booked. P1-05 remains the recovery frontier.

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
