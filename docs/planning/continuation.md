# Continuing the Test Drive II project

The planning packet is complete. The user subsequently authorized Phase 0 and Phase 1 development, TD2EGA first. Phase 0 is complete; Phase 1 has a validated EGA image, saved analysis project, startup findings and one independently tested C17 helper. Read the [current recovery checkpoint](../recovery/README.md) and [progress data](../recovery/progress.json) before continuing. Full EGA recovery, CGA comparison and all later phases remain unfinished.

## Read first

1. `README.md` and `docs/planning/roadmap.md`.
2. `docs/planning/backlog.json`, then the DOS executable, resource and architecture documents.
3. Validation, risks/decisions and tooling/source records.
4. The Amiga report and member inventory before later Amiga work. Refresh originals and external sources rather than treating this snapshot as permanently current.

Workspace: `C:\Projects\TestDrive2`. Originals: `reference\dos` and `reference\amiga`. Primary binary: `reference\dos\TD2EGA.EXE`. The initial workspace had no Git repository or AGENTS.md in the project or checked ancestors. Inspect live instructions and repository state on resumption; do not assume those facts remain unchanged.

## Preserved requirements

Follow this order: EGA disassembly/decompilation into portable C, then CGA graphics analysis; all DOS resource decoding; native Windows DOS-derived game using external original data; Amiga analysis/decompilation; then selectable Amiga graphics/animations/music/SFX alongside DOS EGA/CGA and DOS PC Speaker music/effects.

The user specifically named the extra Amiga scenery **Northern Germany Challenge** and requires it when the necessary files are supplied. Integrate its route/gameplay content, not just its pictures. The archive already has a fourth candidate scenery tree; verify that before requesting more files. Its identity must be established through loader/content evidence because `scen2` and `scen3` reuse `euro_` names and identical catalogs.

The supplied originals must remain unchanged. Native release packages must not contain original resources, including assets/text/fonts/maps/audio extracted from the original EXEs. Later executable runs and writes belong in private working copies and separate user-data locations. Do not use approximated or AI-created original media.

## Important discoveries

- Reference manifest: 250 files, 3,025,505 bytes. DOS: 249 files, 1,613,433 bytes. Amiga archive: 1,412,072 bytes, 352 installed-file members, 2,417,938 uncompressed bytes.
- EGA/CGA/Tandy are packed MZ programs with a common EXEPACK-family stub. Candidate inner relocation counts are 1,652 / 1,652 / 1,674; these are static consistency observations, not validated unpacked images. CGA has an unexplained 11-byte inner-tail remainder.
- `DUEL.EXE` is the launcher; its Hercules option invokes CGA with `herc`. No separate Hercules executable is missing on that evidence.
- 82 paired PCS/PES resources; two observed PCS prefix families. Twelve catalog cars; three DOS scenery families totaling 19 numbered DAT sections.
- `CAMA.BIN` has an exceptional size; only the first master-scenery SGN is present; exact duplicates exist but retain independent logical IDs.
- `VOICES.BIN` is only CR LF. Recover the actual DOS PC Speaker music/effect event and data paths from code; this file is not a substantive standalone sound bank.
- Amiga material is a supplied HD-patched tree, not proven original disks or a WHDLoad package. Hunk candidates include the main game, HD launcher and `sfx/song`; custom compressed resources need consumer-driven analysis.
- Newer WHDLoad third-party patch sources may help analysis but modify render/simulation behavior. External-source hashes and inspection/licensing limits are saved; no downloaded installer was retained.

## Safe next instruction for a later session

The current instruction already authorizes Phases 0 and 1. Refresh live instructions, Git state and original hashes, then continue the first unfinished EGA task. Do not repeat completed unpacking merely to recreate evidence: use the persisted verified image and recipes, with a fresh revision path if a new transform is necessary. Resolve range-specific DS/SS context and startup interfaces, then build the function/control-flow and resource-consumer map. Do not skip to CGA before EGA code closure, a native renderer or Amiga integration. Code-contract recovery precedes full resource-fed behavior validation.

If the user asks only for more planning, keep all implementation tasks pending, refine the documents and metadata, and do not launch games or produce code/builds/decoders. Save new decisions and a current handoff. Distinguish static evidence, compilation, runtime, presentation acceptance and fidelity in every status report.
