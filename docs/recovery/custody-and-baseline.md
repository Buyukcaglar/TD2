# Phase 0 custody and admitted baseline

Date: 13 October 2026. The user authorized Phase 0 and Phase 1 development, with TD2EGA first, all originals unchanged, and durable findings/progress. This supersedes the earlier planning-only restriction for these two phases. Later resource, Windows-host and Amiga integration phases have not started.

The canonical source edition ID is `DOS-EGA-SUPPLIED-EB4F8E88`: `reference/dos/TD2EGA.EXE`, 114,421 bytes, SHA256 `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182`. This identifies supplied bytes; a publisher revision or original-disk provenance is not established. CGA, Tandy and Amiga remain separate admitted reference identities, without new recovery work this checkpoint.

## Source custody

The existing [planning manifest](../planning/evidence/reference-manifest.json) was preserved rather than replaced. A new [session baseline](evidence/custody-baseline.json) verified all 250 paths, sizes and hashes and recorded modification timestamps/file attributes. Total content remains 3,025,505 bytes. Final checks compare both the old content manifest and the new metadata baseline.

`tools/verify_reference.py` opens originals read-only, rejects manifest paths escaping `reference`, reports missing/extra/changed files and refuses an audit output under `reference`. It never changes source attributes to enforce read-only access; doing that would itself alter original metadata.

All 249 DOS files were copied with metadata to `analysis/inputs/dos` and byte-verified. [Working-copy provenance](evidence/working-copy.json) records each source/destination/hash. Analysis transforms use these copies. Full game sessions will require fresh separate writable fixtures under `runs`, as described by the oracle specification; the input copy is not a runtime working directory.

## Version control and private artifacts

A new local Git repository was initialized on `main`; no remote or publication was configured. `.gitignore` excludes `reference`, `analysis`, runs, captures, caches, build/release directories and binary/database artifacts. `.gitattributes` preserves exact file bytes across checkouts, including line endings, so source/tool/evidence hashes do not change through host text conversion. Scope checks verify source and derived executables are ignored before any source-control snapshot.

Publicly reviewable project content consists of handwritten/recovered source, analysis tools, synthetic tests, schemas, hashes/locators and documentation. Unpacked images, complete instruction/decompiler exports, extracted payloads, third-party analysis binaries, original games and runtime captures remain local/private. A hash or path in a document does not license or publish the underlying media.

Existing Ghidra/JDK files from another project are reused read-only. TestDrive2 has its own analysis database and settings/cache/temp directories; no other project's game data, database or source is used. Python analysis dependencies are installed only under `analysis/tools`; no system-wide packages or environment settings were changed.

## Phase 0 documentation gate

| Task | Completed evidence |
| --- | --- |
| P0-01 | Immutable planning manifest retained; current file/hash/metadata baseline and canonical edition ID recorded |
| P0-02 | Local Git repository, exclusions, verified DOS working copies and private artifact/run policies |
| P0-03 | Tool hashes/versions and isolated paths; evidence conventions; five schemas with Draft 2020-12 validation and 59 synthetic cases |
| P0-04 | Pinned future DOSBox-X edition/config/fixture/repeatability specification |

The Phase 0 gate accepts custody/tool/evidence setup and the future-oracle specification. DOSBox-X has not been installed or run, fixture repeatability is unproven, and no gameplay, presentation or physical-timing acceptance follows from this gate. Initial provisional transformations were admitted only after the custody and independent-validation records were available.
