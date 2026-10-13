# Recovery evidence conventions

Established 2026-10-13 for Phase 0 and Phase 1. This convention governs new recovery records; the planning packet remains the dated record of the earlier planning session. The current instruction authorizes recovery work, preserves every original file, and keeps EGA ahead of CGA. DOS audio scope is PC Speaker music and effects. The full DOS resource implementation, native Windows host and Amiga recovery remain later phases.

## Identity and custody

Use workspace-relative paths with `/` in machine-readable records. Record complete-file SHA-256 in lowercase hexadecimal. A path, size or file name alone cannot admit an edition. The primary supplied binary is `reference/dos/TD2EGA.EXE`, 114421 bytes, SHA-256 `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182`; later custody verification must confirm this identity before reuse.

`reference/` is immutable input. Transformations, disassembly databases, memory dumps, writable game copies, captures and decoded media belong only to excluded private directories approved by the workspace custody policy. Hashes, locators, synthetic tests, human-written descriptions and recovery source can be versioned. A publication review still must detect original media or executable-resident text/tables accidentally copied into source.

An artifact record must identify the input hash, tool ID/version/binary or source hash, exact options/configuration hash, output hash, transformation kind, synthesized/removed ranges and validation result. Every downstream locator follows that chain back to an admitted supplied file. A rebuilt MZ envelope, unpacked load module and relocated runtime image are different artifacts, even when they represent the same instructions.

## Stable IDs

| Record | ID form | Identity rule |
| --- | --- | --- |
| Function | `FN-EGA-000001`, later `FN-CGA-000001` | Assign once after discovery. Keep the ID when its name/address/boundary changes. |
| Resource | `RS-DOS-000001`, later `RS-AMIGA-000001` | A logical file/member/embedded item. Equal hashes do not merge distinct paths or roles. |
| Trace fixture | `TR-DOS-EGA-000001` | Immutable measurement recipe. A changed start state/input schedule/measurement contract needs a new revision. |
| Difference | `DF-000001` | One bounded disagreement with two named subjects and a reproducible comparison. |
| Decision | `DC-000001` | A choice with rationale, alternatives, consequences and a review trigger. |

Use an opaque edition ID, for example `DOS-EGA-SUPPLIED-EB4F8E88`, in every record. It identifies the admitted bytes rather than claiming a publisher revision or retail-disk provenance. Evidence links can reference planning records, transformation records or other recovery IDs. On a split/merge, retire the superseded ID with `superseded_by` and an explanation; never silently reuse it for another routine. Tentative function names are aliases, not IDs. Cross-edition function matching is a relationship with evidence and confidence, never an address-based renaming.

## Address coordinates

| Coordinate | Required interpretation |
| --- | --- |
| `packed_file` | Byte offset in the exact supplied packed file. Includes its MZ header. |
| `rebuilt_mz` | Byte offset in a particular derived MZ envelope; its header may differ from the original. |
| `unpacked_module` | Zero-based byte offset in the unrelocated unpacked load module, excluding any MZ header. |
| `tool_segmented` | Analysis-tool address with image hash, language/compiler profile, analysis-base/load map and import/relocation policy. |
| `runtime_segmented` | Actual segment:offset at a named measured checkpoint, with load segment, relocation state, timepoint and machine address policy. |
| `resource_file` | Byte offset in an admitted resource file/archive member. Archive member identity includes container hash and member path. |
| `source` | Workspace source path and one-based line, preferably tied to a Git revision/source hash. |
| `document` | Workspace report/primary-source path or URL plus heading/line/section locator. |

All byte ranges are half-open `[offset, offset + length)`. Offsets and lengths are integers in JSON, displayed in hexadecimal in prose when useful. A single instruction locator gives its start and decoded byte length. A function may have multiple noncontiguous ranges, shared tails or several entries; do not force it into one contiguous interval. Record segment and offset as separate 16-bit integers, preserving the observed pair.

For an MZ header of `h` paragraphs, an unrelocated load-module address `(s,o)` maps to module offset `16*s + o` and, only in that particular uncompressed MZ envelope, file offset `16*h + 16*s + o`. For a runtime load segment `L`, the usual relocated segment is `(L+s) mod 65536`; physical address formation also depends on the machine's A20/wrapping policy. State that policy rather than assuming it. Different segment:offset pairs can alias one physical byte; retain the pair and ownership assumptions even when a linear address is available.

The packed EGA entry `1AEC:0012` is a packer entry, not the recovered game entry. After unpacking there is generally no one-to-one linear mapping to packed file offsets. Use the unpacked artifact hash and transform ID; leave an unavailable packed-byte mapping absent with an explanation. Do not apply original-file string offsets directly to a recovered load image. Tool bases such as Ghidra's loader conventions are analysis choices, never original runtime facts.

## Record schema and evidence scope

The five standalone JSON Schemas in [schemas](schemas/) use Draft 2020-12. Each record contains `record_type`, `schema_version`, `id`, `edition_id`, `status`, `confidence`, `claim`, `evidence`, `dependencies`, `gates` and `unknowns`, followed by its type-specific fields. Registries may wrap a list of records; validate each item against its matching schema. Scalar offsets are decimal JSON numbers. Binary content is referenced by hash/path, not embedded in records.

An evidence item records `method`, `locator`, `result`, `scope` and optional `tool_id`/`record_id`. State precisely what was measured, which branch/range was covered, and what the result does not resolve. Methods distinguish raw-byte inspection, instruction analysis, source comparison, transformation validation, compilation, synthetic vectors, differential traces, runtime observation, visual review and audio review. A string cross-reference proves a consumer candidate; it does not prove a file schema, algorithm or complete reachable path.

Confidence is claim-specific: `unknown` has no supported interpretation; `tentative` is a plausible hypothesis; `supported` has direct bounded evidence with unresolved alternatives; `strong` has converging evidence and addressed alternatives; `refuted` preserves a disproved claim. Confidence is not a completion percentage. Use separate records when one assertion is strong and another tentative.

Every unresolved item has a description, `blocking` flag and a resolution method or dependency. Contradictions remain recorded. An assumption must name its consequence and how it will be tested. Important review decisions receive decision records; changing an assumption never rewrites historical evidence.

## Recovery and acceptance gates

| Gate | Passing evidence | Scope limit |
| --- | --- | --- |
| `static_bytes` | Hash-pinned bytes and valid locators | No execution or semantic equivalence claim |
| `code_contract` | Reviewed instructions/control flow, ABI, memory effects and arithmetic rules | Covers only named paths and conditions |
| `compilation` | Named compiler/options/source hash and successful result | No behavioral or fidelity claim |
| `differential` | Admitted oracle or independently justified vectors, compared boundaries and results | Only exercised vectors/branches |
| `runtime` | Executed scenario with admitted start state, inputs, checkpoints and result | No full-content coverage claim |
| `visual` | Named indexed-pixel/palette/animation measurements and human review where required | Only named scenes/profiles |
| `audio` | Named timing/event/PCM measurements and listening review where required | Only named songs/effects/configurations |
| `fidelity` | Edition-specific coverage review across applicable gates and documented exceptions | Never universal parity by implication |

Every gate has independent `status` (`not_started`, `pending`, `passed`, `failed`, `blocked` or `not_applicable`), evidence IDs and a scope note. `not_applicable` requires a reason. A higher confidence or a later recovery stage cannot silently pass any gate. A specification can pass a documentation task while runtime/differential repeatability remains unproven.

Function recovery proceeds through candidate discovery, bounded ranges, reviewed contract, translation, compilation, differential validation and acceptance. Record the compiler/runtime/game classification separately. A contract includes entry/exit conditions, near/far/interrupt conventions, register and flag inputs/outputs/clobbers, stack cleanup, DS/ES/SS assumptions, globals, aliasing, calls/indirect edges and hardware/OS effects. Preserve widths, signedness, wrap/carry/truncation, shifts and division/rounding explicitly. If any are unknown, record them; decompiler types do not establish them.

A function marked `accepted` requires passing byte/contract/compilation/differential gates and no unresolved blocking item on its supported contract. A loader/runtime function may instead receive an explained nontranslated disposition with bounded evidence. A candidate boundary, disassembly export or compiled placeholder is not recovered game behavior. Shared tails and uncertain indirect targets stay in the coverage ledger until resolved. Full Phase 1 closure still requires all reachable EGA code disposition, actual portable recovery, and the later CGA analysis; acceptance of one helper does not pass the phase gate.

For resources, record consumers and write sites, container relationship, byte ranges, schema/endian/units/limits, external-media classification, decode disposition and explained exceptions. Phase 1 may record raw-data contracts without implementing the full format. A field hypothesis or successful parse of one file cannot become all-corpus acceptance. DOS PC Speaker sequencing/timer/device semantics are separate from PCM output; Amiga audio and Northern Germany Challenge stay in their ordered later phases.

## Review and progress procedure

1. Verify the admitted input and tool/config identities; name the task and owned files before a transformation or edit.
2. Persist raw observations before semantic interpretation. Export readable indexes alongside private analysis databases.
3. Add/revise records with bounded claims, addresses, dependencies, unknowns and independent gate statuses.
4. Validate JSON syntax and schema shape; run meaningful checks appropriate to the changed contract. A schema check verifies record shape only.
5. Update the backlog and coverage ledger from evidence, retaining partial tasks and explicitly pending checks. Preserve tool errors and failed comparisons.
6. Read back changed documents/records, refresh the final original manifest, and state static/code/build/differential/runtime/visual/audio/fidelity results separately in the handoff.

Schema validation cannot prove claim truth, hash existence, address arithmetic, reviewed signatures, graph completeness, publication safety or original-file custody. Those are mandatory semantic checks against the actual artifacts. The future oracle setup and its current limits are in [oracle-spec.md](oracle-spec.md).

Validation on 2026-10-13 used project-local `jsonschema==4.25.1`: all five schemas passed the Draft 2020-12 metaschema check, and all 59 synthetic positive/negative shape cases produced their expected result. The [validation record](evidence/schema-validation.json) pins the validator and dependencies by exact version and PyPI-verified wheel SHA-256. These are schema checks only; the synthetic specimens are not game evidence records.
