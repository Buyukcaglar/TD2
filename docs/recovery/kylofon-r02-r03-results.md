# Kylofon P1-R02 and P1-R03 results

22 October 2026. Upstream remains pinned at `352b56824d8c91e938b8f0794a71afca9a276193`. P1-R02 is complete as source/address/deviation admission; P1-R03 is complete as a representative build and differential spike. These are bounded acceptance decisions. P1-R04 subsystem adoption, P1-05, the EGA/CGA gates and all later resource/gameplay/fidelity gates remain open.

## Result

The repaired private candidate passed **2,233 representative vectors across 11 original entry points**, executing **116,990 original instructions**, with zero candidate disagreements in the admitted profile. The untouched upstream baseline disagreed in **291 admitted cases**: 25 literal reads, 225 literal subtracts and 41 RAM graphics writes at high physical addresses. The patches remove those disagreements.

Four deliberately overlapping SS-argument fixtures remain explicit **excluded mismatches** for both builds. They demonstrate that a host value-argument API does not preserve original live stack-argument aliases. They are not passing comparisons, silently filtered regressions or proof that those aliases never occurred historically. The broader recovered bus/ABI evidence remains authoritative and unchanged.

An independent **380-case support suite** passed loader identity/memory, scalar address wrapping, division guards and separate profile writes. Those checks are counted separately from original-body differential vectors and from the project's existing accepted helper totals.

## Original/reference custody and working copies

All modifications and executable outputs are under `analysis/candidates/kylofon-r03-v1`. `baseline/` contains the original 85 tracked upstream files, without Git metadata. `candidate/` is the separate edited copy. The reference clone was neither edited nor fetched, and no build was performed inside it. Original DOS/Amiga files remain inputs only; loader tests use private copies, and file-write tests use synthetic fixtures.

The reference snapshot still covers all 113 clone files, including Git metadata. The independent 250-original media manifest, their hashes, modification times and attributes are unchanged. The existing function registry and all 331 recovered source/header files are unchanged. No source was staged, committed, pushed or merged into `src/recovered`.

## Static source admission

The [address admission](kylofon-address-admission.md) and its [machine crosswalk](evidence/kylofon-address-admission-v1.json) reconcile every one of the 27 upstream-only and 23 local-only starts, all 76 naming conflicts, all 460 upstream function symbols and 495 distinct candidate addresses. They preserve stable local IDs or neutral address identities and retain upstream aliases. Names, code hashes and candidate starts are not semantic acceptance.

Three particularly useful corrections are:

- `06C9:AF54` is screen-descriptor data, not an admitted executable root.
- `06C9:1A37` is inside the operand of the far CALL at `1A33`; the selected graph supplies no independent alternate-entry witness.
- `06C9:C030` is shared graphics interior code. A purported caller obtained by disassembling the AF54 descriptor supplies no reachability evidence.

Uncalled library prefixes remain discoverable candidates with pending caller/reachability/semantic gates. No new accepted function ID or raw contract was manufactured to make the indexes agree.

The [source/media admission](kylofon-source-admission.md) inventories every string and initializer across all 41 upstream C/H files: 221 string tokens, 26 initializer records and 38 per-site behavior dispositions. **27 game/runtime text tokens remain blocked from distribution**, and eight identity markers require review. One additional original scenery-label format was found in `game/flow_screens.c:446`. The private build may retain them for evaluation; this is not release/package admission. No original text or font payload is copied into public evidence.

## Candidate fixes

The exact changes are preserved privately in `candidate-fixes-v2.patch`; [the change receipt](evidence/kylofon-candidate-changes-v1.json) pins baseline/candidate file hashes and the patch. Eight files were changed or added:

| Candidate file | Correction and validation |
| --- | --- |
| `platform/timer.c`, `timer.h` | Read literal `0040:046C`, physical `086C`, with modulo subtraction. Keep its purpose/time units unassigned. Original-body comparisons distinguish it from physical `046C` |
| `mem.h` | Wrap scalar physical addresses at 20 bits; wrap each byte of word/dword reads and writes; use unsigned dword shifts; guard `INT32_MIN / -1` before C division. Scalar, actual RAM-plot and guard tests exercise these changes |
| `mem.c` | Admit the exact 114,421-byte canonical EXE by SHA-256 using Windows BCrypt; bound EXEPACK relocation entries, skip/destination spans and MZ allocation/tables; reject invalid relocations rather than skip them. Canonical loaded memory and altered/truncated/oversized copies are checked |
| `host_paths.c` (new), `host.c`, `host.h`, `main.c` | Separate original reads from writable user-profile overlays; expose `--user-dir`; reject nested roots, unsafe Win32 names, reparse ancestors and write-through hardlinks. Check actual synthetic writes, fallback and overlay reads, denial paths and preserved originals |

Direct fixed-DGROUP/CS lvalue casts and contiguous bulk accesses still have explicitly bounded native domains. The scalar repair does not prove general alignment portability or repair every bulk wrap/alias operation. The admission adapter uses Windows APIs and is not a second-host portable-core qualification.

The host's physical `046C` BIOS-clock model remains separate from the literal `086C` helper. The patches do not assign units, reset it to a clock value or normalize original instructions. Protection-passed initialization is retained as an explicit upstream native policy, not a claim that removed protection/disk/install paths are faithfully implemented.

## Build evidence

[The build receipt](evidence/kylofon-candidate-build-v1.json) pins the maker, MSVC 19.44 compiler/linker, SDK 10.0.26100.0, headers/libraries, actual source/probe inputs, objects, command arguments, logs and outputs. SDL **3.4.18** was obtained from its official release; the downloaded VC SDK archive matched the published SHA-256 `78d84602ae616cfe26b33a73b7d3b9b6b56e8a6650e53d92c9c6ca938f747acd`.

Both variants built complete EXEs and probe DLLs: **51 C17 compilations and four links, zero warnings**, with 35.585 seconds measured for the direct compile/link work. The warning policy is `/W3 /O2 /MD`, matching the upstream policy; this is distinct from the existing recovered helpers' `/W4 /WX` qualification. No game EXE was launched.

The direct build bypassed slow batch environment/CMake setup by invoking the pinned compiler and linker with explicit include/library paths. The earlier CMake environment attempts/logs are retained. One setup attempt also failed after its still-running batch recipe was edited; no compilation result from that attempt is accepted. Neither CMake build-system qualification nor calendar development-speed improvement is claimed from the successful direct build.

## Original-body comparisons

[The design](kylofon-differential-design.md) and [passing receipt](evidence/kylofon-representative-validation-v1.json) define the full fixture stream, instruction fence, original image/MZ/relocations, build/DLL/validator hashes, baseline witnesses and excluded domains.

| Family | Original entries | Admitted vectors |
| --- | --- | ---: |
| Byte-ring and repeated consumption | `06C9:780E` | 278 |
| Literal read/subtract | `06C9:5D83`, `5D8D` | 270 |
| Input callback vector set/get | `06C9:6A17`, `6A28` | 256 |
| Curve sum, drag, RPM update | `06C9:448A`, `45BF`, `4612` | 725 |
| Clip state and RAM planar plot | `06C9:5DFB`, `BA3C` | 512 |
| Bounded run/block codec stage | `06C9:6B02` | 192 |
| **Admitted total** | **11 entries** | **2,233** |

The actual candidate C bodies run directly. Unicorn independently executes the admitted original instructions. The comparison observes declared scalar values and the first 1 MiB of RAM, excluding the explicitly named original stack scratch/frame aperture. It checks original return control and stack adjustment, but the native data API does not promise original GPR/FLAGS/frame stores. Host services are trapped or excluded; no game loop, BIOS/DOS/device or IRQ delivery is simulated as acceptance.

The codec profile uses synthetic bounded run-only streams with 1/3/11 escapes. It does not decode supplied files, admit the sequence-first/full-zero-loop branches, prove malformed-input safety or close the full codec/resource gate. The graphics cases use RAM planes; they do not establish EGA latches, hardware pixels, display sequencing or human visual acceptance.

## Support checks and preserved attempts

[Support v2](evidence/kylofon-admission-support-v2.json) passed 380 checks:

- Both native loaders match all 1,114,112 model RAM bytes after loading the independently admitted 130,240-byte image, applying 1,652 relocations and five declared protection-state byte assignments.
- Ten invalid-identity cases are rejected.
- 240 scalar memory checks pass. The baseline disagrees in 35 checks, with discriminating failures in all five read/write families.
- 77 division cases cover normal values and explicit faults. The unsafe baseline `INT32_MIN / -1` expression is not executed.
- 51 path/profile checks exercise actual writes, read overlays/fallbacks, unsafe-name/root rejection and hardlink-write denial. Synthetic original file hashes, modification times and attributes stay unchanged. The inherited quiet write API returns zero even on some failures; denial is checked through path resolution and filesystem effects rather than interpreting zero as success.

The first support attempt passed with a weaker repeating memory pattern. Review found that its read pattern did not sufficiently distinguish high-address aliases. The final v2 adds high address bits; both the first receipt and exact executed makers/logs remain archived. A bounded 16-vector differential probe also passed before the complete run. Earlier static coordinate and lexical inventory drafts are preserved with their corrections. The pre-build patch-context failure left a private partial candidate archive; no compiled result came from that partial state.

## Admission boundary and next action

Use these results for P1-R04's measured subsystem decision. The static and representative checks support the value of reusing candidate C; they do not measure a percentage of total project effort saved. Setup/build time, sample counts and disagreement types are now concrete evidence for that decision.

Broader DS/SS/frame/FLAGS/return alias behavior, caller provenance, all-writer/reset/lifetime closure, mutable code transitions, short-DAT heap-tail reads, inherited cockpit/traffic/collision registers, neutral-clutch events, graphics constructor/blitter edge domains and full timing/audio remain excluded or rejected for import until their named proofs exist. The source disposition ledger makes those decisions explicit. No pending recovery or edition-fidelity gate is silently closed by a sample pass.

The main accepted summary remains **215 exports / 292 original entries / 164 suites / 7,132,350 vectors**, with the separate early-exit packet still unregistered. These new candidate checks stay separate from that summary. P1-R04 is the next adoption task; complete EGA semantics still precede CGA, complete DOS resources, native sessions, Amiga and live media switching.
