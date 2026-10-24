# Independent P1-R04 decision-boundary review

22 October 2026. This review reads the saved P1-R02/R03 source, build and validation evidence. It does not edit sources, run tests/makers, admit new original function contracts or change a gate. The normative reuse decisions belong to the parent P1-R04 register.

## Acceptance distinction

P1-R04 asks for per-subsystem import decisions and origin records, a defined native caller profile/raw-contract bridge, and an effort update informed by the spike. Those decision artifacts can complete P1-R04. They do not imply that code has been integrated, existing recovered functions have been replaced, supported historical caller domains have been proved or P1-05/P1-11/P1-GATE have closed.

The saved verification reports 2,233 admitted original-body vectors, 291 baseline disagreements, four deliberately excluded SS-alias mismatches and 380 separate support checks. The build is C17/MSVC x64 `/W3 /O2 /MD`, with deterministic probe services and a pinned SDL dependency. It is not the recovered-helper `/W4 /WX` qualification or a second-host portable-core acceptance.

## Hard conditions for a normative allowlist

1. Select original entry plus actual candidate symbol, precise source/branch range, candidate hash and required shared dependencies. An approved symbol in `res.c`, `sim.c` or `gfx.c` does not approve the whole file.
2. Pin the frozen upstream commit, unchanged upstream file/blob identity, candidate change manifest, compiler/build receipt, actual tested DLL and executed validator. Any future extraction/refactor/adapter change needs a new build and applicable comparisons; saved passes do not transfer automatically.
3. Declare observations precisely. The native API compares selected scalar results and memory. It does not recreate actual original SS frames, GPR/FLAGS, interrupt delivery or return-word mutation. The original comparison excludes a specific scratch aperture from `SP-0300` through the input call frame (`validate_kylofon_representative_v1.py:277-287`). It is not an unqualified whole-RAM equivalence statement.
4. Preserve all four excluded SS-argument alias witnesses as disallowed contexts for this native profile. Neither fixed DGROUP nor synthetic C locals prove DS=SS, stack disjointness or historical reachability at every caller.
5. Keep fixed native DS/CS, owned stable memory, admitted image/relocations, disjoint scratch/source/output and declared descriptor/stream bounds explicit. Scalar 20-bit wrapping does not repair direct typed `DSW`/`DSL` lvalues or contiguous bulk operations. Windows little-endian x64 execution does not establish alignment/strict-aliasing portability elsewhere.
6. Define a bridge from raw original contracts to the narrower native data API before integration. Do not rewrite our raw APIs to erase aliases or copy old receipt status onto newly extracted functions.
7. Distinguish current source qualification from runtime guard enforcement. P1-R04 can require preconditions in an import decision; it must not claim a checked production wrapper exists unless one was implemented and validated.
8. Retain independent recovered implementations and their receipts as fallback/oracle. Do not count selected upstream counterparts as new recovery when the existing project already implements those helpers.

## Entry-specific traps

| Selection | Required qualification |
| --- | --- |
| `rand8`, original `06C9:780E` | 278 fixtures include all cursor low-byte positions and selected 16-bit edges, with 17-call sequences for edge cursors. This supports the selected transformation/consumption observations. It does not close initial table ownership, all writers/reset, callback interleavings, RNG purpose or full game consumption history |
| Literal helpers `5D83/5D8D` | Select the repaired `0040:046C`, physical `086C` read and modulo subtraction. Keep host physical `046C` BIOS clock separate and preserve unassigned purpose/units. The 250 failing baseline literal cases expose one wrong-address class, not 250 distinct defects |
| Input vector set/get `6A17/6A28` | Select data-vector behavior in disjoint frame domains only. The four intentionally overlapping SS cases are observable counterexamples to broader equivalence. This is not keyboard/BIOS/IRQ body or vector-lifetime acceptance |
| `curve_sum`, `drag_apply`, `update_rpm` (`448A/45BF/4612`) | Select only the checked state updates. `update_rpm` is invoked with `NULL,NULL`; the validator does not compare its bool result or its optional old/new RPM output-pointer values (`probe.c:37`, validator `272-287`). Neutral-clutch callers depending on inherited CX/DX remain excluded. Drag fixtures use throttle 0/FF and force/speed edges; its brake path has gear zero, so the brake-to-active-RPM composition is not independently admitted by that fixture family |
| Clip `5DFB` | Select four CS clip-word writes from value arguments, with disjoint original SS input frames. There is no hardware/clipping/rendered-pixel acceptance from that state write |
| Plot `BA3C` | Select the RAM-plane branch (`gfx.c:511-517`) with declared row-table/mask/plane inputs. The `CUR_PLANE(0)==A000` EGA-register/latch branch (`501-509`) is not tested. The 41 high-address baseline failures expose a wrapping class. Do not promote them to display fidelity |
| Run/block decoder `6B02` | **Branch-level selection only.** Fixtures set escape control to exactly 81/83/8B hex, hence skip the `ec<=80` sequence-first branch. They check header/table construction and `rle_run_pass`, not `rle_seq_pass`, `paras_of`, `far_move_up`, the zero-escape/full LOOP domain or more than 11 header escapes. Input/output/paragraph locations are synthetic and fixed in this sample. The permitted instruction fence containing `7030` is not evidence that `7030` executed |
| Scalar memory/division adapter | Select tested scalar reads/writes and signed quotient/fault guard in the fixed build profile. The signed-division support call uses remainder pointer NULL; remainder output-pointer behavior and original x86 fault/handler ABI were not compared. Baseline undefined `INT32_MIN/-1` was intentionally not executed |
| Canonical loader | Select exact canonical EXE identity, admitted decompression/relocation transform and declared passed-state byte assignments. The ten invalid EXEs are rejected at the identity gate; they do not exercise every deeper malformed EXEPACK/MZ bounds branch. Other same-named variants remain unsupported |
| Profile path adapter | Select the tested Windows original-read/profile-write policy, including hardlink-write denial, within stable non-adversarial directory fixtures. The old quiet writer can return zero on both success and failure. Its return value is not a reliable success flag. No complete host/user-data migration or concurrent filesystem race acceptance follows |

The scalar comparisons are explicitly limited: the original-body validator sets `expected_value` only for `780E`, `5D83`, `5D8D`, `6A28` and `6B02`. All other selected functions are accepted through their declared memory observations, not an invented original C return signature.

## Families that must stay outside broad adoption

The 38-site admission ledger remains authoritative for short-DAT heap-tail semantics; inherited cockpit CH/SI, billboard BP and traffic DI/CX; neutral-clutch events; full zero/wrapped LOOP behavior; constructor/descriptor arena and blitter/latch edge domains; live callback/IRQ and all-writer/lifetime history; complete scheduling/audio; and unbounded game arithmetic. A separate candidate implementation already being present does not close those proofs.

CGA, Amiga recovery, Northern Germany Challenge import and live media switching remain unimplemented feature obligations. The integrated game/renderer/host can be retained as a later-phase scaffold candidate, but it is not a currently validated subsystem or immediate completed-work credit.

## Media, provenance and effort rules

The origin manifest should identify upstream MIT notice/license hashes and retain notices in any eventual extracted code. It must also distinguish new local admission adapters from upstream-owned code and pin their exact changes. MIT labels do not admit original media: 27 game/runtime text tokens are distribution blockers, eight identity markers need review, and the private specification contains font hex. Whole repository/file copying into a distributable remains rejected.

The spike's 291 failing baseline fixtures represent two observed semantic classes (literal address and physical wrapping), not 291 separately debugged bugs. The measured 35.585-second direct build and 81.974-second comparison execution do not measure engineer throughput, total adaptation time or a percentage of project effort saved. Revised remaining-work ranges may use those outcomes to lower risk for selected narrow families, but broad host/game/decoder savings must remain a clearly conditional scenario. Do not count already-recovered helper work as a future rewrite saved.

P1-R04 should finish with an explicit allowlist, deferred/rejected list, dependency/phase mapping, origin/change records and a prospective remaining-work estimate with assumptions and re-estimation checkpoints. Existing main native/function/resource totals and phase order should remain unchanged unless separate new recovery evidence actually earns credit.
