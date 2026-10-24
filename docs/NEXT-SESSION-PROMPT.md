# Next-session work prompt

Paste everything below the line into a new Claude Code session opened in `C:\Projects\TestDrive2`.

---

You are continuing the Test Drive II reconstruction in `C:\Projects\TestDrive2`. Read `docs/HANDOVER.md` first; it is the source of truth. Read `CLAUDE.md` for the working rules. Do **not** read `docs/planning/continuation.md`, `backlog.json`, `progress.json` or the `docs/recovery/evidence/` receipts. They come from a previous agent that stalled the project in verification bureaucracy, and the handover already extracts what matters.

## Goal of this session: milestone M0 "Adopt", then the start of M1 "Verify EGA"

A playable, MIT-licensed C11/SDL3 port of TD2EGA already exists at `reference/repos/kylofon-test-drive-2-sdl3` (commit 352b568). This session makes it our codebase and gets a reproducible build and run.

### Tasks, in order

1. **Import the source.** Copy these from the clone into `port/td2/` (create the folder):
   - `td2port/` (sources and CMakeLists)
   - `LICENSE`
   - `FORMATS.md`
   - `port/spec/*.md`, `port/*.csv`, `port/*_functions.json`, `port/RE_GUIDE.md`

   Rules for the copy:
   - Copy with plain file copies. Do not modify the clone, and do not fetch or build inside it.
   - Add `port/td2/PROVENANCE.md` giving the upstream URL `https://github.com/kylofon/test-drive-2-sdl3`, the commit, the MIT notice and the date.
   - Make sure `.gitignore` does not exclude `port/` and does exclude build outputs.

2. **Apply useful fixes.** Read `analysis/candidates/kylofon-r03-v1/candidate-fixes-v2.patch` and apply only these parts to `port/td2`:
   - 20-bit `lin()` wrap and per-byte wrapping `rd16/wr16/rd32/wr32` in `mem.h`
   - the `INT32_MIN/-1` guard in `idiv32_16`
   - the inner EXEPACK bounds checks in `mem.c`
   - the `--user-dir` option so that high scores and `SELECT.DAT` go to a profile folder, not the game folder. The default is `%APPDATA%\TestDrive2`, or `<exe dir>\profile` if that is simpler. Keep it portable: put Windows-specific path code behind `#ifdef _WIN32`, and do not port the reparse-point/hardlink paranoia.

   Do **not** apply the SHA-256 identity gate; a size and marker check is enough. Fix the em-dash mojibake the patch introduced in `main.c`.

3. **Build.** Create a top-level `CMakeLists.txt` (or reuse `port/td2/td2port/CMakeLists.txt`) and `build.ps1`:
   - `build.ps1` calls `vcvars64.bat` (VS 2022 BuildTools, `-vcvars_ver=14.44`).
   - It uses the VS-bundled CMake with Ninja or NMake, and SDL3 from `analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18/cmake`.
   - It builds Release into `build/` and copies `SDL3.dll` next to the exe.
   - Use `tools/build_kylofon_candidate_v1.py` as the known-good flag reference (`/std:c17 /W3 /O2 /utf-8 /MD /D_CRT_SECURE_NO_WARNINGS`, linked with bcrypt only if still needed).
   - It must build from a clean checkout with one command and no warnings at `/W3`.

4. **Run.** Create `run.ps1`:
   - It creates `runs/game/` (gitignored) by copying `reference/dos/*` if that folder does not exist.
   - It launches `build/td2port.exe --game-dir runs/game --user-dir runs/profile`.
   - Verify `--check` prints `TD2EGA.EXE ok (EGA)`.
   - Launch the game, confirm it stays up, and capture headless snapshots with `TD2_SNAPSHOT_DIR`. Use `SDL_VIDEO_DRIVER=dummy` if needed to confirm the title and menu render. Look at the BMPs.
   - Then ask the user to play one race on each scenery (CCC, ec_, TDS2) and report problems. Do not wait idle for that; continue with task 5.

5. **Generic differential harness (M1 start).** Write `tools/diffharness/` as **one** reusable Python module plus a CLI:
   - Load the unpacked image `analysis/derived/td2ega-v1/TD2EGA.unpacked.exe` and relocations at segment 0x1000, matching Kylofon's `mem[]` layout.
   - Run an original function under Unicorn (`PYTHONPATH=analysis/tools/python`) from a given `seg:off`, with given register inputs and a memory snapshot, until RET/RETF.
   - Run the corresponding Kylofon C function in a test DLL built from `port/td2` sources against the same `mem[]` snapshot.
   - Compare **only the observable outputs that matter**: return registers plus the DS/stack memory bytes written. Do not compare full 1 MiB of RAM, all flags, or AF.
   - Use `tools/validate_bios_block.py` and `tools/validation/twenty_bit_bus.py` as references for the Unicorn setup.
   - Write tests under `tests/` for the harness itself.
   - Then run it on 5–10 pure leaf functions (rand8/byte ring `06C9:780E`, RLE and Huffman unpack, `curve_sum`, `drag_apply`, `update_rpm`) with randomised inputs. Write one summary table to `docs/verification.md`. One file is overwritten each run; no versioned receipts.

6. **Commit.** Commit in small logical commits on `main` (or a branch if the user prefers), one per task above. The predecessor's work is already committed (24 October 2026), so the tree should start clean.

### Stop and report when

Stop when tasks 1–5 are done, or when blocked on something that needs the user. Examples: the game crashes at a point you cannot diagnose from code, or a licence question comes up.

The report should cover:
- what builds and runs, and how;
- the snapshot results;
- the harness results table;
- the next three most valuable fixes. Start from the known deviations: neutral clutch (`sim.c:265`), billboard collision (`sim_motion.c:436`), traffic seeding (`sim_traffic.c:244/367`), cockpit marker (`scene_cockpit.c:207`), and PC-speaker synthesis in `host.c:102`.

### Rules (also in CLAUDE.md)

- **`reference/` is read-only.** Never point the game at `reference/dos`; always use a copy.
- **No versioned evidence files.** Overwrite outputs, and keep results in a few human-readable docs. No receipts, no `-vN.json`, no "consumed maker" scripts, no custody re-hashing.
- **Verification serves the game.** Compare behaviour at function or subsystem outputs, then judge by playing. Name things by their game meaning (timer, RNG, crash state). Keep Kylofon's names.
- **Timebox investigations.** If a sub-problem takes more than about an hour without producing code or a fix, write down what is known in `docs/HANDOVER.md` "open questions" and move on.
- **Write in plain sentences.** Keep the handover short and update it at the end of the session: what changed, what is next.
