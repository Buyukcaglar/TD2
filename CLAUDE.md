# Test Drive II reconstruction: working rules

Start with `docs/HANDOVER.md` (current state, salvage inventory, plan) and `docs/NEXT-SESSION-PROMPT.md`.

## Rules

**Data**
- `reference/` is read-only: original DOS and Amiga files, plus the Kylofon clone.
- Game runs use a writable copy under `runs/` (gitignored).
- Never commit or ship original media.

**Codebase**
- The codebase is the Kylofon TD2EGA SDL3 port, MIT-licensed, vendored with its LICENSE and provenance.
- `src/recovered/` is reference material only; do not extend it.

**Evidence**
- No versioned evidence files (`-vN.json`), receipts, custody audits or "consumed" scripts. Overwrite outputs.
- Keep results in a few readable docs.
- `docs/recovery/evidence/` and `analysis/history/` are frozen history.

**Verification**
- Verification serves a playable game: function-level differential tests on observable outputs, snapshots, and playing.
- Do not compare full RAM, all flags or stack aliasing.
- Name things by their game meaning.

**Working habits**
- Timebox: about an hour without code or a fix means write down the open question and move on.
- Write in plain sentences. Update `docs/HANDOVER.md` at the end of each session.

## Build and run

- `.\build.ps1` builds `build\td2port.exe` and the harness DLL `build\td2diff.dll` (MSVC 19.44 via `vcvars64.bat -vcvars_ver=14.44`, VS-bundled CMake and Ninja, SDL3 3.4.18 built from `analysis/external/sdl3-3.4.18/source`, and libarchive 3.8.1 with zlib and xz built once from `analysis/external/archive-libs`, all linked statically with the C runtime, so the exe is a single portable windowed app).
- `.\run.ps1` plays on `runs\game`, a copy of `reference\dos`, with scores and `settings.ini` in `runs\profile`. `.\run.ps1 --check` verifies the EXE. `.\run.ps1 -RecordStates` also saves race states to `runs\states` for the harness's whole-tick cases.
- `$env:PYTHONPATH = "analysis/tools/python;tools"; python -m diffharness` runs the differential harness and rewrites `docs/verification.md`. Tests: `python -m unittest discover -s tests`.
- `python tools/snapshots.py` checks the EGA frames and speaker output of the attract loop, a scripted menu run and a run with live graphics switches against `tests/ega_snapshots.txt`; `--cga` and `--hercules` do the same against `tests/cga_snapshots.txt` and `tests/herc_snapshots.txt` (`--update` rewrites a baseline after an intended change).
- `.\run.ps1 --cga` plays with the CGA backend, `.\run.ps1 --hercules` with TD2CGA's Hercules mode. Ctrl+Shift+G switches the graphics mode live, Ctrl+Shift+S the sound (PC speaker or Amiga, which needs the `amiga` setting: the Amiga game's folder or archive); a right click or Ctrl+Shift+M opens the app's menu (`src/app/`). Headless runs take `TD2_KEYS` ("30:Return,56:Up/240,60:Ctrl+Shift+G": key presses at game times, optionally held) and `TD2_SNAPSHOT_MS`.
- `python tools/cga_compare.py` compares TD2CGA with TD2EGA function by function (`docs/cga.md`); add EGA addresses such as `06c9:3c3a` to print those functions' differences.

- `tools/amiga/` reads the Amiga files in `runs/amiga` (a copy of the unpacked Amiga archive): `hunk.py`, `disasm.py <file> <start> <end>`, `rpck.py`, `ilbm.py`. `tools/dos_unpack.py` unpacks a DOS PES/PCS/DAT file. See `docs/amiga.md`.

Python analysis tools need `PYTHONPATH=analysis/tools/python`, which provides Unicorn 2.1.4 and Capstone 5.0.9. Ghidra 12.1.3 is at `C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC`; run it through `tools/run_ghidra.ps1`.

## Phase order (user requirement)

EGA → CGA → all DOS resources (Hercules only) → native Windows → Amiga recovery → Amiga sound and music switching plus Northern Germany Challenge scenery. DOS audio is PC Speaker only.

Native Windows (`docs/native-windows.md`): live graphics switching by one key combination that is the same on Windows and a later macOS build, a single portable exe, every dialog and window in the OS theme, no app features inside the game picture (only the app's context menu and question windows), and only the base DOS game required (two cars, Master scenery); expansions and the Amiga version are optional.
