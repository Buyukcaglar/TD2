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

- `.\build.ps1` builds `build\td2port.exe` and the harness DLL `build\td2diff.dll` (MSVC 19.44 via `vcvars64.bat -vcvars_ver=14.44`, VS-bundled CMake and Ninja, SDL3 3.4.18 from `analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18`).
- `.\run.ps1` plays on `runs\game`, a copy of `reference\dos`, with scores in `runs\profile`. `.\run.ps1 --check` verifies the EXE. `.\run.ps1 -RecordStates` also saves race states to `runs\states` for the harness's whole-tick cases.
- `$env:PYTHONPATH = "analysis/tools/python;tools"; python -m diffharness` runs the differential harness and rewrites `docs/verification.md`. Tests: `python -m unittest discover -s tests`.
- `python tools/snapshots.py` checks the EGA frames and speaker output against `tests/ega_snapshots.txt` (`--update` rewrites it after an intended change).

Python analysis tools need `PYTHONPATH=analysis/tools/python`, which provides Unicorn 2.1.4 and Capstone 5.0.9. Ghidra 12.1.3 is at `C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC`; run it through `tools/run_ghidra.ps1`.

## Phase order (user requirement)

EGA → CGA → all DOS resources → native Windows → Amiga recovery → live graphics/audio switching plus Northern Germany Challenge scenery. DOS audio is PC Speaker only.
