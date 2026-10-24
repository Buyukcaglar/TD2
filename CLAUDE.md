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

Build and run commands are being set up (milestone M0). The proven compiler is MSVC 19.44 (VS 2022 BuildTools, `vcvars64.bat -vcvars_ver=14.44`) with SDL3 3.4.18 at `analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18`.

Python analysis tools need `PYTHONPATH=analysis/tools/python`, which provides Unicorn 2.1.4 and Capstone 5.0.9. Ghidra 12.1.3 is at `C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC`; run it through `tools/run_ghidra.ps1`.

## Phase order (user requirement)

EGA → CGA → all DOS resources → native Windows → Amiga recovery → live graphics/audio switching plus Northern Germany Challenge scenery. DOS audio is PC Speaker only.
