# Next-session work prompt

Paste everything below the line into a new Claude Code session opened in `C:\Projects\TestDrive2`.

---

You are continuing the Test Drive II reconstruction in `C:\Projects\TestDrive2`. Read `docs/HANDOVER.md` section 0 first; it is the current state. Read `CLAUDE.md` for the working rules and the build, run and harness commands. Do **not** read `docs/planning/continuation.md`, `backlog.json`, `progress.json` or the `docs/recovery/evidence/` receipts.

## Goal of this session: finish M3 "CGA", then start on "all DOS resources"

The game builds with `.\build.ps1` and runs with `.\run.ps1` (`--cga` for CGA). The differential harness (`python -m diffharness`) matches 59 functions: the simulation and unpackers against TD2EGA, whole sim timer calls replayed from recorded race states, and 40 graphics and scene routines against TD2CGA's own code. `python tools/snapshots.py` (and `--cga`) compares the attract loop and a scripted menu run with committed hashes. `TD2_KEYS` scripts key presses for headless runs. `docs/cga.md` explains how TD2CGA differs from TD2EGA and where the CGA backend stands.

1. Start by asking the user for the results of their play tests: one race on each scenery in EGA (ideally with `.\run.ps1 -RecordStates`) and one race in CGA. Fix what they report first, then rerun `python -m diffharness sim_tick` on their recorded states.
2. Work through "Next steps" in `docs/HANDOVER.md` section 0: a scripted run to a stage end in both adapters, then the survey for "all DOS resources".
3. For each behaviour fix, add or extend a harness case that shows the port now matches the original, and rerun `python -m diffharness` so `docs/verification.md` is current. Run `python tools/snapshots.py` and `python tools/snapshots.py --cga` after any change to graphics or sound.

Rules: `reference/` is read-only; no versioned evidence files; compare observable outputs, not full RAM or flags; timebox investigations to about an hour; small logical commits; update `docs/HANDOVER.md` section 0 at the end.
