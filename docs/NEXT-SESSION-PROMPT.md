# Next-session work prompt

Paste everything below the line into a new Claude Code session opened in `C:\Projects\TestDrive2`.

---

You are continuing the Test Drive II reconstruction in `C:\Projects\TestDrive2`. Read `docs/HANDOVER.md` section 0 first; it is the current state. Read `CLAUDE.md` for the working rules and the build, run and harness commands. Do **not** read `docs/planning/continuation.md`, `backlog.json`, `progress.json` or the `docs/recovery/evidence/` receipts.

## Goal of this session: the "native Windows" phase

The game builds with `.\build.ps1` and runs with `.\run.ps1` (`--cga` for CGA, `--hercules` for TD2CGA's Hercules mode). The differential harness (`python -m diffharness`) matches 59 functions: the simulation and unpackers against TD2EGA, whole sim timer calls replayed from recorded race states, and 40 graphics and scene routines against TD2CGA's own code. `python tools/snapshots.py` (and `--cga`, `--hercules`) compares the attract loop and a scripted menu run with committed hashes. `TD2_KEYS` scripts key presses for headless runs. `docs/cga.md` explains how TD2CGA differs from TD2EGA, where the CGA backend stands, and the Hercules mode. The "all DOS resources" phase is Hercules only, by the user's decision.

1. Start by asking the user for the results of their play tests: one race on each scenery in EGA (ideally with `.\run.ps1 -RecordStates`) one race in CGA, and a look at Hercules. Fix what they report first, then rerun `python -m diffharness sim_tick` on their recorded states.
2. Work through "Next steps" in `docs/HANDOVER.md` section 0, then the order of work in `docs/native-windows.md`. Get the user's answers to its open decisions (key combination, settings location, SDL source download) before the steps that need them.
3. For each behaviour fix, add or extend a harness case that shows the port now matches the original, and rerun `python -m diffharness` so `docs/verification.md` is current. Run `python tools/snapshots.py` with no option, `--cga` and `--hercules` after any change to graphics or sound.

Rules: `reference/` is read-only; no versioned evidence files; compare observable outputs, not full RAM or flags; timebox investigations to about an hour; small logical commits; update `docs/HANDOVER.md` section 0 at the end.
