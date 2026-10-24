# Next-session work prompt

Paste everything below the line into a new Claude Code session opened in `C:\Projects\TestDrive2`.

---

You are continuing the Test Drive II reconstruction in `C:\Projects\TestDrive2`. Read `docs/HANDOVER.md` section 0 first; it is the current state. Read `CLAUDE.md` for the working rules and the build, run and harness commands. Do **not** read `docs/planning/continuation.md`, `backlog.json`, `progress.json` or the `docs/recovery/evidence/` receipts.

## Goal of this session: start M3 "CGA"

The game builds with `.\build.ps1` and runs with `.\run.ps1`. The differential harness (`python -m diffharness`) matches 18 functions, plus whole sim timer calls replayed from recorded race states. Graphics and audio sit behind backend interfaces (M2); `python tools/snapshots.py` proves the EGA frames and speaker output are unchanged.

1. Start by asking the user for the results of their play test (one race on each scenery, ideally with `.\run.ps1 -RecordStates`), if they have not already given them. Fix what they report first, then rerun `python -m diffharness sim_tick` on their recorded states.
2. Work through "Next steps" in `docs/HANDOVER.md` section 0, starting with the first CGA steps.
3. For each behaviour fix, add or extend a harness case that shows the port now matches the original, and rerun `python -m diffharness` so `docs/verification.md` is current. Run `python tools/snapshots.py` after any change to graphics or sound.

Rules: `reference/` is read-only; no versioned evidence files; compare observable outputs, not full RAM or flags; timebox investigations to about an hour; small logical commits; update `docs/HANDOVER.md` section 0 at the end.
