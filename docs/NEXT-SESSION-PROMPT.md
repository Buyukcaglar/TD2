# Next-session work prompt

Paste everything below the line into a new Claude Code session opened in `C:\Projects\TestDrive2`.

---

You are continuing the Test Drive II reconstruction in `C:\Projects\TestDrive2`. Read `docs/HANDOVER.md` section 0 first; it is the current state. Read `CLAUDE.md` for the working rules and the build, run and harness commands. Do **not** read `docs/planning/continuation.md`, `backlog.json`, `progress.json` or the `docs/recovery/evidence/` receipts.

## Goal of this session: continue M1 "Verify EGA"

The game builds with `.\build.ps1` and runs with `.\run.ps1`. The differential harness (`python -m diffharness`) matches 14 functions so far.

1. Start by asking the user for the results of their play test (one race on each scenery), if they have not already given them. Fix what they report first.
2. Work through "Next steps" in `docs/HANDOVER.md` section 0, in order: traffic seeding, then the cockpit steering marker.
3. For each behaviour fix, add or extend a harness case that shows the port now matches the original, and rerun `python -m diffharness` so `docs/verification.md` is current.
4. Grow the harness towards subsystem tests: the whole simulation tick on a recorded game state.

Rules: `reference/` is read-only; no versioned evidence files; compare observable outputs, not full RAM or flags; timebox investigations to about an hour; small logical commits; update `docs/HANDOVER.md` section 0 at the end.
