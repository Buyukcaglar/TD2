"""Repeatable EGA snapshots: runs the game headless on a virtual clock and compares the frames with
the baseline hashes in tests/ega_snapshots.txt.

    python tools/snapshots.py            # run and compare
    python tools/snapshots.py --update   # run and rewrite the baseline

The game runs 120 s of attract mode (logos, credits, scores, menus, the demo drive) with
TD2_VIRTUAL_CLOCK, so time only advances while the host would wait and two runs give the same frames.
A frame is saved every 2 s of game time. The images go to runs/snapshots/ (they show original art, so
they stay out of the repository); only their SHA-256 hashes are committed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'build/td2port.exe'
GAME = ROOT / 'runs/game'
OUT = ROOT / 'runs/snapshots'
BASELINE = ROOT / 'tests/ega_snapshots.txt'
SECONDS = 120


def take() -> dict[str, str]:
    """Runs the game and returns {snapshot name: sha256}."""
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob('snap*.bmp'):
        old.unlink()
    env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
               TD2_RUN_SECONDS=str(SECONDS), TD2_SNAPSHOT_DIR=str(OUT))
    for k in ('TD2_STATE_DIR', 'TD2_AUDIO_DUMP'):
        env.pop(k, None)
    profile = ROOT / 'runs/snapshot-profile'       # empty profile: default scores and selections
    profile.mkdir(parents=True, exist_ok=True)
    for f in profile.iterdir():
        f.unlink()
    r = subprocess.run([str(EXE), '--game-dir', str(GAME), '--user-dir', str(profile)], env=env,
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f'td2port.exe exited with {r.returncode}: {r.stderr.strip()}')
    return {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(OUT.glob('snap*.bmp'))}


def read_baseline() -> dict[str, str]:
    lines = [ln.split() for ln in BASELINE.read_text().splitlines() if ln and not ln.startswith('#')]
    return {name: digest for digest, name in lines}


def write_baseline(shots: dict[str, str]):
    head = ['# EGA snapshot hashes: python tools/snapshots.py --update rewrites this file.',
            f'# {SECONDS} s of attract mode on the virtual clock, one frame every 2 s of game time.']
    BASELINE.write_text('\n'.join(head + [f'{d}  {n}' for n, d in shots.items()]) + '\n', newline='\n')


def compare(shots: dict[str, str], base: dict[str, str]) -> list[str]:
    """Problems, empty when the run matches the baseline."""
    problems = [f'{n}: differs' for n in base if n in shots and shots[n] != base[n]]
    problems += [f'{n}: missing' for n in base if n not in shots]
    problems += [f'{n}: not in the baseline' for n in shots if n not in base]
    return problems


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--update', action='store_true', help='rewrite tests/ega_snapshots.txt from this run')
    a = p.parse_args()
    shots = take()
    if a.update:
        write_baseline(shots)
        print(f'wrote {BASELINE.relative_to(ROOT)} ({len(shots)} snapshots)')
        return 0
    problems = compare(shots, read_baseline())
    for line in problems:
        print(line)
    print(f'{len(shots)} snapshots, {len(problems)} problems (images in {OUT.relative_to(ROOT)})')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
