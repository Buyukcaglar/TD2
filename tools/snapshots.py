"""Repeatable snapshots: runs the game headless on a virtual clock and compares the frames and the
speaker output with the baseline hashes in tests/ega_snapshots.txt (tests/cga_snapshots.txt,
tests/herc_snapshots.txt).

    python tools/snapshots.py                  # EGA: run and compare
    python tools/snapshots.py --cga            # the same with the CGA backend
    python tools/snapshots.py --hercules       # and with TD2CGA's Hercules mode
    python tools/snapshots.py --update [--cga | --hercules]   # run and rewrite the baseline

Each adapter makes two runs with TD2_VIRTUAL_CLOCK, so time only advances while the host would wait
and two runs give the same frames:
- attract: 120 s of attract mode (logos, credits, scores, menus, the demo drive), a frame every 2 s;
- menus: keys from TD2_KEYS open car select (up, down, down, escape) and scenery select (up, enter),
  a frame every 0.5 s.
Everything the PC speaker plays goes to audio.wav. The files go to runs/snapshots/<adapter>/ (they
show original art and play original music, so they stay out of the repository); only their SHA-256
hashes are committed.
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
SECONDS = 120

# The first keys skip the credits and bring the menu to CLOCK whatever the attract demo left
# selected (Up, Right, Down, Right, Up); Down then picks YOUR CAR and Right, Right SCENERY.
MENU_KEYS = ('30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,42:Down,43:Return,'
             '46:Up,49:Down,52:Down,55:Escape,60:Right,60.5:Right,61:Return,65:Up,68:Return')

# name, seconds, keys, ms between frames; the attract run's files keep their plain names.
# The port's command-line option for each adapter but EGA.
FLAGS = {'cga': '--cga', 'herc': '--hercules'}

RUNS = [('attract', SECONDS, None, 2000), ('menus', 72, MENU_KEYS, 500)]


def baseline_path(adapter: str) -> Path:
    return ROOT / f'tests/{adapter}_snapshots.txt'


def take(adapter: str = 'ega') -> dict[str, str]:
    """Runs the game and returns {file name: sha256}."""
    procs = []
    for name, seconds, keys, every_ms in RUNS:
        out = OUT / adapter / name
        out.mkdir(parents=True, exist_ok=True)
        for old in [*out.glob('snap*.bmp'), *out.glob('audio.wav')]:
            old.unlink()
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(out), TD2_SNAPSHOT_MS=str(every_ms),
                   TD2_AUDIO_DUMP=str(out / 'audio.wav'))
        env.pop('TD2_STATE_DIR', None)
        env.pop('TD2_KEYS', None)
        if keys:
            env['TD2_KEYS'] = keys
        profile = ROOT / f'runs/snapshot-profile/{adapter}-{name}'   # empty: default scores and selections
        profile.mkdir(parents=True, exist_ok=True)
        for f in profile.iterdir():
            f.unlink()
        args = [str(EXE), '--game-dir', str(GAME), '--user-dir', str(profile)]
        if adapter in FLAGS:
            args.append(FLAGS[adapter])
        procs.append((name, out, subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.PIPE, text=True)))
    shots = {}
    for name, out, p in procs:
        _, err = p.communicate(timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f'td2port.exe ({adapter} {name}) exited with {p.returncode}: {err.strip()}')
        prefix = '' if name == 'attract' else f'{name}/'
        for f in sorted(out.glob('snap*.bmp')) + sorted(out.glob('audio.wav')):
            shots[prefix + f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    return shots


def read_baseline(adapter: str = 'ega') -> dict[str, str]:
    lines = [ln.split() for ln in baseline_path(adapter).read_text().splitlines() if ln and not ln.startswith('#')]
    return {name: digest for digest, name in lines}


def write_baseline(shots: dict[str, str], adapter: str = 'ega'):
    head = [f'# {adapter.upper()} snapshot hashes: python tools/snapshots.py --update'
            f'{" " + FLAGS[adapter] if adapter in FLAGS else ""} rewrites this file.',
            f'# {SECONDS} s of attract mode on the virtual clock, one frame every 2 s of game time, the',
            '# scripted menu run (menus/), and the speaker output of each (audio.wav).']
    baseline_path(adapter).write_text('\n'.join(head + [f'{d}  {n}' for n, d in shots.items()]) + '\n', newline='\n')


def compare(shots: dict[str, str], base: dict[str, str]) -> list[str]:
    """Problems, empty when the run matches the baseline."""
    problems = [f'{n}: differs' for n in base if n in shots and shots[n] != base[n]]
    problems += [f'{n}: missing' for n in base if n not in shots]
    problems += [f'{n}: not in the baseline' for n in shots if n not in base]
    return problems


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--update', action='store_true', help='rewrite the baseline from this run')
    p.add_argument('--cga', action='store_true', help='run with the CGA backend (tests/cga_snapshots.txt)')
    p.add_argument('--hercules', action='store_true',
                   help="run with TD2CGA's Hercules mode (tests/herc_snapshots.txt)")
    a = p.parse_args()
    adapter = 'cga' if a.cga else 'herc' if a.hercules else 'ega'
    shots = take(adapter)
    if a.update:
        write_baseline(shots, adapter)
        print(f'wrote {baseline_path(adapter).relative_to(ROOT)} ({len(shots)} snapshots)')
        return 0
    problems = compare(shots, read_baseline(adapter))
    for line in problems:
        print(line)
    print(f'{len(shots)} snapshots, {len(problems)} problems (images in {(OUT / adapter).relative_to(ROOT)})')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
