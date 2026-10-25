"""Repeatable snapshots: runs the game headless on a virtual clock and compares the frames and the
speaker output with the baseline hashes in tests/ega_snapshots.txt (tests/cga_snapshots.txt,
tests/herc_snapshots.txt).

    python tools/snapshots.py                  # EGA: run and compare
    python tools/snapshots.py --cga            # the same with the CGA backend
    python tools/snapshots.py --hercules       # and with TD2CGA's Hercules mode
    python tools/snapshots.py --update [--cga | --hercules]   # run and rewrite the baseline
    python tools/snapshots.py --amiga          # the Amiga backend without Amiga files, against EGA

Each adapter makes five runs with TD2_VIRTUAL_CLOCK, so time only advances while the host would wait
and two runs give the same frames:
- attract: 120 s of attract mode (logos, credits, scores, menus, the demo drive), a frame every 2 s;
- menus: keys from TD2_KEYS open car select (up, down, down, escape) and scenery select (up, enter),
  a frame every 0.5 s;
- switch: the attract run with Ctrl+Shift+G at 45, 52 and 60 s, during the demo drive, so the graphics
  go round all three modes and back. Every frame from 62 s on must equal the attract run's frame of
  the same number: the switch leaves the race as it was (round_trip());
- menuswitch: the menus run with Ctrl+Shift+G on the main menu (36 s), in car select (47 s) and in
  scenery select (63 s). The frames from 64 s on must equal the menus run's frames of the same time;
- race: a race against the clock from the menu, the throttle held and Return every 6 s to drive on
  after each crash, until the game is over (about 450 s): the section's end, the gas station and the
  results, the last life, game over, the record book and the name entry (the profile's score table is
  empty, so the run makes both), "TD" typed, the top scores and the menu again. A frame every 0.5 s,
  and each still screen once it has stood that long (TD2_SNAPSHOT_HELD).
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
EXE = ROOT / 'build/TD2.exe'
GAME = ROOT / 'runs/game'
OUT = ROOT / 'runs/snapshots'
SECONDS = 120

# The first keys skip the credits and bring the menu to CLOCK whatever the attract demo left
# selected (Up, Right, Down, Right, Up); Down then picks YOUR CAR and Right, Right SCENERY.
MENU_KEYS = ('30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,42:Down,43:Return,'
             '46:Up,49:Down,52:Down,55:Escape,60:Right,60.5:Right,61:Return,65:Up,68:Return')

# name, seconds, keys, ms between frames; the attract run's files keep their plain names.
# The port's command-line option for each adapter but EGA.
FLAGS = {'cga': '--cga', 'herc': '--hercules', 'amiga': '--amiga-graphics'}
# The Amiga backend without the Amiga game's files must show the EGA frames: its attract, menus and race runs
# are compared with the EGA baseline (its switches go round other modes, so it has no switch runs).
AMIGA_RUNS = ('attract', 'menus', 'race')

# Up held from 52 s; the Returns go on after crashes and leave the results pages; then a name.
RACE_KEYS = ','.join(['30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,43:Return,46:Return,52:Up/400'] +
                     [f'{t}:Return' for t in range(58, 451, 6)] + ['466:Return,470:T,470.5:D,471:Return,476:Return'])

SWITCH_KEYS = '45:Ctrl+Shift+G,52:Ctrl+Shift+G,60:Ctrl+Shift+G'   # in the demo race, which starts at 42 s
MENU_SWITCH_KEYS = ','.join(sorted(MENU_KEYS.split(',') + ['36:Ctrl+Shift+G', '47:Ctrl+Shift+G', '63:Ctrl+Shift+G'],
                                   key=lambda k: float(k.split(':')[0])))
# switch run: (plain run it must come back to, seconds from which it must, match frames by game time)
SWITCH_RUNS = {'switch': ('attract', 62.0, False), 'menuswitch': ('menus', 64.0, True)}

RUNS = [('attract', SECONDS, None, 2000), ('menus', 72, MENU_KEYS, 500), ('switch', SECONDS, SWITCH_KEYS, 2000),
        ('menuswitch', 72, MENU_SWITCH_KEYS, 500), ('race', 482, RACE_KEYS, 500)]

SELECT = '0 0 0 F40 P959 TDS2'        # select.dat: the cars and the scenery the runs start with

# Game time of each frame, from the port's log: {(adapter, run): {file name: seconds}}.
TIMES: dict[tuple[str, str], dict[str, float]] = {}


def baseline_path(adapter: str) -> Path:
    return ROOT / f'tests/{adapter}_snapshots.txt'


def take(adapter: str = 'ega') -> dict[str, str]:
    """Runs the game and returns {file name: sha256}."""
    procs = []
    for name, seconds, keys, every_ms in RUNS:
        if adapter == 'amiga' and name not in AMIGA_RUNS:
            continue
        out = OUT / adapter / name
        out.mkdir(parents=True, exist_ok=True)
        for old in [*out.glob('snap*.bmp'), *out.glob('audio.wav')]:
            old.unlink()
        env = dict(os.environ, SDL_VIDEO_DRIVER='dummy', SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1',
                   TD2_RUN_SECONDS=str(seconds), TD2_SNAPSHOT_DIR=str(out), TD2_SNAPSHOT_MS=str(every_ms),
                   TD2_AUDIO_DUMP=str(out / 'audio.wav'))
        env.pop('TD2_STATE_DIR', None)
        env.pop('TD2_KEYS', None)
        env.pop('TD2_SNAPSHOT_HELD', None)
        if keys:
            env['TD2_KEYS'] = keys
        profile = ROOT / f'runs/snapshot-profile/{adapter}-{name}'   # default scores, cars 0 and 1
        profile.mkdir(parents=True, exist_ok=True)
        for f in profile.iterdir():
            f.unlink()
        # the intro shows the chosen cars; the game's own select.dat picks the RUF, which the base game
        # does not have
        (profile / 'select.dat').write_text(SELECT + chr(10))
        if name == 'race':
            env['TD2_SNAPSHOT_HELD'] = '1'     # the still screens between the race's frames too
            (profile / 'TDS2HISC.DAT').write_bytes(bytes(0x154))   # an empty score table, checksum 0
        args = [str(EXE), '--game-dir', str(GAME), '--user-dir', str(profile)]
        if adapter in FLAGS:
            args.append(FLAGS[adapter])
        procs.append((name, out, subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.PIPE, text=True)))
    shots = {}
    for name, out, p in procs:
        _, err = p.communicate(timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f'TD2.exe ({adapter} {name}) exited with {p.returncode}: {err.strip()}')
        TIMES[(adapter, name)] = {w[0]: float(w[2]) for w in (ln.split() for ln in err.splitlines())
                                  if len(w) == 4 and w[0].startswith('snap') and w[1] == 'at'}
        prefix = '' if name == 'attract' else f'{name}/'
        for f in sorted(out.glob('snap*.bmp')) + sorted(out.glob('audio.wav')):
            shots[prefix + f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    return shots


def round_trip(shots: dict[str, str], adapter: str = 'ega') -> list[str]:
    """Problems with the two switch runs (after take()): from the time the graphics are back in the
    adapter's own mode, each frame must equal the plain run's frame of the same number (switch, whose
    race keeps its frame count) or of the same game time (menuswitch, whose screens draw themselves
    again). Some frame before must differ, so a switch did happen."""
    problems = []
    for run, (plain, back, by_time) in SWITCH_RUNS.items():
        times = TIMES.get((adapter, run), {})
        if by_time:
            at = {t: n for n, t in TIMES.get((adapter, plain), {}).items()}
            pair = {n: at.get(t) for n, t in times.items()}
        else:
            pair = {n: n for n in times}
        prefix = '' if plain == 'attract' else f'{plain}/'

        def same(n):
            return pair[n] is not None and shots.get(f'{run}/{n}') == shots.get(prefix + pair[n])
        after = [n for n, t in times.items() if t >= back and pair[n] is not None]
        problems += [f'{run}/{n}: differs from the {plain} run after switching back' for n in after if not same(n)]
        if not after:
            problems.append(f'{run}: no frames after switching back')
        if all(same(n) for n, t in times.items() if t < back):
            problems.append(f'{run}: no frame shows another graphics mode')
    return problems


def read_baseline(adapter: str = 'ega') -> dict[str, str]:
    lines = [ln.split() for ln in baseline_path(adapter).read_text().splitlines() if ln and not ln.startswith('#')]
    return {name: digest for digest, name in lines}


def write_baseline(shots: dict[str, str], adapter: str = 'ega'):
    head = [f'# {adapter.upper()} snapshot hashes: python tools/snapshots.py --update'
            f'{" " + FLAGS[adapter] if adapter in FLAGS else ""} rewrites this file.',
            f'# {SECONDS} s of attract mode on the virtual clock, one frame every 2 s of game time, the',
            '# scripted menu run (menus/), both with three live graphics switches (switch/, menuswitch/), a',
            '# race to game over and the name entry (race/), and the speaker output of each (audio.wav).']
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
    p.add_argument('--amiga', action='store_true',
                   help='run with the Amiga backend, without Amiga files (the EGA baseline)')
    a = p.parse_args()
    adapter = 'cga' if a.cga else 'herc' if a.hercules else 'amiga' if a.amiga else 'ega'
    shots = take(adapter)
    if adapter == 'amiga':
        base = {n: d for n, d in read_baseline('ega').items() if n.split('/')[0] not in SWITCH_RUNS}
        problems = compare(shots, base)
        for line in problems:
            print(line)
        print(f'{len(shots)} snapshots against EGA, {len(problems)} problems (images in {(OUT / adapter).relative_to(ROOT)})')
        return 1 if problems else 0
    if a.update:
        for line in round_trip(shots, adapter):
            print(line)
        write_baseline(shots, adapter)
        print(f'wrote {baseline_path(adapter).relative_to(ROOT)} ({len(shots)} snapshots)')
        return 0
    problems = round_trip(shots, adapter) + compare(shots, read_baseline(adapter))
    for line in problems:
        print(line)
    print(f'{len(shots)} snapshots, {len(problems)} problems (images in {(OUT / adapter).relative_to(ROOT)})')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
