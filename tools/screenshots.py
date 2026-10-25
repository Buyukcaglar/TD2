"""The README's screenshots: the same four moments in every graphics mode, each a whole window.

    python tools/screenshots.py                       # all scenes, all modes, into docs/screenshots
    python tools/screenshots.py --modes ega,amiga --scenes race

Each shot runs build/TD2.exe in a visible window on the virtual clock with the race script below,
holds the game at the scene's game time (TD2_HOLD_SECONDS) and captures the window, title bar
included, with PrintWindow. The runs use the F40 and the 959 (a select.dat of their own), so the
intro's showroom shows the Ferrari. The Amiga mode needs the Amiga game (--amiga, default the
archive in reference/amiga); its intro has duel's own pace, so its first two scenes come later.
Windows only.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import struct
import subprocess
import time
import zlib
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'build/TD2.exe'
GAME = ROOT / 'runs/game'
OUT = ROOT / 'docs/screenshots'
PROFILE = ROOT / 'runs/screenshot-profile'

# The race run's keys from tools/snapshots.py: to the menu, CLOCK, a race with the throttle held.
KEYS = '30:Return,39:Up,39.5:Right,40:Down,40.5:Right,41:Up,43:Return,46:Return,52:Up/400'
FLAGS = {'ega': [], 'cga': ['--cga'], 'herc': ['--hercules'], 'amiga': ['--amiga-graphics']}
# scene: game time in seconds, per mode where it differs
SCENES = {'accolade': {'*': 2.0, 'amiga': 4.0}, 'ferrari': {'*': 7.0, 'amiga': 14.4},
          'menu': {'*': 42.5}, 'race': {'*': 57.0}}

user32, dwmapi, gdi32 = ctypes.windll.user32, ctypes.windll.dwmapi, ctypes.windll.gdi32


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [('biSize', wintypes.DWORD), ('biWidth', wintypes.LONG), ('biHeight', wintypes.LONG),
                ('biPlanes', wintypes.WORD), ('biBitCount', wintypes.WORD), ('biCompression', wintypes.DWORD),
                ('biSizeImage', wintypes.DWORD), ('biXPelsPerMeter', wintypes.LONG),
                ('biYPelsPerMeter', wintypes.LONG), ('biClrUsed', wintypes.DWORD), ('biClrImportant', wintypes.DWORD)]


def window_of(pid: int):
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
        return True
    user32.EnumWindows(each, 0)
    return found[0] if found else None


def grab(hwnd) -> tuple[int, int, bytes]:
    """The window as drawn, cut to its visible frame (DWM's extended frame bounds): (w, h, RGB rows)."""
    r, f = wintypes.RECT(), wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(f), ctypes.sizeof(f))
    w, h = r.right - r.left, r.bottom - r.top
    hdc = user32.GetWindowDC(hwnd)
    mem = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mem, bmp)
    user32.PrintWindow(hwnd, mem, 2)                       # PW_RENDERFULLCONTENT: the Direct3D picture too
    info = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(info), 0)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(hwnd, hdc)
    x0, y0, x1, y1 = f.left - r.left, f.top - r.top, f.right - r.left, f.bottom - r.top
    rows = bytearray()
    for y in range(y0, y1):
        line = buf.raw[(y * w + x0) * 4:(y * w + x1) * 4]
        rgb = bytearray(len(line) // 4 * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows += rgb
    return x1 - x0, y1 - y0, bytes(rows)


def write_png(path: Path, w: int, h: int, rgb: bytes):
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    raw = b''.join(b'\0' + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) +
                     chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def shoot(mode: str, scene: str, at: float, amiga: str | None):
    profile = PROFILE / mode
    profile.mkdir(parents=True, exist_ok=True)
    for old in profile.iterdir():
        if old.is_file():
            old.unlink()
    (profile / 'select.dat').write_text('0 0 0 F40 P959 TDS2\n')
    (profile / 'settings.ini').write_text(f'amiga={amiga}\n' if mode == 'amiga' and amiga else '')
    env = dict(os.environ, SDL_AUDIO_DRIVER='dummy', TD2_VIRTUAL_CLOCK='1', TD2_KEYS=KEYS, TD2_HOLD_SECONDS=str(at))
    for name in ('SDL_VIDEO_DRIVER', 'TD2_SNAPSHOT_DIR', 'TD2_STATE_DIR', 'TD2_RUN_SECONDS', 'TD2_AUDIO_DUMP'):
        env.pop(name, None)
    p = subprocess.Popen([str(EXE), '--game-dir', str(GAME), '--user-dir', str(profile), '--scale', '3',
                          *FLAGS[mode]], env=env, stderr=subprocess.PIPE, text=True)
    try:
        held = next((line for line in p.stderr if line.startswith('holding')), None)
        if not held:
            raise RuntimeError(f'TD2.exe ({mode}) ended before {at} s')
        time.sleep(1.0)
        hwnd = window_of(p.pid)
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.5)
        w, h, rgb = grab(hwnd)
    finally:
        p.kill()
        p.wait()
    write_png(OUT / f'{scene}-{mode}.png', w, h, rgb)
    print(f'{scene}-{mode}.png: {held.strip()}, {w}x{h}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--modes', default=','.join(FLAGS))
    ap.add_argument('--scenes', default=','.join(SCENES))
    ap.add_argument('--amiga', default=next((str(p) for p in (ROOT / 'reference/amiga').glob('*.lha')), None))
    args = ap.parse_args()
    user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))   # per-monitor v2, so rectangles are pixels
    OUT.mkdir(parents=True, exist_ok=True)
    for scene in args.scenes.split(','):
        for mode in args.modes.split(','):
            shoot(mode, scene, SCENES[scene].get(mode, SCENES[scene]['*']), args.amiga)


if __name__ == '__main__':
    main()
