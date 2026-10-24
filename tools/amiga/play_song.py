"""Renders the Amiga title song with the port's player (amiga/song.c) and Paula model to a WAV file.

Usage: python tools/amiga/play_song.py runs/amiga/sfx/song out.wav [seconds]   (needs build/td2diff.dll)
"""
import ctypes
import sys
import wave
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RATE = 44100


def render(song, seconds):
    dll = ctypes.CDLL(str(ROOT / 'build/td2diff.dll'))
    blob = Path(song).read_bytes()
    err = ctypes.create_string_buffer(256)
    if not dll.dh_song_load(blob, len(blob), err, 256):
        raise SystemExit(err.value.decode())
    n = RATE // 10
    buf = (ctypes.c_int16 * n)()
    out = bytearray()
    for i in range(int(seconds * 10)):
        dll.dh_song_render(buf, n, RATE, 1 if i == 0 else 0)
        out += bytes(buf)
    return bytes(out)


if __name__ == '__main__':
    pcm = render(sys.argv[1], float(sys.argv[3]) if len(sys.argv) > 3 else 60)
    with wave.open(sys.argv[2], 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm)
    peak = max(abs(int.from_bytes(pcm[i:i + 2], 'little', signed=True)) for i in range(0, len(pcm), 2))
    print(f'wrote {sys.argv[2]}: {len(pcm) // 2 / RATE:.1f} s, peak {peak}')
