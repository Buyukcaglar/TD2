"""The Amiga game's "Rpck" run-length packing (duel's loader at $1e5d0, unpacker at $1e518).

A packed file is 'Rpck', the unpacked size (big-endian long), then the packed stream. The stream is a
signed count byte n followed by data: n >= 0 repeats the next byte n + 1 times, n < 0 copies the next
-n bytes (-128 copies 128). The loader also accepts a plain file, which it reads as it is.

Usage: python tools/amiga/rpck.py runs/amiga   (unpacks every packed file and reports the sizes)
"""
import struct
import sys
from pathlib import Path

MAGIC = b'Rpck'


def unpack_stream(packed, size=None):
    out = bytearray()
    i = 0
    while i < len(packed):
        n = packed[i]
        i += 1
        if n < 0x80:
            out += packed[i:i + 1] * (n + 1)
            i += 1
        else:
            n = 256 - n
            out += packed[i:i + n]
            i += n
    return bytes(out)


def read(data):
    """The bytes the game sees for a file: unpacked when it is an Rpck file."""
    if data[:4] != MAGIC:
        return data
    size = struct.unpack_from('>I', data, 4)[0]
    out = unpack_stream(data[8:])
    # Some streams end with a pad that writes one byte past the size; the game's buffer takes it.
    if len(out) not in (size, size + 1):
        raise ValueError(f'unpacked {len(out)} bytes, header says {size}')
    return out[:size]


if __name__ == '__main__':
    root = Path(sys.argv[1])
    n = bad = 0
    for p in sorted(root.rglob('*')):
        if p.is_file() and p.read_bytes()[:4] == MAGIC:
            n += 1
            try:
                out = read(p.read_bytes())
                print(f'{p.relative_to(root)}: {len(out)} bytes, starts {out[:8].hex()}')
            except ValueError as e:
                bad += 1
                print(f'{p.relative_to(root)}: {e}')
    print(f'{n} packed files, {bad} failed')
